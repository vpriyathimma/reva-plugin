import { randomUUID } from 'crypto';
import { resolveDeveloperProfile } from './sessionResolver';

const REVA_PDP_URL          = process.env.REVA_PDP_URL          || '';
const CEDAR_POLICY_STORE_ID = process.env.CEDAR_POLICY_STORE_ID || '';
const CEDAR_AUTHORIZATION   = process.env.CEDAR_AUTHORIZATION   || '';
const CEDAR_ORIGIN          = process.env.CEDAR_ORIGIN          || '';

export type CedarDecision = 'allow' | 'deny' | 'conditional_allow';

export interface CedarResult {
  decision:     CedarDecision;
  decision_id:  string;
  reason?:      string;
  policy_name?: string;
  latency_ms?:  number;
}

const sessionTraceStore = new Map<string, string>();

export function getOrCreateSessionTrace(sessionId: string): string {
  if (!sessionTraceStore.has(sessionId)) {
    sessionTraceStore.set(sessionId, randomUUID());
  }
  return sessionTraceStore.get(sessionId)!;
}

function buildTraceparent(sessionTraceId: string): string {
  const traceId = sessionTraceId.replace(/-/g, '').padEnd(32, '0').slice(0, 32);
  return `00-${traceId}-0000000000000001-01`;
}

export async function evaluateCedar(payload: {
  principal:  { type: string; id: string; properties?: Record<string, any>; parents?: Array<{ type: string; id: string }> };
  action:     { name: string };
  resource:   { type: string; id: string; properties?: Record<string, any>; parents?: Array<{ type: string; id: string }> };
  context:    Record<string, any>;
  session_id: string;
}): Promise<CedarResult> {
  const sessionTraceId = getOrCreateSessionTrace(payload.session_id);

  // ── Cedar payload — matches SecureBank format exactly ────────────
  const cedarPayload = [{
    subject: {
      type:       payload.principal.type,
      id:         payload.principal.id,
      properties: payload.principal.properties || {},
      parents:    payload.principal.parents    || [],
    },
    action: { name: payload.action.name },
    resource: {
      type:       payload.resource.type,
      id:         payload.resource.id,
      properties: payload.resource.properties || {},
      parents:    payload.resource.parents    || [],
    },
    context: {
      ...payload.context,
      session_trace_id: sessionTraceId,
    },
  }];

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'traceparent':  buildTraceparent(sessionTraceId),
  };

  if (CEDAR_POLICY_STORE_ID) headers['policyStoreId'] = CEDAR_POLICY_STORE_ID;
  if (CEDAR_AUTHORIZATION)   headers['Authorization']  = CEDAR_AUTHORIZATION;
  if (CEDAR_ORIGIN)          headers['Origin']          = CEDAR_ORIGIN;

  const start = Date.now();

  try {
    console.log('[Cedar] Sending payload:', JSON.stringify(cedarPayload[0].subject), cedarPayload[0].action, cedarPayload[0].resource.id);

    const res = await fetch(REVA_PDP_URL, {
      method:  'POST',
      headers,
      body:    JSON.stringify(cedarPayload),
    });

    const latency = Date.now() - start;

    if (!res.ok) {
      const errText = await res.text();
      console.error(`[Cedar] PDP returned HTTP ${res.status}: ${errText}`);
      return { decision: 'allow', decision_id: randomUUID(), reason: `PDP error HTTP ${res.status}`, latency_ms: latency };
    }

    const result      = await res.json() as any;
    const firstResult = Array.isArray(result) ? result[0] : (result?.results?.[0] ?? result);

    console.log('[Cedar] Raw response:', JSON.stringify(firstResult));

    const rawDecision = firstResult?.decision;
    let decision: CedarDecision = 'deny';

    if (rawDecision === true || rawDecision === 'allow' || rawDecision === 'Allow') {
      decision = 'allow';
    } else if (rawDecision === 'conditional_allow' || rawDecision === 'ConditionalAllow') {
      decision = 'conditional_allow';
    }

    let policyName: string | undefined;
    try {
      const chain = typeof firstResult?.decision_chain === 'string'
        ? JSON.parse(firstResult.decision_chain)
        : firstResult?.decision_chain;
      if (Array.isArray(chain) && chain.length > 0) {
        policyName = chain.find((c: any) => c.decision !== 'allow')?.name || chain[0]?.name;
      }
    } catch {}

    console.log(JSON.stringify({
      event:         'CEDAR_DECISION',
      decision,
      policy_name:   policyName,
      session_trace: sessionTraceId,
      latency_ms:    latency,
      principal:     payload.principal.id,
      action:        payload.action.name,
      resource:      payload.resource.id,
    }));

    return {
      decision,
      decision_id:  firstResult?.decision_id || randomUUID(),
      reason:       policyName,
      policy_name:  policyName,
      latency_ms:   latency,
    };

  } catch (err: any) {
    console.error(`[Cedar] PDP call failed: ${err.message}`);
    return { decision: 'allow', decision_id: randomUUID(), reason: `PDP network error: ${err.message}` };
  }
}

const SENSITIVITY_SCOPE: Record<string, string> = {
  low:      'MCPTool:Read',
  medium:   'MCPTool:Write',
  high:     'MCPTool:Communicate',
  critical: 'MCPTool:Destructive',
};

export function buildCallToolPayload(params: {
  agentName:        string;
  agentId:          string;
  toolName:         string;
  serverName:       string;
  humanSub:         string;
  clientSource:     string;
  sessionId:        string;
  sensitivity:      string;
  toolScope:        string;
  scores:           Record<string, any>;
  hitlAcknowledged: boolean;
  intent:           string;
  priorIntents:     string;
  query:            string;
  queryHistory:     string;
}) {
  return {
    principal: {
      type: 'AICodingAgents::Agent',
      id:   params.agentName,
    },
    action:   { name: 'CallTool' },
    resource: {
      type: 'MCPTool',
      id:   params.toolName,
      properties: {
        tool_name:   params.toolName,
        server_name: params.serverName,
        sensitivity: params.sensitivity,
      },
    },
    context: {
      access_state:          'Active',
      adaptiveRisk:          false,
      human_sub:             params.humanSub,
      agent_id:              params.agentId,
      agent_name:            params.agentName,
      client_source:         params.clientSource,
      hitlAcknowledged:      params.hitlAcknowledged,
      mcp_tool_sensitivity:  params.sensitivity,
      mcp_server_name:       params.serverName,
      mcp_tool_scope:        SENSITIVITY_SCOPE[params.sensitivity] || 'MCPTool:Read',
      intent:                params.intent,
      prior_intents:         params.priorIntents,
      query:                 params.query.slice(0, 500),
      query_history:         params.queryHistory.slice(0, 500),
      prompt:                params.query.slice(0, 500),
      prompt_history:        params.queryHistory.slice(0, 500),
      response:              '',
      trust_score:           params.scores.trust_score            ?? 70,
      injection_score:       params.scores.injection_score        ?? 0,
      jailbreak_score:       params.scores.jailbreak_score        ?? 0,
      escalation_score:      params.scores.escalation_score       ?? 0,
      exfiltration_score:    params.scores.exfiltration_score     ?? 0,
      sod_violation:         params.scores.sod_violation          ?? false,
      sod_score:             params.scores.sod_score              ?? 0,
      time_anomaly_score:    params.scores.time_anomaly_score     ?? 0,
      velocity_score:        params.scores.velocity_score         ?? 0,
      intent_mismatch_score: params.scores.intent_mismatch_score  ?? 0,
      after_hours_score:     params.scores.after_hours_score      ?? 0,
      bypass_attempts_score: params.scores.bypass_attempts_score  ?? 0,
      bulk_operation_score:  params.scores.bulk_operation_score   ?? 0,
      intent_pool_score:     params.scores.intent_pool_score      ?? 0,
      intent_pool_pattern:   params.scores.intent_pool_pattern    ?? 'none',
    },
    session_id: params.sessionId,
  };
}

export function buildSubmitPromptPayload(params: {
  agentName:    string;
  agentId:      string;
  humanSub:     string;
  clientSource: string;
  sessionId:    string;
  scores:       Record<string, any>;
  intent:       string;
  priorIntents: string;
  query:        string;
  queryHistory: string;
}) {
  return {
    principal: {
      type: 'AICodingAgents::Agent',
      id:   params.agentName,
    },
    action:   { name: 'SubmitPrompt' },
    resource: {
      type: 'Prompt',
      id:   params.sessionId,
      properties: {
        session_id: params.sessionId,
      },
    },
    context: {
      access_state:          'Active',
      adaptiveRisk:          false,
      human_sub:             params.humanSub,
      agent_id:              params.agentId,
      agent_name:            params.agentName,
      client_source:         params.clientSource,
      hitlAcknowledged:      false,
      intent:                params.intent,
      prior_intents:         params.priorIntents,
      query:                 params.query.slice(0, 500),
      query_history:         params.queryHistory.slice(0, 500),
      response:              '',
      trust_score:           params.scores.trust_score            ?? 70,
      injection_score:       params.scores.injection_score        ?? 0,
      jailbreak_score:       params.scores.jailbreak_score        ?? 0,
      escalation_score:      params.scores.escalation_score       ?? 0,
      exfiltration_score:    params.scores.exfiltration_score     ?? 0,
      sod_violation:         params.scores.sod_violation          ?? false,
      sod_score:             params.scores.sod_score              ?? 0,
      time_anomaly_score:    params.scores.time_anomaly_score     ?? 0,
      velocity_score:        params.scores.velocity_score         ?? 0,
      intent_mismatch_score: params.scores.intent_mismatch_score  ?? 0,
      after_hours_score:     params.scores.after_hours_score      ?? 0,
      bypass_attempts_score: params.scores.bypass_attempts_score  ?? 0,
      bulk_operation_score:  params.scores.bulk_operation_score   ?? 0,
      intent_pool_score:     params.scores.intent_pool_score      ?? 0,
      intent_pool_pattern:   params.scores.intent_pool_pattern    ?? 'none',
    },
    session_id: params.sessionId,
  };
}

// ── Claude Code file zone resolver ───────────────────────────────
export function resolveFileZone(filePath: string): string {
  const p = filePath.replace(/\\/g, '/');
  if (p.includes('.env') || p.includes('secrets') || p.includes('.pem') || p.includes('.key')) return 'secrets';
  if (p.includes('package.json') || p.includes('tsconfig') || p.includes('.claude/')) return 'config';
  if (p.includes('tests/') || p.includes('test/') || p.includes('.test.') || p.includes('.spec.')) return 'tests';
  if (p.includes('src/') || p.includes('lib/') || p.includes('app/')) return 'src';
  if (p.includes('docs/') || p.includes('README')) return 'docs';
  return 'other';
}

// ── Classify bash command risk tier ─────────────────────────────
export function classifyCommand(cmd: string): 'safe' | 'restricted' | 'destructive' {
  const c = cmd.toLowerCase().trim();

  // Destructive — Deny always
  if (/\brm\s|drop\s+table|truncate|delete\s+from|mkfs|dd\s+if=|>\s*\/dev\/|kill\s+-9|pkill|rmdir/.test(c))
    return 'destructive';

  // Restricted — HITL required
  if (/npm\s+install|pip\s+install|yarn\s+install|git\s+push|git\s+pull|git\s+merge|git\s+rebase|curl|wget|ssh\s|scp\s|docker\s+build|docker\s+run|kubectl|terraform|chmod|chown|nohup|psql|mysql|mongosh|pg_dump|mysqldump/.test(c))
    return 'restricted';

  return 'safe';
}

// ── Classify MCP tool into Cedar action tier ─────────────────────
export function classifyMCPTool(toolName: string): 'MCPRead' | 'MCPWrite' {
  const t = toolName.toLowerCase();
  // Write tier — create, update, add, edit, transition, comment, worklog, draft
  if (/create|update|add|edit|transition|comment|worklog|draft/.test(t))
    return 'MCPWrite';
  // Everything else — search, get, list, read, fetch, lookup, retrieve
  return 'MCPRead';
}

// ── Map Claude Code tool name to Cedar action ────────────────────
export function mapToolToAction(toolName: string): string {
  const t = toolName.toLowerCase();
  if (t === 'read' || t === 'glob' || t === 'grep') return 'ReadFile';
  if (t === 'write') return 'WriteFile';
  if (t === 'edit' || t === 'multiedit') return 'EditFile';
  if (t === 'bash') return 'RunBash';
  if (t === 'task' || t === 'agent' || t === 'taskcreate' || t === 'taskupdate') return 'SpawnAgent';
  if (t === 'worktreetool' || t.includes('worktree')) return 'CreateWorktree';
  if (t.startsWith('mcp__')) return classifyMCPTool(t.split('__')[2] || t);
  if (t === 'toolsearch' || t === 'websearch' || t === 'webfetch') return 'ReadFile';
  return 'ReadFile'; // default safe
}

// ── Build Developer principal block with profile (for ClaudeCode policies) ──
function buildDeveloperPrincipal(osUser: string, agentType: string) {
  const principalType = agentType === 'subagent' ? 'Agent' : 'Developer';

  // Agent principal — no Department parent, no role
  if (principalType === 'Agent') {
    return {
      type: 'Agent',
      id:   osUser,
      properties: {
        agent_type:        agentType,
        parent_session_id: '',
      },
      parents: [],
    };
  }

  // Developer principal — inject role/employment_type and Department parent
  const profile = resolveDeveloperProfile(osUser);
  return {
    type: 'Developer',
    id:   osUser,
    properties: {
      os_user:         osUser,
      user_role:       profile.user_role,
      employment_type: profile.employment_type,
    },
    parents: [
      { type: 'Department', id: profile.department },
    ],
  };
}

// ── Claude Code file operation payload ───────────────────────────
export function buildFileOperationPayload(params: {
  osUser:           string;
  projectName:      string;
  toolName:         string;
  filePath:         string;
  command?:         string;
  agentType:        string;
  sessionId:        string;
  spawnCount?:      number;
  hitlAcknowledged: boolean;
  scores:           Record<string, any>;
  prompt?:          string;
  prompt_history?:  string[];
  spiffeId?:        string;
}) {
  const fileZone   = resolveFileZone(params.filePath || params.command || '');
  const cedarAction = mapToolToAction(params.toolName);
  const isCommand   = cedarAction === 'RunBash';
  const isSpawn     = cedarAction === 'SpawnAgent' || cedarAction === 'CreateWorktree';

  // SpawnAgent resource — use session_id prefix + spawn count as stable identifier
  const sessionPrefix = params.sessionId.slice(0, 8);

  // Sanitize command — Cedar entityId cannot contain newlines
  const sanitizedCommand = (params.command || '').replace(/[\r\n]+/g, ' ').slice(0, 200);

  return {
    principal: buildDeveloperPrincipal(params.osUser, params.agentType),
    action: { name: cedarAction },
    resource: isCommand
      ? {
          type: 'Command',
          id:   sanitizedCommand.slice(0, 100),
          properties: {
            command_text: sanitizedCommand,
            command_risk: classifyCommand(params.command || ''),
          },
        }
      : isSpawn
      ? {
          type: 'Session',
          id:   `${sessionPrefix}-spawnagent${params.spawnCount || 1}`,
          properties: {
            session_id:  params.sessionId,
            agent_scope: 'subagent',
          },
        }
      : {
          type: 'File',
          id:   params.filePath || 'unknown',
          properties: {
            file_path: params.filePath,
            file_zone: fileZone,
            sensitivity: fileZone === 'secrets' ? 'critical' : fileZone === 'src' ? 'high' : 'medium',
          },
        },
    context: {
      access_state:     'Active',
      os_user:          params.osUser,
      project_name:     params.projectName,
      file_path:        params.filePath || '',
      file_zone:        fileZone,
      agent_type:       params.agentType,
      tool_name:        params.toolName,
      session_id:       params.sessionId,
      session_trace_id: getOrCreateSessionTrace(params.sessionId),
      approver_consent: params.hitlAcknowledged,
      command:          sanitizedCommand,
      command_risk:     classifyCommand(params.command || ''),
      trust_score:      params.scores.trust_score       ?? 70,
      injection_score:  params.scores.injection_score   ?? 0,
      escalation_score: params.scores.escalation_score  ?? 0,
      exfiltration_score: params.scores.exfiltration_score ?? 0,
      sod_violation:    params.scores.sod_violation     ?? false,
      prompt:           (params.prompt || '').slice(0, 500),
      prompt_history:   (params.prompt_history || []).slice(-3).join(' | ').slice(0, 500),
      ...(params.spiffeId ? { spiffe_id: params.spiffeId } : {}),
    },
    session_id: params.sessionId,
  };
}

// ── Build ClaudeCode SubmitPrompt Cedar payload (bypass attempts only) ─────
export function buildClaudeCodePromptPayload(params: {
  osUser:        string;
  projectName:   string;
  sessionId:     string;
  promptSnippet: string;
  bypassAttempt: boolean;
  scores:        Record<string, any>;
  spiffeId?:     string;
}) {
  return {
    principal: buildDeveloperPrincipal(params.osUser, 'main'),
    action: { name: 'SubmitPrompt' },
    resource: {
      type: 'Prompt',
      id:   `${params.sessionId.slice(0, 8)}-bypass`,
      properties: {
        session_id:  params.sessionId,
        bypass_type: 'shell-exclamation',
      },
    },
    context: {
      access_state:     'Active',
      os_user:          params.osUser,
      project_name:     params.projectName,
      session_id:       params.sessionId,
      session_trace_id: getOrCreateSessionTrace(params.sessionId),
      bypass_attempt:   params.bypassAttempt,
      prompt_snippet:   params.promptSnippet.slice(0, 200),
      trust_score:      params.scores.trust_score ?? 70,
      ...(params.spiffeId ? { spiffe_id: params.spiffeId } : {}),
    },
    session_id: params.sessionId,
  };
}

// ── Build MCP tool Cedar payload ────────────────────────────────
export function buildMCPToolPayload(params: {
  osUser:           string;
  projectName:      string;
  toolName:         string;
  serverName:       string;
  agentType:        string;
  sessionId:        string;
  hitlAcknowledged: boolean;
  scores:           Record<string, any>;
  prompt?:          string;
  prompt_history?:  string[];
  spiffeId?:        string;
}) {
  const cedarAction = classifyMCPTool(params.toolName);
  const mcpToolId   = `${params.serverName}__${params.toolName}`;

  return {
    principal: buildDeveloperPrincipal(params.osUser, params.agentType),
    action: { name: cedarAction },
    resource: {
      type: 'MCPTool',
      id:   mcpToolId,
      properties: {
        tool_name:   params.toolName,
        server_name: params.serverName,
        tier:        cedarAction,
      },
      parents: [
        { type: 'MCPServer', id: params.serverName },
      ],
    },
    context: {
      access_state:     'Active',
      os_user:          params.osUser,
      project_name:     params.projectName,
      tool_name:        params.toolName,
      server_name:      params.serverName,
      agent_type:       params.agentType,
      session_id:       params.sessionId,
      session_trace_id: getOrCreateSessionTrace(params.sessionId),
      approver_consent: params.hitlAcknowledged,
      trust_score:      params.scores.trust_score      ?? 70,
      injection_score:  params.scores.injection_score  ?? 0,
      escalation_score: params.scores.escalation_score ?? 0,
      exfiltration_score: params.scores.exfiltration_score ?? 0,
      prompt:           (params.prompt || '').slice(0, 500),
      prompt_history:   (params.prompt_history || []).slice(-3).join(' | ').slice(0, 500),
      ...(params.spiffeId ? { spiffe_id: params.spiffeId } : {}),
    },
    session_id: params.sessionId,
  };
}
