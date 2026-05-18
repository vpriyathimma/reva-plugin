import { Request, Response }     from 'express';
import { classifyToolCall }      from '../../api/intentClassifier';
import { logDecision }           from '../discovery/enroll';
import { sessionIntentStore }    from './beforePrompt';
import { sessionStore }          from '../discovery/enroll';
import { claudeSessionUserStore } from './onSessionStart';
import { recordDynamicTool, discoveredServers } from '../../api/mcpProbe';
import { triggerHITL }           from '../hitl/trigger';
import { pollHITL }              from '../hitl/poll';
import { recordHITLApproval, recordHITLDenial } from '../hitl/callback';
import { resolveAgentName }      from '../../api/agentResolver';
import { evaluateCedar, buildCallToolPayload, buildFileOperationPayload, buildMCPToolPayload, getOrCreateSessionTrace } from '../../api/pdpEvaluate';

// HITL user mapping — OS username → Okta email
const HITL_MAP: Record<string, string> = {
  saisrungaram: 'sai.srungaram@reva.ai',
  yashprakash:  'yash.prakash@reva.ai',
};

function resolveHITLEmail(osUser: string): string {
  return HITL_MAP[osUser] || osUser;
}

// Track active MCP servers discovered via PreToolUse
export const activeMcpServers = new Map<string, Set<string>>(); // session_id → Set of server names

// Subagent context store — tracks active subagent window per session
// SpawnAgent fires → subagent_active = true
// Next SpawnAgent or UserPromptSubmit → subagent_active = false (new turn)
interface SubagentContext {
  active:      boolean;
  started_at:  string;
  spawn_count: number; // how many agents spawned this turn
}
export const subagentContextStore = new Map<string, SubagentContext>();

function markSubagentActive(session_id: string): void {
  const existing = subagentContextStore.get(session_id);
  subagentContextStore.set(session_id, {
    active:      true,
    started_at:  new Date().toISOString(),
    spawn_count: (existing?.spawn_count || 0) + 1,
  });
  console.log(`[Subagent] Context active for session=${session_id} spawn_count=${(existing?.spawn_count || 0) + 1}`);
}

function isSubagentActive(session_id: string): boolean {
  return subagentContextStore.get(session_id)?.active || false;
}

function trackMcpServer(session_id: string, tool_name: string): void {
  if (!tool_name.startsWith('mcp__')) return;
  const parts = tool_name.split('__');
  if (parts.length < 2) return;
  const server_name = parts[1];
  if (!activeMcpServers.has(session_id)) {
    activeMcpServers.set(session_id, new Set());
  }
  activeMcpServers.get(session_id)!.add(server_name);
}

export const hitlStore = new Map<string, {
  acknowledged: boolean;
  approved_at:  string;
  tool_name:    string;
  blocked?:     boolean; // permanently blocked after timeout/denial
}>();

const hitlInFlight = new Map<string, boolean>();

// Scope mapping — tool sensitivity → MCPTool scope
const SENSITIVITY_SCOPE: Record<string, string> = {
  low:      'MCPTool:Read',
  medium:   'MCPTool:Write',
  high:     'MCPTool:Communicate',
  critical: 'MCPTool:Destructive',
};

export async function handleToolCall(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization || '';
    const token      = authHeader.replace('Bearer ', '');
    // Allow unauthenticated hook calls from Claude Code plugin

    const {
      session_id    = `session-${Date.now()}`,
      tool_name     = '',
      server_name   = '',
      server_url    = '',
      user_email_body = (req as any).user?.email || '',
      agent_cid     = '',
      client_source = 'claude-code',
    } = req.body;

    // Resolve OS user — X-OS-User header is most reliable (set by hooks.json allowedEnvVars)
    const osUserFromHeader  = (req.headers['x-os-user'] as string) || '';
    const projectFromHeader = (req.headers['x-project-dir'] as string) || '';
    const osUserFromSession = claudeSessionUserStore.get(session_id);
    const enrolledSession   = sessionStore.get(session_id);
    const user_email = osUserFromHeader || osUserFromSession || enrolledSession?.user_email || user_email_body || 'claude-code-hook@reva.ai';

    const sessionIntent   = sessionIntentStore.get(session_id);
    const promptIntent    = sessionIntent?.intent         || 'unknown';
    const priorIntents    = sessionIntent?.prior_intents  || '';
    const query           = sessionIntent?.prompt         || '';
    const promptHistory   = sessionIntent?.prompt_history || [];
    const baseSensitivity = (() => {
      // Check MCP probe results for auto-classified sensitivity
      const probed = discoveredServers.get(server_name) || discoveredServers.get(`claude.ai ${server_name}`);
      const probedTool = probed?.tools?.find(t => t.name === tool_name || tool_name.includes(t.name));
      return probedTool?.sensitivity || 'medium';
    })();

    // Record dynamic tool for inventory (especially for auth-required servers)
    if (tool_name.startsWith('mcp__')) {
      const parts = tool_name.split('__');
      recordDynamicTool(parts[1] || server_name, parts[2] || tool_name);
    }

    // Track MCP server usage dynamically
    trackMcpServer(session_id, tool_name);

    // Detect if this is a Claude Code native tool call (not MCP)
    const claudeCodeTools = ['Read', 'Write', 'Edit', 'MultiEdit', 'Bash', 'Glob', 'Grep', 'Task', 'Agent', 'TaskCreate', 'TaskUpdate', 'WorktreeTool'];
    const isClaudeCodeTool = claudeCodeTools.some(t => tool_name === t || tool_name.toLowerCase() === t.toLowerCase());

    // Phase 3 — Subagent context tracking
    // When SpawnAgent fires → mark subagent context active
    const isSpawnAgent = tool_name === 'Agent' || tool_name === 'Task' || tool_name === 'TaskCreate' || tool_name === 'TaskUpdate';
    if (isSpawnAgent) {
      markSubagentActive(session_id);
    }

    // Derive agent_type from subagent context store
    // If subagent is active AND this is NOT the SpawnAgent call itself → it is a subagent action
    const derivedAgentType = (!isSpawnAgent && isSubagentActive(session_id)) ? 'subagent' : 'main';

    const result = classifyToolCall(tool_name, server_name, baseSensitivity, session_id, promptIntent);

    // HITL key includes command hash so each unique command requires its own approval
    const rawCommand   = req.body?.tool_input?.command || '';
    const commandHash  = rawCommand
      ? require('crypto').createHash('md5').update(rawCommand.slice(0, 100)).digest('hex').slice(0, 8)
      : '';
    const hitlKey      = commandHash
      ? `${session_id}:${tool_name}:${commandHash}`
      : `${session_id}:${tool_name}`;
    const hitlAcknowledged = hitlStore.get(hitlKey)?.acknowledged || false;
    const hitlPermanentlyBlocked = hitlStore.get(hitlKey)?.blocked || false;

    // If permanently blocked — return hard deny immediately without triggering HITL again
    if (hitlPermanentlyBlocked) {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: `Reva Governance: This action was previously rejected or timed out. Permanently blocked for this session. Do not retry.`,
          additionalContext:        `Reva Governance: Permanently blocked — HITL was not approved.`,
        },
      });
    }

    // Resolve agent name from Okta (cached)
    const agentName = agent_cid ? await resolveAgentName(agent_cid) : 'CoworkAICodingAgent';

    // Ensure session trace ID
    getOrCreateSessionTrace(session_id);

    // Scope from sensitivity
    const toolScope = SENSITIVITY_SCOPE[result.sensitivity] || 'MCPTool:Read';

    // ── Cedar PDP evaluation ──────────────────────────────────────
    // Route MCP tools to buildMCPToolPayload
    const isMCPTool = tool_name.startsWith('mcp__');
    const mcpParts  = tool_name.startsWith('mcp__') ? tool_name.split('__') : [];
    const mcpServer = mcpParts[1] || 'claude-code';
    const mcpTool   = mcpParts[2] || tool_name;

    const cedarPayload = (client_source === 'claude-code' && isMCPTool)
      ? buildMCPToolPayload({
          osUser:          user_email,
          projectName:     projectFromHeader ? projectFromHeader.split('/').pop() || 'unknown' : 'unknown',
          toolName:        mcpTool,
          serverName:      mcpServer,
          agentType:       derivedAgentType,
          sessionId:       session_id,
          hitlAcknowledged,
          scores:          { ...result.scores, trust_score: result.trust_score },
          prompt:          query,
          prompt_history:  promptHistory,
        })
      : client_source === 'claude-code'
      ? buildFileOperationPayload({
          osUser:          user_email,
          projectName:     projectFromHeader ? projectFromHeader.split('/').pop() || 'claude-demo-project' : server_name || 'claude-demo-project',
          toolName:        tool_name,
          filePath:        req.body?.tool_input?.file_path  // Edit, Write, MultiEdit
                            || req.body?.tool_input?.path        // Read
                            || req.body?.tool_input?.new_path    // MultiEdit rename
                            || req.body?.tool_input?.pattern     // Glob
                            || req.body?.tool_input?.regex       // Grep
                            || '',
          command:         req.body?.tool_input?.command || '',
          agentType:       derivedAgentType,
          sessionId:       session_id,
          spawnCount:      subagentContextStore.get(session_id)?.spawn_count || 1,
          hitlAcknowledged,
          scores:          { ...result.scores, trust_score: result.trust_score },
          prompt:          query,
          prompt_history:  promptHistory,
        })
      : buildCallToolPayload({
          agentName,
          agentId:         agent_cid,
          toolName:        tool_name,
          serverName:      server_name,
          humanSub:        user_email,
          clientSource:    client_source,
          sessionId:       session_id,
          sensitivity:     result.sensitivity,
          toolScope,
          scores:          { ...result.scores, trust_score: result.trust_score },
          hitlAcknowledged,
          intent:          result.intent,
          priorIntents,
          query,
          queryHistory:    priorIntents,
        });

    const cedarResult = await evaluateCedar(cedarPayload);

    let effect: 'Permit' | 'Deny' | 'HITL' = 'Permit';
    let reason  = 'Tool call permitted';

    if (cedarResult.decision === 'deny') {
      // Extract command_risk from payload context for bash commands
      const commandRisk    = (cedarPayload as any)?.context?.command_risk || 'safe';
      const fileZone       = (cedarPayload as any)?.context?.file_zone    || 'other';
      // Read agent_type from Cedar payload context — more reliable than derivedAgentType for parallel requests
      const payloadAgentType = (cedarPayload as any)?.context?.agent_type || derivedAgentType;

      // Destructive commands, secrets, and subagent src writes → always hard deny, never HITL
      const isHardDeny =
        commandRisk      === 'destructive' ||
        fileZone         === 'secrets'     ||
        (payloadAgentType === 'subagent' && fileZone === 'src');

      if (isHardDeny) {
        effect = 'Deny';
        reason = 'Blocked by Reva Governance Policy';
      } else if (!hitlAcknowledged) {
        effect = 'HITL';
        reason = 'HITL required — approve in Okta Verify to proceed';
      } else {
        effect = 'Deny';
        reason = 'Blocked by Reva Governance Policy';
      }
    }

    logDecision({
      timestamp:   new Date().toISOString(),
      session_id,
      user_email,
      tool:        tool_name,
      server:      server_name,
      sensitivity: result.sensitivity,
      effect,
      reason,
      intent:            promptIntent,
      trust_score:       result.trust_score,
      scores:            result.scores,
      prompt:            query.slice(0, 200),
      prompt_history:    promptHistory,
      agent_type:        derivedAgentType,
      command_risk:      (cedarPayload as any)?.context?.command_risk || '',
      file_zone:         (cedarPayload as any)?.context?.file_zone   || '',
      cedar_decision:    cedarResult.decision,
      cedar_policy_name: cedarResult.policy_name,
      cedar_latency_ms:  cedarResult.latency_ms,
      cedar_decision_id: cedarResult.decision_id,
    });

    // HITL: trigger Okta Verify push — SYNCHRONOUS — hold response until approved/denied
    if (effect === 'HITL' && !hitlInFlight.get(hitlKey)) {
      hitlInFlight.set(hitlKey, true);
      try {
        console.log(`[HITL] Triggering synchronous push for ${user_email} → ${tool_name}`);
        const triggerResult = await triggerHITL(resolveHITLEmail(user_email), tool_name, session_id);

        if (!triggerResult.success || !triggerResult.poll_url) {
          recordHITLDenial(session_id, tool_name, user_email, 'error');
          hitlInFlight.delete(hitlKey);
          // Fail open with warning if HITL trigger fails
          return res.json({
            hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny',
              permissionDecisionReason: 'HITL trigger failed — Okta Verify unavailable' },
            reva: { effect: 'Deny', reason: 'HITL trigger failed', cedar: cedarResult },
          });
        }

        // Poll synchronously — Claude Code waits for this response
        const status = await pollHITL(triggerResult.poll_url);

        if (status === 'approved') {
          // Re-evaluate Cedar with hitlAcknowledged: true
          recordHITLApproval(session_id, tool_name, user_email, triggerResult.poll_url);
          hitlStore.set(hitlKey, { acknowledged: true, approved_at: new Date().toISOString(), tool_name });

          // Rebuild payload with hitlAcknowledged: true and re-evaluate
          const approvedPayload = (client_source === 'claude-code' && isMCPTool)
            ? buildMCPToolPayload({ osUser: user_email, projectName: projectFromHeader ? projectFromHeader.split('/').pop() || 'unknown' : 'unknown', toolName: mcpTool, serverName: mcpServer, agentType: derivedAgentType, sessionId: session_id, hitlAcknowledged: true, scores: { ...result.scores, trust_score: result.trust_score }, prompt: query, prompt_history: promptHistory })
            : buildFileOperationPayload({ osUser: user_email, projectName: projectFromHeader ? projectFromHeader.split('/').pop() || 'claude-demo-project' : 'claude-demo-project', toolName: tool_name, filePath: req.body?.tool_input?.file_path || req.body?.tool_input?.path || req.body?.tool_input?.pattern || req.body?.tool_input?.regex || '', command: req.body?.tool_input?.command || '', agentType: derivedAgentType, sessionId: session_id, hitlAcknowledged: true, scores: { ...result.scores, trust_score: result.trust_score }, prompt: query, prompt_history: promptHistory });

          const approvedCedar = await evaluateCedar(approvedPayload);

          logDecision({ timestamp: new Date().toISOString(), session_id, user_email, tool: tool_name, server: server_name, sensitivity: result.sensitivity, effect: 'Permit', reason: 'HITL approved — Cedar re-evaluated and permitted', intent: promptIntent, trust_score: result.trust_score, scores: result.scores, prompt: query.slice(0, 200), prompt_history: promptHistory, agent_type: derivedAgentType, cedar_decision: approvedCedar.decision, cedar_policy_name: approvedCedar.policy_name, cedar_latency_ms: approvedCedar.latency_ms });

          hitlInFlight.delete(hitlKey);
          return res.json({
            hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
            reva: { effect: 'Permit', reason: `HITL approved by ${resolveHITLEmail(user_email)}`, hitlAcknowledged: true, cedar: approvedCedar },
          });

        } else {
          // Denied or timed out
          const denyStatus = status === 'waiting' ? 'timeout' : status as 'denied' | 'timeout' | 'error';
          recordHITLDenial(session_id, tool_name, user_email, denyStatus, triggerResult.poll_url);
          hitlInFlight.delete(hitlKey);

          logDecision({ timestamp: new Date().toISOString(), session_id, user_email, tool: tool_name, server: server_name, sensitivity: result.sensitivity, effect: 'Deny', reason: `HITL ${denyStatus} by ${resolveHITLEmail(user_email)}`, intent: promptIntent, trust_score: result.trust_score, scores: result.scores, prompt: query.slice(0, 200), prompt_history: promptHistory, agent_type: derivedAgentType, cedar_decision: cedarResult.decision, cedar_policy_name: cedarResult.policy_name, cedar_latency_ms: cedarResult.latency_ms });

          return res.json({
            hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny',
              permissionDecisionReason: `HITL ${denyStatus} — tool call blocked` },
            reva: { effect: 'Deny', reason: `HITL ${denyStatus}`, cedar: cedarResult },
          });
        }

      } catch (err: any) {
        console.error(`[HITL] Synchronous error: ${err.message}`);
        hitlInFlight.delete(hitlKey);
        return res.json({
          hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny',
            permissionDecisionReason: 'HITL error — tool call blocked' },
          reva: { effect: 'Deny', reason: 'HITL error' },
        });
      }
    }

    if (effect === 'Deny') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: reason,
        },
        reva: { effect, reason, trust_score: result.trust_score, sensitivity: result.sensitivity, hitlAcknowledged, cedar: cedarResult },
      });
    }

    if (effect === 'HITL') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: `⏳ Waiting for Okta Verify approval from ${resolveHITLEmail(user_email)} — please approve or reject on your phone. Tool: ${tool_name} | Command: ${rawCommand.slice(0, 60) || 'n/a'} | Session: ${session_id.slice(0, 8)}`,
          additionalContext:        `Reva governance: HITL approval required. Okta Verify push sent to ${resolveHITLEmail(user_email)}.`,
        },
        reva: { effect: 'HITL', reason, hitl_required: true, hitl_key: hitlKey, trust_score: result.trust_score, sensitivity: result.sensitivity, hitlAcknowledged, cedar: cedarResult },
      });
    }

    return res.json({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
      reva: { effect: 'Permit', reason, trust_score: result.trust_score, sensitivity: result.sensitivity, cedar: cedarResult },
    });

  } catch (err: any) {
    console.error('beforeToolCall error:', err.message);
    // Fail-closed during subagent context — never fail open for subagents
    const session_id_safe = req.body?.session_id || '';
    const isSubagentCtx   = subagentContextStore.get(session_id_safe)?.active || false;
    if (isSubagentCtx) {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: 'Blocked by Reva Governance Policy',
        },
      });
    }
    return res.json({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } });
  }
}
