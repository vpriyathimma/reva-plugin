import { randomUUID } from 'crypto';

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
  principal:  { type: string; id: string };
  action:     { name: string };
  resource:   { type: string; id: string; properties?: Record<string, any> };
  context:    Record<string, any>;
  session_id: string;
}): Promise<CedarResult> {
  const sessionTraceId = getOrCreateSessionTrace(payload.session_id);

  // ── Cedar payload — matches SecureBank format exactly ────────────
  const cedarPayload = [{
    subject: {
      type: payload.principal.type,
      id:   payload.principal.id,
    },
    action: { name: payload.action.name },
    resource: {
      type:       payload.resource.type,
      id:         payload.resource.id,
      properties: payload.resource.properties || {},
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
      type: 'AICodingAgents::MCPTool',
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
      type: 'AICodingAgents::Prompt',
      id:   params.sessionId,
      properties: {
        session_id:    params.sessionId,
        client_source: params.clientSource,
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
      after_hours_score:     params.scores.after_hours_score      ?? 0,
      bypass_attempts_score: params.scores.bypass_attempts_score  ?? 0,
      intent_pool_score:     params.scores.intent_pool_score      ?? 0,
      intent_pool_pattern:   params.scores.intent_pool_pattern    ?? 'none',
    },
    session_id: params.sessionId,
  };
}
