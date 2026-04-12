import { Request, Response }          from 'express';
import { classifyPrompt, recordBypassAttempt } from '../../api/intentClassifier';
import { logDecision }                from '../discovery/enroll';
import { resolveAgentName }           from '../../api/agentResolver';
import { evaluateCedar, buildSubmitPromptPayload, getOrCreateSessionTrace } from '../../api/pdpEvaluate';

export const sessionIntentStore = new Map<string, {
  intent:       string;
  trust_score:  number;
  query:        string;
  prior_intents: string;
  timestamp:    string;
}>();

// Query history per session — last 3 prompts
export const queryHistoryStore = new Map<string, string[]>();

export async function handlePromptSubmit(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization || '';
    const token      = authHeader.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Missing connector token' });

    const {
      session_id   = `session-${Date.now()}`,
      prompt       = '',
      user_email   = 'unknown',
      agent_cid    = '',
      client_source = 'cowork',
    } = req.body;

    // Classify intent + compute guardrail scores
    const result = classifyPrompt(prompt, session_id, user_email);

    // Build query history
    const history = queryHistoryStore.get(session_id) || [];
    const queryHistory = history.slice(-3).join(', ');
    history.push(prompt.slice(0, 200));
    queryHistoryStore.set(session_id, history.slice(-10));

    // Build prior intents
    const prevIntent   = sessionIntentStore.get(session_id);
    const priorIntents = prevIntent
      ? `${prevIntent.prior_intents},${prevIntent.intent}`.replace(/^,/, '')
      : '';

    // Store current intent for PreToolUse threading
    sessionIntentStore.set(session_id, {
      intent:        result.intent,
      trust_score:   result.trust_score,
      query:         prompt.slice(0, 500),
      prior_intents: priorIntents,
      timestamp:     new Date().toISOString(),
    });

    // Resolve agent name from Okta (cached after first call)
    const agentName = agent_cid ? await resolveAgentName(agent_cid) : 'CoworkAICodingAgent';

    // Ensure session trace ID exists
    getOrCreateSessionTrace(session_id);

    // ── Cedar PDP evaluation (Phase 7) ────────────────────────────
    const cedarPayload = buildSubmitPromptPayload({
      agentName,
      agentId:      agent_cid,
      humanSub:     user_email,
      clientSource: client_source,
      sessionId:    session_id,
      scores:       { ...result.scores, trust_score: result.trust_score },
      intent:       result.intent,
      priorIntents,
      query:        prompt,
      queryHistory,
    });

    const cedarResult = await evaluateCedar(cedarPayload);

    let effect: 'Permit' | 'Deny' | 'HITL' = 'Permit';
    let reason  = 'Prompt permitted';

    if (cedarResult.decision === 'deny') {
      effect = 'Deny';
      reason = cedarResult.policy_name
        ? `Denied by policy: ${cedarResult.policy_name}`
        : 'Denied by Cedar PDP';
      recordBypassAttempt(session_id);
    } else if (cedarResult.decision === 'conditional_allow') {
      effect = 'HITL';
      reason = cedarResult.policy_name
        ? `HITL required by policy: ${cedarResult.policy_name}`
        : 'HITL required by Cedar PDP';
    }

    logDecision({
      timestamp:   new Date().toISOString(),
      session_id,
      user_email,
      tool:        'prompt',
      server:      'cowork',
      sensitivity: result.sensitivity,
      effect,
      reason,
    });

    if (effect === 'Deny') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'UserPromptSubmit',
          permissionDecision:       'deny',
          permissionDecisionReason: reason,
        },
        reva: { effect, reason, trust_score: result.trust_score, intent: result.intent, scores: result.scores, cedar: cedarResult },
      });
    }

    return res.json({
      hookSpecificOutput: { hookEventName: 'UserPromptSubmit', permissionDecision: 'allow' },
      reva: { effect: 'Permit', reason, trust_score: result.trust_score, intent: result.intent, scores: result.scores, cedar: cedarResult },
    });

  } catch (err: any) {
    console.error('beforePrompt error:', err.message);
    return res.json({ hookSpecificOutput: { hookEventName: 'UserPromptSubmit', permissionDecision: 'allow' } });
  }
}
