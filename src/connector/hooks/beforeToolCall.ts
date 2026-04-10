import { Request, Response } from 'express';
import { classifyToolCall }          from '../../api/intentClassifier';
import { logDecision }               from '../discovery/enroll';
import { sessionIntentStore }        from './beforePrompt';
import { getToolSensitivity }        from '../../api/knownServers';

export const hitlStore = new Map<string, {
  acknowledged: boolean;
  approved_at:  string;
  tool_name:    string;
}>();

export async function handleToolCall(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization || '';
    const token      = authHeader.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Missing connector token' });

    const {
      session_id  = `session-${Date.now()}`,
      tool_name   = '',
      tool_input  = {},
      server_name = '',
      server_url  = '',
      user_email  = 'unknown',
    } = req.body;

    const sessionIntent   = sessionIntentStore.get(session_id);
    const promptIntent    = sessionIntent?.intent || 'unknown';

    // URL-first lookup — server_url is authoritative, server_name is fallback
    const baseSensitivity = getToolSensitivity(server_name, server_url, tool_name);

    const result = classifyToolCall(tool_name, server_name, baseSensitivity, session_id, promptIntent);

    const hitlKey          = `${session_id}:${tool_name}`;
    const hitlAcknowledged = hitlStore.get(hitlKey)?.acknowledged || false;

    // ── Decision logic (Phase 4) ──────────────────────────────────
    // Phase 7: replaced by Cedar PDP call with all scores as context
    let effect: 'Permit' | 'Deny' | 'HITL' = 'Permit';
    let reason  = 'Tool call permitted';

    const dangerousMismatch =
      ['read'].includes(promptIntent) &&
      ['destructive', 'exfiltrate'].includes(result.intent);

    if (dangerousMismatch) {
      effect = 'Deny';
      reason = `Intent mismatch: prompt intent "${promptIntent}" but tool "${tool_name}" is "${result.intent}"`;
    } else if (result.scores.sod_violation) {
      effect = 'Deny';
      reason = `SOD violation detected`;
    } else if (result.sensitivity === 'critical') {
      effect = 'Deny';
      reason = `Critical sensitivity tool "${tool_name}" — not permitted via Cowork`;
    } else if (result.sensitivity === 'high' && !hitlAcknowledged) {
      effect = 'HITL';
      reason = `High sensitivity tool "${tool_name}" requires human approval`;
    } else if (result.scores.bulk_operation_score > 50 && !hitlAcknowledged) {
      effect = 'HITL';
      reason = `Bulk operation on "${tool_name}" requires human approval`;
    } else if (result.trust_score < 20) {
      effect = 'Deny';
      reason = `Trust score critically low (${result.trust_score}/100)`;
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
    });

    if (effect === 'Deny') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: reason,
        },
        reva: { effect, reason, trust_score: result.trust_score, intent: result.intent, sensitivity: result.sensitivity, hitlAcknowledged, scores: result.scores },
      });
    }

    if (effect === 'HITL') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: `${reason}. Check your Okta Verify app to approve.`,
        },
        reva: { effect: 'HITL', reason, hitl_required: true, hitl_key: hitlKey, trust_score: result.trust_score, intent: result.intent, sensitivity: result.sensitivity, hitlAcknowledged, scores: result.scores },
      });
    }

    return res.json({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
      reva: { effect: 'Permit', reason, trust_score: result.trust_score, intent: result.intent, sensitivity: result.sensitivity, scores: result.scores },
    });

  } catch (err: any) {
    console.error('beforeToolCall error:', err.message);
    return res.json({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } });
  }
}
