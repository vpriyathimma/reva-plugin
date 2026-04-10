import { Request, Response } from 'express';
import { classifyToolCall }              from '../../api/intentClassifier';
import { logDecision }                   from '../discovery/enroll';
import { sessionIntentStore }            from './beforePrompt';
import { getToolSensitivity }            from '../../api/knownServers';
import { triggerHITL }                  from '../hitl/trigger';
import { pollHITL }                     from '../hitl/poll';
import { recordHITLApproval, recordHITLDenial, hitlLog } from '../hitl/callback';

export const hitlStore = new Map<string, {
  acknowledged: boolean;
  approved_at:  string;
  tool_name:    string;
}>();

// In-flight HITL — prevents duplicate pushes for same key
const hitlInFlight = new Map<string, boolean>();

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
    const baseSensitivity = getToolSensitivity(server_name, server_url, tool_name);

    const result = classifyToolCall(tool_name, server_name, baseSensitivity, session_id, promptIntent);

    const hitlKey          = `${session_id}:${tool_name}`;
    const hitlAcknowledged = hitlStore.get(hitlKey)?.acknowledged || false;

    // ── Decision logic ────────────────────────────────────────────
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

    // ── HITL: trigger Okta Verify push in background ──────────────
    if (effect === 'HITL' && !hitlInFlight.get(hitlKey)) {
      hitlInFlight.set(hitlKey, true);

      // Fire and forget — do not block hook response
      (async () => {
        try {
          const triggerResult = await triggerHITL(user_email, tool_name, session_id);

          if (!triggerResult.success || !triggerResult.poll_url) {
            console.warn(`[HITL] Trigger failed: ${triggerResult.error}`);
            recordHITLDenial(session_id, tool_name, user_email, 'error', undefined);
            hitlInFlight.delete(hitlKey);
            return;
          }

          console.log(`[HITL] Push sent to ${user_email} for ${tool_name}`);

          // Poll for response
          const status = await pollHITL(triggerResult.poll_url);

          if (status === 'approved') {
            recordHITLApproval(session_id, tool_name, user_email, triggerResult.poll_url);
          } else {
            recordHITLDenial(session_id, tool_name, user_email, status, triggerResult.poll_url);
          }
        } catch (err: any) {
          console.error(`[HITL] Background error: ${err.message}`);
        } finally {
          hitlInFlight.delete(hitlKey);
        }
      })();
    }

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
          permissionDecisionReason: `${reason}. A push notification has been sent to your Okta Verify app. Approve it then re-submit your request.`,
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
