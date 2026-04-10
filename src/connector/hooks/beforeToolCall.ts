// PreToolUse hook handler
// Receives tool call from Cowork before it executes
// Looks up session intent, classifies tool, computes scores, returns decision
// Cedar replaces simple decision logic in Phase 7

import { Request, Response } from 'express';
import { classifyToolCall }           from '../../api/intentClassifier';
import { sessionStore, logDecision }  from '../discovery/enroll';
import { sessionIntentStore }         from './beforePrompt';
import { getToolSensitivity }         from '../../api/knownServers';

// HITL acknowledgement store — Phase 6 populates this
export const hitlStore = new Map<string, {
  acknowledged: boolean;
  approved_at:  string;
  tool_name:    string;
}>();

export async function handleToolCall(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization || '';
    const token      = authHeader.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ error: 'Missing connector token' });
    }

    // Extract PreToolUse hook payload from Cowork
    const {
      session_id   = `session-${Date.now()}`,
      tool_name    = '',
      tool_input   = {},
      server_name  = '',
      user_email   = 'unknown',
    } = req.body;

    // Retrieve prompt intent from session store
    const sessionIntent = sessionIntentStore.get(session_id);
    const promptIntent  = sessionIntent?.intent || 'unknown';
    const sessionTrust  = sessionIntent?.trust_score || 50;

    // Get base sensitivity from known-servers registry
    const baseSensitivity = getToolSensitivity(server_name, tool_name);

    // Classify tool call
    const result = classifyToolCall(
      tool_name,
      server_name,
      baseSensitivity,
      session_id,
      promptIntent,
    );

    // Check HITL acknowledgement
    const hitlKey         = `${session_id}:${tool_name}`;
    const hitlAcknowledged = hitlStore.get(hitlKey)?.acknowledged || false;

    // ── Simple decision logic (Phase 4) ──────────────────────────
    // Phase 7: replaced by Cedar PDP call with all scores as context

    let effect: 'Permit' | 'Deny' | 'HITL' = 'Permit';
    let reason  = 'Tool call permitted';

    if (result.scores.intent_mismatch_score > 50) {
      effect = 'Deny';
      reason = `Intent mismatch: prompt intent was "${promptIntent}" but tool "${tool_name}" suggests "${result.intent}"`;
    } else if (result.scores.sod_violation) {
      effect = 'Deny';
      reason = `SOD violation: same user cannot perform this action on this resource`;
    } else if (result.sensitivity === 'critical') {
      effect = 'Deny';
      reason = `Critical sensitivity tool "${tool_name}" — not permitted via Cowork`;
    } else if (result.sensitivity === 'high' && !hitlAcknowledged) {
      effect = 'HITL';
      reason = `High sensitivity tool "${tool_name}" requires human approval`;
    } else if (result.trust_score < 30) {
      effect = 'Deny';
      reason = `Trust score critically low (${result.trust_score}/100) — anomalous session pattern`;
    } else if (result.scores.bulk_operation_score > 50) {
      effect = 'HITL';
      reason = `Bulk operation detected on "${tool_name}" — requires human approval`;
    }

    // Log decision
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

    // Return decision to Cowork hook
    if (effect === 'Deny') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: reason,
        },
        reva: {
          effect,
          reason,
          trust_score:       result.trust_score,
          intent:            result.intent,
          sensitivity:       result.sensitivity,
          hitlAcknowledged,
          scores:            result.scores,
        },
      });
    }

    if (effect === 'HITL') {
      // Phase 6 wires Okta Verify push here
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: `${reason}. Check your Okta Verify app to approve.`,
        },
        reva: {
          effect:            'HITL',
          reason,
          hitl_required:     true,
          hitl_key:          hitlKey,
          trust_score:       result.trust_score,
          intent:            result.intent,
          sensitivity:       result.sensitivity,
          hitlAcknowledged,
          scores:            result.scores,
        },
      });
    }

    return res.json({
      hookSpecificOutput: {
        hookEventName:      'PreToolUse',
        permissionDecision: 'allow',
      },
      reva: {
        effect:      'Permit',
        reason,
        trust_score: result.trust_score,
        intent:      result.intent,
        sensitivity: result.sensitivity,
        scores:      result.scores,
      },
    });

  } catch (err: any) {
    console.error('beforeToolCall error:', err.message);
    // Fail open on internal error
    return res.json({
      hookSpecificOutput: {
        hookEventName:      'PreToolUse',
        permissionDecision: 'allow',
      },
    });
  }
}
