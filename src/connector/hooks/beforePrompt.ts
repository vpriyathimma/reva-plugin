// UserPromptSubmit hook handler
// Receives prompt from Cowork before Claude processes it
// Classifies intent, computes scores, returns decision to Cowork
// Cedar replaces simple decision logic in Phase 7

import { Request, Response } from 'express';
import { classifyPrompt, recordBypassAttempt } from '../../api/intentClassifier';
import { sessionStore, logDecision }           from '../discovery/enroll';

// In-session prompt intent store
// Threaded to PreToolUse via session_id
export const sessionIntentStore = new Map<string, {
  intent:       string;
  trust_score:  number;
  prompt_hash:  string;
  timestamp:    string;
}>();

export async function handlePromptSubmit(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization || '';
    const token      = authHeader.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ error: 'Missing connector token' });
    }

    // Extract hook payload from Cowork
    const {
      session_id  = `session-${Date.now()}`,
      prompt      = '',
      user_email  = 'unknown',
    } = req.body;

    // Classify prompt intent + compute all guardrail scores
    const result = classifyPrompt(prompt, session_id, user_email);

    // Thread intent to PreToolUse via session store
    sessionIntentStore.set(session_id, {
      intent:      result.intent,
      trust_score: result.trust_score,
      prompt_hash: Buffer.from(prompt).toString('base64').slice(0, 32),
      timestamp:   new Date().toISOString(),
    });

    // ── Simple decision logic (Phase 4) ──────────────────────────
    // Phase 7: replaced by Cedar PDP call with all scores as context

    let effect:  'Permit' | 'Deny' | 'HITL' = 'Permit';
    let reason   = 'Prompt permitted';

    if (result.scores.injection_score > 70) {
      effect = 'Deny';
      reason = `Prompt injection detected (score: ${result.scores.injection_score})`;
      recordBypassAttempt(session_id);
    } else if (result.scores.jailbreak_score > 70) {
      effect = 'Deny';
      reason = `Jailbreak attempt detected (score: ${result.scores.jailbreak_score})`;
      recordBypassAttempt(session_id);
    } else if (result.scores.escalation_score > 70) {
      effect = 'Deny';
      reason = `Privilege escalation attempt detected (score: ${result.scores.escalation_score})`;
    } else if (result.trust_score < 20) {
      effect = 'Deny';
      reason = `Trust score critically low (${result.trust_score}/100)`;
    }

    // Log decision
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

    // Return decision to Cowork hook
    if (effect === 'Deny') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:             'UserPromptSubmit',
          permissionDecision:        'deny',
          permissionDecisionReason:  reason,
        },
        reva: {
          effect,
          reason,
          trust_score:  result.trust_score,
          intent:       result.intent,
          scores:       result.scores,
        },
      });
    }

    return res.json({
      hookSpecificOutput: {
        hookEventName:      'UserPromptSubmit',
        permissionDecision: 'allow',
      },
      reva: {
        effect:      'Permit',
        reason,
        trust_score: result.trust_score,
        intent:      result.intent,
        scores:      result.scores,
      },
    });

  } catch (err: any) {
    console.error('beforePrompt error:', err.message);
    // Fail open on internal error — do not block user
    return res.json({
      hookSpecificOutput: {
        hookEventName:      'UserPromptSubmit',
        permissionDecision: 'allow',
      },
    });
  }
}
