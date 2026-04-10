import { Request, Response } from 'express';
import { classifyPrompt, recordBypassAttempt } from '../../api/intentClassifier';
import { logDecision } from '../discovery/enroll';

export const sessionIntentStore = new Map<string, {
  intent:      string;
  trust_score: number;
  prompt_hash: string;
  timestamp:   string;
}>();

export async function handlePromptSubmit(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization || '';
    const token      = authHeader.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Missing connector token' });

    const {
      session_id = `session-${Date.now()}`,
      prompt     = '',
      user_email = 'unknown',
    } = req.body;

    const result = classifyPrompt(prompt, session_id, user_email);

    sessionIntentStore.set(session_id, {
      intent:      result.intent,
      trust_score: result.trust_score,
      prompt_hash: Buffer.from(prompt).toString('base64').slice(0, 32),
      timestamp:   new Date().toISOString(),
    });

    // ── Decision logic (Phase 4) ──────────────────────────────────
    let effect: 'Permit' | 'Deny' | 'HITL' = 'Permit';
    let reason  = 'Prompt permitted';

    if (result.scores.injection_score > 30) {
      effect = 'Deny';
      reason = `Prompt injection detected (score: ${result.scores.injection_score})`;
      recordBypassAttempt(session_id);
    } else if (result.scores.jailbreak_score > 30) {
      effect = 'Deny';
      reason = `Jailbreak attempt detected (score: ${result.scores.jailbreak_score})`;
      recordBypassAttempt(session_id);
    } else if (result.scores.escalation_score > 60) {
      effect = 'Deny';
      reason = `Privilege escalation attempt (score: ${result.scores.escalation_score})`;
    } else if (result.trust_score < 20) {
      effect = 'Deny';
      reason = `Trust score critically low (${result.trust_score}/100)`;
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
        reva: { effect, reason, trust_score: result.trust_score, intent: result.intent, scores: result.scores },
      });
    }

    return res.json({
      hookSpecificOutput: { hookEventName: 'UserPromptSubmit', permissionDecision: 'allow' },
      reva: { effect: 'Permit', reason, trust_score: result.trust_score, intent: result.intent, scores: result.scores },
    });

  } catch (err: any) {
    console.error('beforePrompt error:', err.message);
    return res.json({ hookSpecificOutput: { hookEventName: 'UserPromptSubmit', permissionDecision: 'allow' } });
  }
}
