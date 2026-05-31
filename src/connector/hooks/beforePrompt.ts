// beforePrompt — pure classifier + context store
// NO Cedar eval here. Prompt + prompt_history flow as context into PreToolUse.
// Cedar makes all decisions at tool call time, not prompt time.

import { Request, Response }          from 'express';
import { classifyPrompt, recordBypassAttempt, recordBlock, getPersistentTrust } from '../../api/intentClassifier';
import { logDecision }                from '../discovery/enroll';
import { getOrCreateSessionTrace, evaluateCedar, buildClaudeCodeInjectionPayload } from '../../api/pdpEvaluate';

import { subagentContextStore } from './beforeToolCall';

export const sessionIntentStore = new Map<string, {
  intent:         string;
  trust_score:    number;
  sensitivity:    string;
  scores:         Record<string, any>;
  prompt:         string;
  prompt_history: string[];
  prior_intents:  string;
  initial_scope?: string;
  timestamp:      string;
}>();

// Query history per session — last 10 prompts, PreToolUse reads last 3
export const queryHistoryStore = new Map<string, string[]>();

export async function handlePromptSubmit(req: Request, res: Response) {
  try {
    // Read OS user from X-OS-User header (set by hooks.json allowedEnvVars)
    const osUserFromHeader  = (req.headers['x-os-user'] as string) || '';

    const {
      session_id   = `session-${Date.now()}`,
      prompt       = '',
      user_email   = osUserFromHeader || (req as any).user?.email || 'claude-code-hook@reva.ai',
    } = req.body;

    // Detect ! prefix bypass attempts — log only, do NOT fire Cedar
    const isBypassAttempt = prompt.trim().startsWith('!');
    if (isBypassAttempt) {
      console.warn(`[BYPASS] Developer used ! command bypass: session=${session_id} user=${user_email} prompt="${prompt.slice(0, 100)}"`);
      recordBypassAttempt(session_id);
    }

    // Classify intent + compute guardrail scores
    const result = classifyPrompt(prompt, session_id, user_email);

    // Record blocks when Claude would likely block this prompt
    if (result.scores.injection_score > 50) {
      recordBlock(user_email, {
        type: 'prompt_injection',
        prompt: prompt.slice(0, 200),
        score: result.scores.injection_score,
        timestamp: new Date().toISOString(),
      });
    }
    if (result.scores.jailbreak_score > 50) {
      recordBlock(user_email, {
        type: 'jailbreak_attempt',
        prompt: prompt.slice(0, 200),
        score: result.scores.jailbreak_score,
        timestamp: new Date().toISOString(),
      });
    }

    // Build query history
    const history = queryHistoryStore.get(session_id) || [];
    history.push(prompt.slice(0, 500));
    queryHistoryStore.set(session_id, history.slice(-10));

    // Build prior intents chain
    const prevIntent   = sessionIntentStore.get(session_id);
    const priorIntents = prevIntent
      ? `${prevIntent.prior_intents},${prevIntent.intent}`.replace(/^,/, '')
      : '';

    // Persistent, penalty-based actor trust — carries forward across prompts and
    // decays 15 per recorded block (injection/jailbreak). Replaces the per-prompt
    // computeTrustScore value, which crashes to 0 on injection; that value still
    // drives `sensitivity` only. recordBlock above already incremented the count,
    // so an injection prompt reports baseline-15 (e.g. 55), not 0.
    result.trust_score = getPersistentTrust(user_email);

    // Store full context — PreToolUse reads this for every Cedar evaluation
    sessionIntentStore.set(session_id, {
      intent:         result.intent,
      trust_score:    result.trust_score,
      sensitivity:    result.sensitivity,
      scores:         result.scores,
      prompt:         prompt.slice(0, 500),
      prompt_history: history.slice(-3),
      prior_intents:  priorIntents,
      // Phase 2 — initial task scope = the FIRST prompt's intent for this session.
      // Derived from the prompt (classifier), not hardcoded; subsequent prompts
      // don't overwrite it, so it stays the originating scope / ceiling.
      initial_scope:  prevIntent?.initial_scope || result.intent,
      timestamp:      new Date().toISOString(),
    });

    // Ensure session trace ID exists
    getOrCreateSessionTrace(session_id);

    // Reset subagent context on new prompt — each developer turn starts fresh
    if (subagentContextStore.has(session_id)) {
      subagentContextStore.set(session_id, {
        active:      false,
        started_at:  new Date().toISOString(),
        spawn_count: 0,
      });
      console.log(`[Subagent] Context reset for session=${session_id} on new prompt`);
    }

    // Phase 1 — exception-only SubmitPrompt.
    // Route injection/jailbreak through Cedar so the deny is recorded in the
    // decision logs (with full prompt + prompt_history). The prompt is NEVER
    // erased here — enforcement of effects still happens at PreToolUse. Clean
    // prompts skip Cedar entirely and keep the original classify-only log.
    const isInjection = result.scores.injection_score > 50;
    const isJailbreak = result.scores.jailbreak_score > 50;

    if (isInjection || isJailbreak) {
      const detection   = isInjection ? 'prompt_injection' : 'jailbreak_attempt';
      const projectName = (req.body.project_name as string) || 'unknown';
      let cedarResult;
      try {
        cedarResult = await evaluateCedar(buildClaudeCodeInjectionPayload({
          osUser:        user_email,
          projectName,
          sessionId:     session_id,
          prompt,
          promptHistory: history.slice(-3),
          isInjection,
          isJailbreak,
          scores:        result.scores,
          trustScore:    result.trust_score,
        }));
      } catch (e: any) {
        console.error('[Prompt:Cedar] SubmitPrompt eval failed:', e.message);
      }

      logDecision({
        timestamp:      new Date().toISOString(),
        session_id,
        user_email,
        tool:           'prompt',
        server:         'claude-code',
        sensitivity:    result.sensitivity,
        effect:         cedarResult && cedarResult.decision === 'allow' ? 'Permit' : 'Deny',
        reason:         (cedarResult && cedarResult.policy_name) || detection,
        intent:         result.intent,
        trust_score:    result.trust_score,
        scores:         result.scores,
        prompt,
        agent_type:     'main',
        command_risk:   '',
        file_zone:      '',
      });
      console.log(`[Prompt:Cedar] ${detection} session=${session_id} decision=${cedarResult?.decision ?? 'error'} policy=${cedarResult?.policy_name || detection} trust=${result.trust_score}`);
    } else {
      // Clean prompt — classify-only log (unchanged: enforcement deferred to PreToolUse)
      logDecision({
        timestamp:      new Date().toISOString(),
        session_id,
        user_email,
        tool:           'prompt',
        server:         'claude-code',
        sensitivity:    result.sensitivity,
        effect:         'Permit',
        reason:         'Prompt classified — enforcement deferred to PreToolUse',
        intent:         result.intent,
        trust_score:    result.trust_score,
        scores:         result.scores,
        prompt:         prompt.slice(0, 200),
        agent_type:     'main',
        command_risk:   '',
        file_zone:      '',
      });
    }

    console.log(`[Prompt] session=${session_id} intent=${result.intent} trust=${result.trust_score} bypass=${isBypassAttempt}`);

    // Always allow — Cedar evaluates at PreToolUse time with prompt context
    return res.json({
      hookSpecificOutput: { hookEventName: 'UserPromptSubmit', permissionDecision: 'allow' },
      reva: {
        effect:      'Permit',
        reason:      'Prompt classified — enforcement at tool call',
        trust_score: result.trust_score,
        intent:      result.intent,
        sensitivity: result.sensitivity,
        scores:      result.scores,
      },
    });

  } catch (err: any) {
    console.error('beforePrompt error:', err.message);
    return res.json({ hookSpecificOutput: { hookEventName: 'UserPromptSubmit', permissionDecision: 'allow' } });
  }
}
