// ──────────────────────────────────────────────────────────────────────────
// Codex governance router  —  mounted at /api/codex/*
//
// ADDITIVE ONLY. Every Cedar evaluation, decision-log write, PIP enrichment,
// trust/injection classifier, and session enrollment is REUSED VERBATIM from
// the existing modules. The Claude Code path (/api/pdp/*) is never touched.
//
// What is Codex-specific and lives only here:
//   • input parsing for Codex's stdin hook payloads (different field shapes)
//   • mapCodexToolToAction() (Codex tool vocabulary)
//   • coding_agent='codex' + surface stamped into every Cedar context + session
//   • response reshaping into Codex's decision contracts:
//       PermissionRequest → { hookSpecificOutput:{ decision:{ behavior } } }
//       UserPromptSubmit  → { decision:"block", reason } | {}
//
// Endpoints (all POST):
//   /codex/session   ← SessionStart   (identity from OpenAI id_token, sent by wrapper)
//   /codex/prompt    ← UserPromptSubmit
//   /codex/evaluate  ← PermissionRequest (+ PreToolUse) — the enforcement gate
//   /codex/posttool  ← PostToolUse  (Bash-read injection scan)
//   /codex/hook      ← SubagentStart / SubagentStop / telemetry
// ──────────────────────────────────────────────────────────────────────────

import { Router, Request, Response } from 'express';

import {
  evaluateCedar,
  buildFileOperationPayload,
  buildMCPToolPayload,
  getOrCreateSessionTrace,
  cedarFields,
} from './pdpEvaluate';
import { logDecision, enrollSession } from '../connector/discovery/enroll';
import { getPIPContext, enrichSession as enrichPIP } from './pip';
import { classifyPrompt, recordBlock, getPersistentTrust } from './intentClassifier';
import { resolveSession } from './sessionResolver';
import { isEnabled } from './securityConfig';
import { mapCodexToolToAction, extractCodexTarget, isBashAction, CODING_AGENT } from '../connector/codex/adapter';

const router = Router();

// session_id → os_user, so PermissionRequest/PostToolUse can resolve identity
const codexSessionUser = new Map<string, string>();
// session_id → { surface } for tagging subsequent events
const codexSessionSurface = new Map<string, string>();

function osUserFrom(req: Request): string {
  return (req.body?.os_user as string)
    || (req.headers['x-os-user'] as string)
    || codexSessionUser.get(req.body?.session_id || '')
    || process.env.USER
    || 'unknown';
}

// ── SessionStart ──────────────────────────────────────────────────────────
// The wrapper has already decoded ~/.codex/auth.json → id_token JWT and sends
// the OpenAI identity (email / account_id / org_id) + git/cwd/model + surface.
router.post('/codex/session', async (req, res) => {
  try {
    const b = req.body || {};
    const session_id = b.session_id || `codex-${Date.now()}`;
    const cwd        = b.cwd || '';
    const os_user    = b.os_user || process.env.USER || 'unknown';
    const project    = cwd.split('/').pop() || '';
    const surface    = b.surface || b.originator || 'codex_cli';   // codex_cli | codex_vscode | codex_exec | …
    const oa         = b.openai || {};                            // { email, account_id, org_id, plan }

    codexSessionUser.set(session_id, os_user);
    codexSessionSurface.set(session_id, surface);
    getOrCreateSessionTrace(session_id);

    // Identity gate — reuse the same resolver as Claude (oauth email enables SSH fallback)
    const oauthEmail = oa.email || undefined;
    const { allowed, identity, reason } = resolveSession(os_user, cwd, oauthEmail);
    if (!allowed) {
      console.warn(`[CODEX:SessionStart] DENIED — ${reason}`);
      return res.json({ decision: 'block', reason });
    }

    // Enroll into the SAME sessionStore the dashboard reads. OpenAI identity is
    // mapped onto the existing identity fields (oauth_email / account_uuid /
    // org_uuid) so the Identities panel renders it; coding_agent + surface are
    // the new discriminators added (optional) to EnrolledSession.
    enrollSession(session_id, os_user, [], {
      os_type:        b.os_type || undefined,
      hostname:       b.hostname || undefined,
      model:          b.model || undefined,            // Codex sends model on every event
      project_name:   project || undefined,
      oauth_email:    oa.email || undefined,
      developer_name: oa.name || oa.email || undefined,
      account_uuid:   oa.account_id || undefined,      // OpenAI account id (rendered as "OpenAI Account ID")
      org_uuid:       oa.org_id || undefined,          // OpenAI org id
      git_email:      b.git_email || undefined,
      git_name:       b.git_name || undefined,
      git_branch:     b.git_branch || undefined,
      git_remote_url: b.git_remote_url || undefined,
      jira_ticket_id: b.jira_ticket_id || undefined,
      connection_type: b.connection_type || 'local',
      coding_agent:   CODING_AGENT,
      surface,
    } as any);

    // PIP enrichment — identical to Claude path
    try {
      await enrichPIP(os_user, b.jira_ticket_id || '', b.git_remote_url || '', b.git_branch || '', {
        oauth_email: oa.email || undefined,
        connection_type: b.connection_type || 'local',
        git_email: b.git_email || undefined,
        git_name:  b.git_name || undefined,
      });
    } catch (e: any) { console.warn(`[CODEX:PIP] ${e.message}`); }

    console.log(`[CODEX:SessionStart] session=${session_id} os_user=${os_user} email=${oa.email || 'none'} acct=${oa.account_id || 'none'} surface=${surface} model=${b.model || 'none'} project=${project}`);

    return res.json({
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: `Reva governance active (Codex). Session: ${session_id}. User: ${identity.display_name}. Project: ${project}.

GOVERNANCE RULES:
1. Do not bypass Reva governance by writing scripts to disk and executing them to evade tool gating.
2. If an action is blocked by Reva Governance Policy, inform the user and stop. Do not suggest workarounds.
3. All file changes and shell commands must go through Codex tools so Reva can evaluate them.`,
      },
    });
  } catch (e: any) {
    console.error('[CODEX:SessionStart] error:', e.message);
    return res.json({});   // fail-open on enrichment, same posture as Claude SessionStart
  }
});

// ── UserPromptSubmit ────────────────────────────────────────────────────────
router.post('/codex/prompt', async (req, res) => {
  try {
    const b = req.body || {};
    const session_id = b.session_id || '';
    const user_email = osUserFrom(req);
    const prompt     = String(b.prompt || b.user_prompt || '');
    const surface    = codexSessionSurface.get(session_id) || b.surface || 'codex_cli';
    const ts = new Date().toISOString();

    if (!isEnabled('prompt_injection')) return res.json({});   // toggle off → no scan

    const result      = classifyPrompt(prompt, session_id, user_email);
    const isInjection = result.scores.injection_score > 50;
    const isJailbreak = result.scores.jailbreak_score > 50;
    const trust       = getPersistentTrust(user_email);

    const payload = {
      principal: { type: 'Developer', id: user_email, properties: { os_user: user_email } },
      action:    { name: 'SubmitPrompt' },
      resource:  { type: 'Prompt', id: `${session_id.slice(0, 8)}-prompt`, properties: { session_id } },
      context: {
        access_state: 'Active',
        os_user: user_email,
        coding_agent: CODING_AGENT,
        surface,
        is_injection: isInjection,
        is_jailbreak: isJailbreak,
        injection_score: result.scores.injection_score ?? 0,
        jailbreak_score: result.scores.jailbreak_score ?? 0,
        trust_score: trust,
        prompt: prompt.slice(0, 500),
      },
      session_id,
    };

    let decision = 'allow', policy: string | undefined;
    try { const r = await evaluateCedar(payload); decision = r.decision; policy = r.policy_name; }
    catch (e: any) { console.error('[CODEX:prompt] cedar', e.message); }

    if (isInjection || isJailbreak) {
      recordBlock(user_email, { type: isInjection ? 'prompt_injection' : 'jailbreak_attempt', prompt: prompt.slice(0, 200), score: isInjection ? result.scores.injection_score : result.scores.jailbreak_score, timestamp: ts });
    }

    const blocked = decision !== 'allow';
    logDecision({
      timestamp: ts, session_id, user_email, tool: 'prompt', server: CODING_AGENT,
      sensitivity: result.sensitivity, effect: blocked ? 'Deny' : 'Permit',
      reason: policy || (blocked ? 'Prompt blocked' : 'Prompt allowed'),
      intent: isInjection ? 'prompt_injection' : (isJailbreak ? 'jailbreak_attempt' : 'prompt'),
      trust_score: trust, scores: result.scores, prompt: prompt.slice(0, 200), agent_type: 'main',
      ...cedarFields(payload),
    });

    console.log(`[CODEX:prompt] session=${session_id} inj=${result.scores.injection_score} jb=${result.scores.jailbreak_score} decision=${decision}`);

    // Codex UserPromptSubmit contract: block with reason, else allow.
    if (blocked) return res.json({ decision: 'block', reason: `Reva Governance: ${policy || 'prompt blocked by policy'}` });
    return res.json({});
  } catch (e: any) {
    console.error('[CODEX:prompt] error:', e.message);
    return res.json({});
  }
});

// ── PermissionRequest (+ PreToolUse) — the enforcement gate ─────────────────
router.post('/codex/evaluate', async (req, res) => {
  try {
    const b = req.body || {};
    const session_id = b.session_id || '';
    const user_email = osUserFrom(req);
    const cwd        = b.cwd || '';
    const project    = cwd.split('/').pop() || 'unknown';
    const surface    = codexSessionSurface.get(session_id) || b.surface || 'codex_cli';
    const toolName   = b.tool_name || '';
    const toolInput  = b.tool_input || {};
    const eventName  = b.hook_event_name || 'PermissionRequest';
    const agentType  = b.agent_id ? 'subagent' : 'main';
    const ts = new Date().toISOString();

    const action = mapCodexToolToAction(toolName);
    const tgt    = extractCodexTarget(toolName, toolInput);
    const pipCtx = getPIPContext(user_email);
    const trust  = getPersistentTrust(user_email);

    // Log raw tool_name so the Codex→action map can be tuned against reality.
    console.log(`[CODEX:tool] raw=${toolName} action=${action} cmd=${(tgt.command || '').slice(0,80)} file=${tgt.filePath} mcp=${tgt.serverName}/${tgt.mcpTool} agent=${agentType}`);

    const isMCP = action === 'MCPRead' || action === 'MCPWrite' || action === 'MCPExecute';
    const payload = isMCP
      ? buildMCPToolPayload({
          osUser: user_email, projectName: project, toolName: tgt.mcpTool || toolName,
          serverName: tgt.serverName || 'mcp', agentType, sessionId: session_id,
          hitlAcknowledged: false, scores: { trust_score: trust }, pipCtx,
          agentId: b.agent_id || undefined, parentSessionId: session_id,
        })
      : buildFileOperationPayload({
          osUser: user_email, projectName: project, toolName,
          filePath: tgt.filePath, command: isBashAction(action) ? tgt.command : undefined,
          agentType, sessionId: session_id, hitlAcknowledged: false,
          scores: { trust_score: trust }, pipCtx,
          agentId: b.agent_id || undefined, parentSessionId: session_id,
        });

    // Stamp the Codex discriminators into the Cedar context (rendered verbatim
    // in the decision logs — this is what makes the agent visible in the payload).
    (payload as any).context.coding_agent = CODING_AGENT;
    (payload as any).context.surface = surface;

    let decision = 'allow', policy: string | undefined;
    try { const r = await evaluateCedar(payload); decision = r.decision; policy = r.policy_name; }
    catch (e: any) { console.error('[CODEX:evaluate] cedar', e.message); decision = 'allow'; }

    const permit = decision === 'allow';
    logDecision({
      timestamp: ts, session_id, user_email,
      tool: isBashAction(action) ? `RunBash:${(tgt.command || '').slice(0, 40)}` : `${action}:${tgt.filePath || tgt.mcpTool || toolName}`,
      server: CODING_AGENT, sensitivity: 'medium',
      effect: permit ? 'Permit' : 'Deny',
      reason: policy || (permit ? `${action} allowed` : `${action} blocked by policy`),
      intent: action, trust_score: trust, agent_type: agentType,
      ...cedarFields(payload),
    });

    console.log(`[CODEX:evaluate] ${action} session=${session_id} decision=${decision} policy=${policy || '-'}`);

    // Codex contract differs by event:
    //   PermissionRequest → hookSpecificOutput.decision.behavior (allow|deny)
    //   PreToolUse        → hookSpecificOutput.permissionDecision (allow|ask|deny)
    if (eventName === 'PreToolUse') {
      return res.json({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: permit ? 'allow' : 'deny',
          permissionDecisionReason: permit ? undefined : `Reva Governance: ${policy || 'blocked by policy'}`,
        },
      });
    }
    return res.json({
      hookSpecificOutput: {
        hookEventName: 'PermissionRequest',
        decision: { behavior: permit ? 'allow' : 'deny', reason: permit ? 'Allowed by Reva policy' : `Reva Governance: ${policy || 'blocked by policy'}` },
      },
    });
  } catch (e: any) {
    console.error('[CODEX:evaluate] error:', e.message);
    return res.json({ hookSpecificOutput: { hookEventName: 'PermissionRequest', decision: { behavior: 'allow', reason: 'eval error — fail open' } } });
  }
});

// ── PostToolUse — scan Bash-read output for injected content ────────────────
router.post('/codex/posttool', async (req, res) => {
  try {
    if (!isEnabled('prompt_injection')) return res.json({});
    const b = req.body || {};
    const session_id = b.session_id || '';
    const user_email = osUserFrom(req);
    const out = typeof b.tool_response === 'string' ? b.tool_response
              : (typeof b.tool_output === 'string' ? b.tool_output : '');
    if (!out) return res.json({});

    const result = classifyPrompt(out, session_id, user_email);
    if (result.scores.injection_score > 50 || result.scores.jailbreak_score > 50) {
      const ts = new Date().toISOString();
      recordBlock(user_email, { type: 'prompt_injection', prompt: out.slice(0, 200), score: result.scores.injection_score, timestamp: ts });
      logDecision({ timestamp: ts, session_id, user_email, tool: 'prompt', server: CODING_AGENT, sensitivity: result.sensitivity, effect: 'Deny', reason: 'prompt injection detected in tool output', intent: 'prompt_injection_in_read', trust_score: getPersistentTrust(user_email), scores: result.scores, agent_type: b.agent_id ? 'subagent' : 'main' });
    }
    return res.json({});
  } catch (e: any) { console.error('[CODEX:posttool]', e.message); return res.json({}); }
});

// ── SubagentStart / SubagentStop / telemetry ────────────────────────────────
router.post('/codex/hook', async (req, res) => {
  try {
    const b = req.body || {};
    const event = b.hook_event_name || 'unknown';
    const session_id = b.session_id || '';
    const user_email = osUserFrom(req);
    const ts = new Date().toISOString();
    const aid = b.agent_id || '';

    if (event === 'SubagentStart') {
      logDecision({ timestamp: ts, session_id, user_email, tool: 'SubagentStart', server: CODING_AGENT, sensitivity: 'medium', effect: 'Permit', reason: `Subagent started: ${b.agent_type || ''}#${String(aid).slice(0, 8)}`, intent: 'delegate', agent_type: 'subagent' });
    } else if (event === 'SubagentStop') {
      logDecision({ timestamp: ts, session_id, user_email, tool: 'SubagentStop', server: CODING_AGENT, sensitivity: 'medium', effect: 'Permit', reason: `Subagent stopped: ${b.agent_type || ''}#${String(aid).slice(0, 8)}`, intent: 'delegate', agent_type: 'subagent' });
    }
    return res.json({});
  } catch (e: any) { console.error('[CODEX:hook]', e.message); return res.json({}); }
});

export default router;
