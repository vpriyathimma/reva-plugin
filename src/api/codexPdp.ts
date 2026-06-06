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
  buildClaudeCodeInjectionPayload,
  buildFileOperationPayload,
  buildMCPToolPayload,
  getOrCreateSessionTrace,
  cedarFields,
} from './pdpEvaluate';
import { logDecision, enrollSession } from '../connector/discovery/enroll';
import { getPIPContext, enrichSession as enrichPIP } from './pip';
import { classifyPrompt, recordBlock, getPersistentTrust, checkIntentDrift } from './intentClassifier';
import { resolveSession } from './sessionResolver';
import { isEnabled } from './securityConfig';
import { mapCodexToolToAction, extractCodexTarget, isBashAction, CODING_AGENT } from '../connector/codex/adapter';

const router = Router();

// session_id → os_user, so PermissionRequest/PostToolUse can resolve identity
const codexSessionUser = new Map<string, string>();
// session_id → { surface } for tagging subsequent events
const codexSessionSurface = new Map<string, string>();
// session_id → { declared, initial } prompt scope — threaded into tool-call
// Cedar context (declared_scope/initial_scope) so the dashboard renders the
// Intent Profile button on Codex tool decisions, same as Claude Code.
const codexSessionScope = new Map<string, { declared: string; initial: string }>();
function recordScope(session_id: string, prompt: string) {
  if (!session_id || !prompt) return;
  const cur = codexSessionScope.get(session_id);
  codexSessionScope.set(session_id, { declared: prompt, initial: cur?.initial || prompt });
}

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

    // Return empty — no additionalContext. Keeps the hook invisible to the
    // developer in the Codex UI (governance is enforced silently at the tool gate).
    return res.json({});
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

    if (!isEnabled('prompt_injection')) { recordScope(session_id, prompt); return res.json({}); }   // toggle off → no scan

    const result      = classifyPrompt(prompt, session_id, user_email);
    const isInjection = result.scores.injection_score > 50;
    const isJailbreak = result.scores.jailbreak_score > 50;
    const trust       = getPersistentTrust(user_email);

    // Track the prompt as this session's declared scope (used by the tool gate
    // for intent-drift context + the Intent Profile button).
    recordScope(session_id, prompt);

    // Mirror Claude Code exactly:
    //  • Clean prompt  → NO Cedar call (SubmitPrompt has only forbid policies, so
    //    a clean prompt would default-deny). Log a classify-only Permit. Enforcement
    //    is deferred to the tool gate (PreToolUse/PermissionRequest).
    //  • Injection/JB  → record the block + route through Cedar so the deny is in the
    //    decision log, but the prompt is NEVER blocked here — effects are enforced at
    //    the tool gate via injection_score/trust in context.
    if (isInjection || isJailbreak) {
      const detection = isInjection ? 'prompt_injection' : 'jailbreak_attempt';
      recordBlock(user_email, { type: detection, prompt: prompt.slice(0, 200), score: isInjection ? result.scores.injection_score : result.scores.jailbreak_score, timestamp: ts });

      const payload = {
        principal: { type: 'Developer', id: user_email, properties: { os_user: user_email } },
        action:    { name: 'SubmitPrompt' },
        resource:  { type: 'Prompt', id: `${session_id.slice(0, 8)}-prompt`, properties: { session_id } },
        context: {
          access_state: 'Active', os_user: user_email, coding_agent: CODING_AGENT, surface,
          is_injection: isInjection, is_jailbreak: isJailbreak,
          injection_score: result.scores.injection_score ?? 0,
          jailbreak_score: result.scores.jailbreak_score ?? 0,
          trust_score: trust, prompt: prompt.slice(0, 500),
          declared_scope: prompt.slice(0, 500),
        },
        session_id,
      };
      let decision = 'allow', policy: string | undefined;
      try { const r = await evaluateCedar(payload); decision = r.decision; policy = r.policy_name; }
      catch (e: any) { console.error('[CODEX:prompt] cedar', e.message); }

      logDecision({
        timestamp: ts, session_id, user_email, tool: 'prompt', server: CODING_AGENT,
        sensitivity: result.sensitivity, effect: decision === 'allow' ? 'Permit' : 'Deny',
        reason: policy || detection, intent: result.intent || detection,
        trust_score: trust, scores: result.scores, prompt: prompt.slice(0, 200), agent_type: 'main',
        ...cedarFields(payload),
      });
      console.log(`[CODEX:prompt] ${detection} session=${session_id} inj=${result.scores.injection_score} jb=${result.scores.jailbreak_score} decision=${decision}`);
    } else {
      // Clean prompt — classify-only log, enforcement deferred to the tool gate.
      logDecision({
        timestamp: ts, session_id, user_email, tool: 'prompt', server: CODING_AGENT,
        sensitivity: result.sensitivity, effect: 'Permit',
        reason: 'Prompt classified — enforcement deferred to tool call',
        intent: result.intent || 'prompt', trust_score: trust, scores: result.scores,
        prompt: prompt.slice(0, 200), agent_type: 'main',
      });
    }

    // Never block at prompt time — same as Claude Code.
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

    const tgt    = extractCodexTarget(toolName, toolInput);
    let   action = mapCodexToolToAction(toolName);
    // apply_patch granularity: Add File → WriteFile (create), Update File → EditFile.
    if (action === 'EditFile' && tgt.operation === 'add') action = 'WriteFile';
    const pipCtx = getPIPContext(user_email);
    const trust  = getPersistentTrust(user_email);
    const scope  = codexSessionScope.get(session_id) || { declared: '', initial: '' };

    // Log raw tool_name + operation so the map can be tuned + deletes are visible.
    console.log(`[CODEX:tool] raw=${toolName} action=${action} op=${tgt.operation || '-'} cmd=${(tgt.command || '').slice(0,80)} file=${tgt.filePath} mcp=${tgt.serverName}/${tgt.mcpTool} agent=${agentType}`);

    const isMCP = action === 'MCPRead' || action === 'MCPWrite' || action === 'MCPExecute';

    // Intent drift — reuse the SAME model Claude uses (checkIntentDrift), translating
    // the Codex action into the classifier's tool vocabulary so mutate-vs-read is
    // judged identically (apply_patch→edit/write, shell→bash, reads→read). Gated by
    // the same 'intent_drift' toggle. Previously unwired, so is_intent_drift defaulted
    // to false and the PDP never saw Codex drift → out-of-scope reads were allowed.
    const driftTarget = isBashAction(action) ? (tgt.command || '') : (tgt.filePath || tgt.mcpTool || '');
    const driftTool   = isBashAction(action) ? 'bash'
                      : action === 'WriteFile' ? 'write'
                      : action === 'EditFile'  ? 'edit'
                      : action === 'ReadFile'  ? 'read'
                      : toolName;
    const drift = (isEnabled('intent_drift') && !isMCP)
      ? checkIntentDrift({ target: driftTarget, tool_name: driftTool, declared_scope: scope.declared, initial_scope: scope.initial })
      : { is_intent_drift: false, intent_drift_score: 0, reduces_trust: false };
    if (drift.is_intent_drift) {
      // Mirror Claude: drastic drift (mutate when only a read was asked) erodes trust;
      // scope drift (out-of-scope read) is contained by Cedar with no trust hit.
      if (drift.reduces_trust) {
        const blk = { type: 'intent_drift' as const, prompt: driftTarget.slice(0, 200), score: drift.intent_drift_score, timestamp: new Date().toISOString() };
        recordBlock(user_email, blk);
        if (b.agent_id && agentType === 'subagent') recordBlock(`${user_email}:${b.agent_id}`, blk);
      }
      console.log(`[CODEX:drift] agent=${agentType} score=${drift.intent_drift_score} asked="${(scope.declared || scope.initial).slice(0,50)}" target="${driftTarget.slice(0,60)}"`);
    }

    const payload = isMCP
      ? buildMCPToolPayload({
          osUser: user_email, projectName: project, toolName: tgt.mcpTool || toolName,
          serverName: tgt.serverName || 'mcp', agentType, sessionId: session_id,
          hitlAcknowledged: false, scores: { trust_score: trust }, pipCtx,
          agentId: b.agent_id || undefined, parentSessionId: session_id,
          declaredScope: scope.declared, initialScope: scope.initial,
        })
      : buildFileOperationPayload({
          osUser: user_email, projectName: project, toolName,
          filePath: tgt.filePath, command: isBashAction(action) ? tgt.command : undefined,
          agentType, sessionId: session_id, hitlAcknowledged: false,
          isIntentDrift: drift.is_intent_drift, intentDriftScore: drift.intent_drift_score,
          scores: { trust_score: trust }, pipCtx,
          agentId: b.agent_id || undefined, parentSessionId: session_id,
          declaredScope: scope.declared, initialScope: scope.initial,
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

    // Codex contract: ALLOW by emitting nothing (returning permissionDecision/
    // behavior "allow" is rejected as unsupported and surfaces a failed-hook
    // error to the developer). Only emit a decision to DENY. This also keeps the
    // hook invisible on the happy path.
    if (permit) {
      return res.json({});
    }
    if (eventName === 'PreToolUse') {
      return res.json({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: `Reva Governance: ${policy || 'blocked by policy'}`,
        },
      });
    }
    return res.json({
      hookSpecificOutput: {
        hookEventName: 'PermissionRequest',
        decision: { behavior: 'deny', reason: `Reva Governance: ${policy || 'blocked by policy'}` },
      },
    });
  } catch (e: any) {
    console.error('[CODEX:evaluate] error:', e.message);
    return res.json({});   // fail open silently — never emit an "allow" decision
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
      const isSub = !!b.agent_id;
      // Best-effort source file that carried the payload (e.g. the doc the agent read).
      const srcTgt = extractCodexTarget(b.tool_name || '', b.tool_input || {});
      const sourcePath = srcTgt.filePath || '';
      recordBlock(user_email, { type: 'prompt_injection', prompt: out.slice(0, 200), score: result.scores.injection_score, timestamp: ts });

      // Send to the PDP as a SubmitPrompt (is_injection) — same primitive Claude's
      // read-injection path uses — so it lands in AVP, not just the local feed.
      const payload = buildClaudeCodeInjectionPayload({
        osUser: user_email,
        projectName: b.project_name || b.cwd || '',
        sessionId: session_id,
        prompt: out,
        promptHistory: [],
        isInjection: result.scores.injection_score > 50,
        isJailbreak: result.scores.jailbreak_score > 50,
        scores: result.scores,
        trustScore: getPersistentTrust(user_email),
        pipCtx: getPIPContext(user_email),
        agentType: isSub ? 'subagent' : 'main',
        agentId: b.agent_id || '',
        agentName: isSub ? 'subagent' : 'main',
        parentSessionId: isSub ? (b.parent_session_id || session_id) : '',
        sourcePath,
      });
      (payload as any).context.coding_agent = CODING_AGENT;

      let decision = 'allow', policy: string | undefined;
      try { const r = await evaluateCedar(payload); decision = r.decision; policy = r.policy_name; }
      catch (e: any) { console.error('[CODEX:posttool] cedar', e.message); }

      logDecision({
        timestamp: ts, session_id, user_email,
        tool: 'SubmitPrompt', server: CODING_AGENT, sensitivity: result.sensitivity,
        effect: decision === 'allow' ? 'Permit' : 'Deny',
        reason: policy || 'prompt injection detected in tool output',
        intent: 'prompt_injection_in_read',
        trust_score: getPersistentTrust(user_email),
        scores: result.scores, agent_type: isSub ? 'subagent' : 'main',
        ...cedarFields(payload),
      });
      console.log(`[CODEX:posttool] injection→PDP session=${session_id} decision=${decision} policy=${policy || '-'} src=${sourcePath}`);
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
