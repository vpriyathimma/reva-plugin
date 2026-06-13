// ──────────────────────────────────────────────────────────────────────────
// Kiro governance router  —  mounted at /api/kiro/*
//
// ADDITIVE ONLY. Every Cedar evaluation, decision-log write, PIP enrichment,
// trust/injection classifier, and session enrollment is REUSED VERBATIM from
// the existing modules. The Claude Code path (/api/pdp/*) and the Codex path
// (/api/codex/*) are never touched.
//
// What is Kiro-specific and lives only here:
//   • input parsing for Kiro's STDIN hook payloads (different field shapes)
//   • mapKiroToolToAction() (Kiro tool vocabulary: fs_write, execute_bash, …)
//   • coding_agent='kiro' + surface stamped into every Cedar context + session
//   • Kiro identity from `kiro-cli whoami --format json` (accountType, email,
//     region, startUrl, profileArn) — all stored for insights page
//   • response contract: { decision:'allow'|'deny', reason?:string }
//     (gate.py translates to exit 0 / exit 2 + STDERR)
//
// Endpoints (all POST):
//   /kiro/session   ← agentSpawn   (identity from kiro-cli whoami, sent by session.py)
//   /kiro/prompt    ← userPromptSubmit
//   /kiro/evaluate  ← preToolUse — the enforcement gate
//   /kiro/posttool  ← postToolUse  (Bash-read injection scan)
//   /kiro/hook      ← stop / telemetry
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
import { logDecision, enrollSession, sessionStore } from '../connector/discovery/enroll';
import { getPIPContext, enrichSession as enrichPIP } from './pip';
import { classifyPrompt, recordBlock, getPersistentTrust, checkIntentDrift } from './intentClassifier';
import { resolveSession } from './sessionResolver';
import { isEnabled } from './securityConfig';
import { mapKiroToolToAction, extractKiroTarget, isBashAction, CODING_AGENT } from '../connector/kiro/adapter';
import { isQuarantined } from './quarantine';
import { isSessionTerminated } from './sessionControl';

const router = Router();

// session_id → os_user, so preToolUse/postToolUse can resolve identity
const kiroSessionUser = new Map<string, string>();
// session_id → { surface } for tagging subsequent events
const kiroSessionSurface = new Map<string, string>();
// session_id → { declared, initial } prompt scope — threaded into tool-call
// Cedar context (declared_scope/initial_scope) so the dashboard renders the
// Intent Profile button on Kiro tool decisions, same as Claude Code / Codex.
const kiroSessionScope = new Map<string, { declared: string; initial: string }>();
function recordScope(session_id: string, prompt: string) {
  if (!session_id || !prompt) return;
  const cur = kiroSessionScope.get(session_id);
  kiroSessionScope.set(session_id, { declared: prompt, initial: cur?.initial || prompt });
}

function osUserFrom(req: Request): string {
  return (req.body?.os_user as string)
    || (req.headers['x-os-user'] as string)
    || kiroSessionUser.get(req.body?.session_id || '')
    || process.env.USER
    || 'unknown';
}

// ── agentSpawn (SessionStart) ──────────────────────────────────────────────
// session.py runs `kiro-cli whoami --format json` and sends the full Kiro
// identity (accountType, email, region, startUrl, profileArn) + git/cwd/model.
router.post('/kiro/session', async (req, res) => {
  try {
    const b = req.body || {};
    const session_id = b.session_id || `kiro-${Date.now()}`;
    const cwd        = b.cwd || '';
    const os_user    = b.os_user || process.env.USER || 'unknown';
    const project    = cwd.split('/').pop() || '';
    const surface    = b.surface || 'kiro_cli';   // kiro_cli | kiro_ide
    const ki         = b.kiro_identity || {};      // { accountType, email, region, startUrl, profileArn }

    kiroSessionUser.set(session_id, os_user);
    kiroSessionSurface.set(session_id, surface);
    getOrCreateSessionTrace(session_id);

    // Identity gate — reuse the same resolver as Claude / Codex
    const oauthEmail = ki.email || undefined;
    const { allowed, identity, reason } = resolveSession(os_user, cwd, oauthEmail);
    if (!allowed) {
      console.warn(`[KIRO:SessionStart] DENIED — ${reason}`);
      return res.json({ decision: 'block', reason });
    }

    // Enroll into the SAME sessionStore the dashboard reads. Kiro identity is
    // mapped onto the existing identity fields + kiro-specific extras so the
    // Identities panel renders all Kiro fields in developer details.
    enrollSession(session_id, os_user, [], {
      os_type:          b.os_type || undefined,
      hostname:         b.hostname || undefined,
      model:            b.model || undefined,
      project_name:     project || undefined,
      oauth_email:      ki.email || undefined,
      developer_name:   ki.email || b.git_name || undefined,
      account_uuid:     ki.accountType || undefined,        // "BuilderId" | "IdentityCenter" | "Social" — rendered as "Auth Method"
      org_uuid:         ki.startUrl || undefined,            // Identity Center start URL
      git_email:        b.git_email || undefined,
      git_name:         b.git_name || undefined,
      git_branch:       b.git_branch || undefined,
      git_remote_url:   b.git_remote_url || undefined,
      jira_ticket_id:   b.jira_ticket_id || undefined,
      connection_type:  b.connection_type || 'local',
      coding_agent:     CODING_AGENT,
      surface,
      // Kiro-specific extras — stored in the session for the insights page
      kiro_account_type:  ki.accountType || undefined,
      kiro_email:         ki.email || undefined,
      kiro_region:        ki.region || undefined,
      kiro_start_url:     ki.startUrl || undefined,
      kiro_profile_arn:   ki.profileArn || undefined,
    } as any);

    // Force kiro_* fields directly onto the session object — bypasses any stale
    // compiled enroll.js that may not assign them during session construction.
    const sess = sessionStore.get(session_id);
    if (sess) {
      sess.kiro_account_type = ki.accountType || undefined;
      sess.kiro_email        = ki.email || undefined;
      sess.kiro_region       = ki.region || undefined;
      sess.kiro_start_url    = ki.startUrl || undefined;
      sess.kiro_profile_arn  = ki.profileArn || undefined;
    }

    // PIP enrichment — identical to Claude / Codex path
    try {
      await enrichPIP(os_user, b.jira_ticket_id || '', b.git_remote_url || '', b.git_branch || '', {
        oauth_email: ki.email || undefined,
        connection_type: b.connection_type || 'local',
        git_email: b.git_email || undefined,
        git_name:  b.git_name || undefined,
      });
    } catch (e: any) { console.warn(`[KIRO:PIP] ${e.message}`); }

    console.log(`[KIRO:SessionStart] session=${session_id} os_user=${os_user} email=${ki.email || 'none'} accountType=${ki.accountType || 'none'} region=${ki.region || 'none'} surface=${surface} model=${b.model || 'none'} project=${project}`);

    return res.json({});
  } catch (e: any) {
    console.error('[KIRO:SessionStart] error:', e.message);
    return res.json({});   // fail-open on enrichment
  }
});

// ── userPromptSubmit ────────────────────────────────────────────────────────
router.post('/kiro/prompt', async (req, res) => {
  try {
    const b = req.body || {};
    const session_id = b.session_id || '';
    const user_email = osUserFrom(req);
    const prompt     = String(b.prompt || b.user_prompt || '');
    const surface    = kiroSessionSurface.get(session_id) || b.surface || 'kiro_cli';
    const ts = new Date().toISOString();

    if (!isEnabled('prompt_injection')) { recordScope(session_id, prompt); return res.json({}); }

    const result      = classifyPrompt(prompt, session_id, user_email);
    const isInjection = result.scores.injection_score > 50;
    const isJailbreak = result.scores.jailbreak_score > 50;
    const trust       = getPersistentTrust(user_email);

    recordScope(session_id, prompt);

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
      catch (e: any) { console.error('[KIRO:prompt] cedar', e.message); }

      logDecision({
        timestamp: ts, session_id, user_email, tool: 'prompt', server: CODING_AGENT,
        sensitivity: result.sensitivity, effect: decision === 'allow' ? 'Permit' : 'Deny',
        reason: policy || detection, intent: result.intent || detection,
        trust_score: trust, scores: result.scores, prompt: prompt.slice(0, 200), agent_type: 'main',
        ...cedarFields(payload),
      });
      console.log(`[KIRO:prompt] ${detection} session=${session_id} inj=${result.scores.injection_score} jb=${result.scores.jailbreak_score} decision=${decision}`);
    } else {
      logDecision({
        timestamp: ts, session_id, user_email, tool: 'prompt', server: CODING_AGENT,
        sensitivity: result.sensitivity, effect: 'Permit',
        reason: 'Prompt classified — enforcement deferred to tool call',
        intent: result.intent || 'prompt', trust_score: trust, scores: result.scores,
        prompt: prompt.slice(0, 200), agent_type: 'main',
      });
    }

    // Never block at prompt time — same as Claude Code / Codex.
    return res.json({});
  } catch (e: any) {
    console.error('[KIRO:prompt] error:', e.message);
    return res.json({});
  }
});

// ── preToolUse — the enforcement gate ──────────────────────────────────────
// Kiro contract: gate.py sends { tool_name, tool_input, session_id, cwd, … }
// and expects back { decision:'allow' } or { decision:'deny', reason:'…' }.
// gate.py translates to exit 0 or exit 2 (STDERR = reason).
router.post('/kiro/evaluate', async (req, res) => {
  try {
    const b = req.body || {};
    const session_id = b.session_id || '';
    const user_email = osUserFrom(req);
    const cwd        = b.cwd || '';
    const project    = cwd.split('/').pop() || 'unknown';
    const surface    = kiroSessionSurface.get(session_id) || b.surface || 'kiro_cli';
    const toolName   = b.tool_name || '';
    const toolInput  = b.tool_input || {};
    const agentType  = b.agent_id ? 'subagent' : 'main';
    const ts = new Date().toISOString();

    // ── Terminate / Quarantine — session-scoped (terminate) and Kiro-agent-scoped
    // (quarantine). A Claude Code or Codex quarantine never lands here. ──
    const denyKiro = (reason: string) => {
      logDecision({
        timestamp: ts, session_id, user_email, tool: toolName || 'tool',
        server: CODING_AGENT, sensitivity: 'high', effect: 'Deny', reason, agent_type: agentType,
      });
      return res.json({ decision: 'deny', reason });
    };
    if (isSessionTerminated(session_id)) {
      return denyKiro('This session has been terminated by an administrator. Please exit and start a new session to continue.');
    }
    if (isEnabled('quarantine_access')) {
      const qRec = isQuarantined(user_email, CODING_AGENT);
      if (qRec) {
        console.log(`[KIRO:quarantine] tool blocked: ${user_email} via ${qRec.policyId}`);
        return denyKiro(qRec.message);
      }
    }

    const tgt    = extractKiroTarget(toolName, toolInput);
    let   action = mapKiroToolToAction(toolName);
    // fs_write granularity: create → WriteFile.
    if (action === 'EditFile' && tgt.operation === 'add') action = 'WriteFile';
    const pipCtx = getPIPContext(user_email);
    const trust  = getPersistentTrust(user_email);
    const scope  = kiroSessionScope.get(session_id) || { declared: '', initial: '' };

    console.log(`[KIRO:tool] raw=${toolName} action=${action} op=${tgt.operation || '-'} cmd=${(tgt.command || '').slice(0,80)} file=${tgt.filePath} mcp=${tgt.serverName}/${tgt.mcpTool} agent=${agentType}`);

    const isMCP = action === 'MCPRead' || action === 'MCPWrite' || action === 'MCPExecute';

    // Intent drift — identical model to Claude / Codex
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
      if (drift.reduces_trust) {
        const blk = { type: 'intent_drift' as const, prompt: driftTarget.slice(0, 200), score: drift.intent_drift_score, timestamp: new Date().toISOString() };
        recordBlock(user_email, blk);
        if (b.agent_id && agentType === 'subagent') recordBlock(`${user_email}:${b.agent_id}`, blk);
      }
      console.log(`[KIRO:drift] agent=${agentType} score=${drift.intent_drift_score} asked="${(scope.declared || scope.initial).slice(0,50)}" target="${driftTarget.slice(0,60)}"`);
    }

    // Normalize Kiro tool names to Claude Code vocabulary so buildFileOperationPayload's
    // internal mapToolToAction() produces the correct Cedar action.
    // Kiro sends: shell/read/write/edit — Claude Code expects: bash/read/write/edit
    const normalizedToolName = isBashAction(action) ? 'bash'
      : action === 'WriteFile' ? 'write'
      : action === 'EditFile'  ? 'edit'
      : action === 'ReadFile'  ? 'read'
      : toolName;

    const payload = isMCP
      ? buildMCPToolPayload({
          osUser: user_email, projectName: project, toolName: tgt.mcpTool || toolName,
          serverName: tgt.serverName || 'mcp', agentType, sessionId: session_id,
          hitlAcknowledged: false, scores: { trust_score: trust }, pipCtx,
          agentId: b.agent_id || undefined, parentSessionId: session_id,
          declaredScope: scope.declared, initialScope: scope.initial,
        })
      : buildFileOperationPayload({
          osUser: user_email, projectName: project, toolName: normalizedToolName,
          filePath: tgt.filePath, command: isBashAction(action) ? tgt.command : undefined,
          agentType, sessionId: session_id, hitlAcknowledged: false,
          isIntentDrift: drift.is_intent_drift, intentDriftScore: drift.intent_drift_score,
          scores: { trust_score: trust }, pipCtx,
          agentId: b.agent_id || undefined, parentSessionId: session_id,
          declaredScope: scope.declared, initialScope: scope.initial,
        });

    // Stamp Kiro discriminators into Cedar context
    (payload as any).context.coding_agent = CODING_AGENT;
    (payload as any).context.surface = surface;

    let decision = 'allow', policy: string | undefined;
    try { const r = await evaluateCedar(payload); decision = r.decision; policy = r.policy_name; }
    catch (e: any) { console.error('[KIRO:evaluate] cedar', e.message); decision = 'allow'; }

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

    console.log(`[KIRO:evaluate] ${action} session=${session_id} decision=${decision} policy=${policy || '-'}`);

    // Kiro contract: gate.py reads { decision, reason } and translates
    // to exit 0 (allow) or exit 2 + STDERR (deny). Simple JSON response.
    if (permit) {
      return res.json({ decision: 'allow' });
    }
    return res.json({
      decision: 'deny',
      reason: `Reva Governance: ${policy || 'blocked by policy'}`,
    });
  } catch (e: any) {
    console.error('[KIRO:evaluate] error:', e.message);
    return res.json({ decision: 'allow' });   // fail open silently
  }
});

// ── postToolUse — scan Bash-read output for injected content ────────────────
router.post('/kiro/posttool', async (req, res) => {
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
      const srcTgt = extractKiroTarget(b.tool_name || '', b.tool_input || {});
      const sourcePath = srcTgt.filePath || '';
      recordBlock(user_email, { type: 'prompt_injection', prompt: out.slice(0, 200), score: result.scores.injection_score, timestamp: ts });

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
      catch (e: any) { console.error('[KIRO:posttool] cedar', e.message); }

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
      console.log(`[KIRO:posttool] injection→PDP session=${session_id} decision=${decision} policy=${policy || '-'} src=${sourcePath}`);
    }
    return res.json({});
  } catch (e: any) { console.error('[KIRO:posttool]', e.message); return res.json({}); }
});

// ── stop / telemetry ────────────────────────────────────────────────────────
router.post('/kiro/hook', async (req, res) => {
  try {
    const b = req.body || {};
    const event = b.hook_event_name || 'unknown';
    const session_id = b.session_id || '';
    const user_email = osUserFrom(req);
    const ts = new Date().toISOString();

    if (event === 'stop') {
      logDecision({ timestamp: ts, session_id, user_email, tool: 'SessionEnd', server: CODING_AGENT, sensitivity: 'low', effect: 'Permit', reason: 'Kiro session ended', intent: 'session_end', agent_type: 'main' });
      // Clean up session maps
      kiroSessionUser.delete(session_id);
      kiroSessionSurface.delete(session_id);
      kiroSessionScope.delete(session_id);
    }
    return res.json({});
  } catch (e: any) { console.error('[KIRO:hook]', e.message); return res.json({}); }
});

export default router;
