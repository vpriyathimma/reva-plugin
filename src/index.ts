import express     from 'express';
import cors        from 'cors';
import path        from 'path';
import dotenv      from 'dotenv';
import session     from 'express-session';

dotenv.config();

import { authorize }             from './connector/oauth/authorize';
import { callback }              from './connector/oauth/callback';
import { parseDiscoveryPayload, parseDesktopConfig } from './connector/discovery/configReader';
import { scanAllServers }        from './connector/discovery/toolScanner';
import { classifyTools }         from './connector/discovery/classifier';
import { enrollSession }         from './connector/discovery/enroll';
import { verifyConnectorToken }  from './connector/oauth/token';
import inventoryRouter           from './api/inventory';
import pdpRouter                 from './api/pdp';
import testIdjagRouter           from './api/testIdjag';
import oauthDiscoveryRouter      from './mcp/oauthDiscovery';
import mcpServerRouter           from './mcp/mcpServer';

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret:            process.env.JWT_SIGNING_SECRET || 'reva-session-secret',
  resave:            false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 3600000 },
}));

// ── Request logger ────────────────────────────────────────────────
app.use((req, _res, next) => {
  console.log(`[REQ] ${req.method} ${req.path}`);
  next();
});

// ── MCP OAuth discovery ───────────────────────────────────────────
app.use(oauthDiscoveryRouter);

// ── MCP server ────────────────────────────────────────────────────
app.use(mcpServerRouter);

// ── OAuth ─────────────────────────────────────────────────────────
app.get('/oauth/authorize', authorize);
app.get('/oauth/callback',  callback);

// ── Discovery ─────────────────────────────────────────────────────
app.post('/api/discover', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');
    const user  = verifyConnectorToken(token);

    if (!user) return res.status(401).json({ error: 'Invalid or expired connector token' });

    let servers;
    if (req.body.mcpServers) {
      servers = parseDesktopConfig(req.body);
    } else {
      const payload = parseDiscoveryPayload(req.body);
      servers = payload.servers;
    }

    const session_id = req.body.session_id || `session-${Date.now()}`;
    const rawTools   = await scanAllServers(servers);
    const tools      = classifyTools(rawTools);
    const enrolled   = enrollSession(session_id, user.email, tools);

    return res.json({
      status:       'enrolled',
      session_id:   enrolled.session_id,
      user:         user.email,
      server_count: enrolled.server_count,
      tool_count:   enrolled.tool_count,
      locked:       enrolled.locked,
      tools: tools.map(t => ({
        server:             t.server_name,
        tool:               t.tool_name,
        type:               t.server_type,
        sensitivity:        t.sensitivity,
        sensitivity_reason: t.sensitivity_reason,
      })),
    });
  } catch (err: any) {
    console.error('Discovery error:', err.message);
    return res.status(400).json({ error: err.message });
  }
});

// ── API ───────────────────────────────────────────────────────────
app.use('/api', inventoryRouter);
app.use('/api', pdpRouter);
app.use('/api', testIdjagRouter);

// ── Codex governance router (additive — reuses the same PDP engine; /api/codex/*) ──
import codexPdpRouter from './api/codexPdp';
app.use('/api', codexPdpRouter);

// ── Kiro governance router (additive — reuses the same PDP engine; /api/kiro/*) ──
import kiroPdpRouter from './api/kiroPdp';
app.use('/api', kiroPdpRouter);

// HITL routes
import { hitlRouter } from './api/hitlConfig';
app.use('/api', hitlRouter);

// Generic hook handler — all 26 Claude Code lifecycle hooks
import { logDecision } from './connector/discovery/enroll';
import { recordBlock, classifyPrompt, getPersistentTrust } from './api/intentClassifier';
import { bindSpawnToAgent, extractAgentId, displayName, resolveSubagent } from './connector/hooks/beforeToolCall';
import { evaluateCedar, buildClaudeCodeInjectionPayload, cedarFields } from './api/pdpEvaluate';
import { getPIPContext } from './api/pip';
import { sessionIntentStore } from './connector/hooks/beforePrompt';
import { claudeSessionUserStore } from './connector/hooks/onSessionStart';

// Dedupe file-content injection scans — one block per (session, file-set) so
// repeated PostToolBatch posts don't crater trust for the same payload.
const scannedFileInjections = new Set<string>();

// Cumulative set of files where injection/jailbreak content was found, per session.
// Drives the quarantine "Clipped Reason" so it names EVERY flagged file
// (docs/setup.md, docs/CONTRIBUTING.md, …) instead of a coarse directory token.
const injectedFilesBySession = new Map<string, Set<string>>();

// Reva must detect injected content regardless of HOW an agent ingested it, and
// must attribute it to the SPECIFIC files — not the directory it searched.
//   Read        → tool_input.file_path
//   Grep/Glob   → per-file paths live INSIDE the output ("docs/setup.md:12:…")
//   Bash reads  → grep -r/cat/head/… aggregate output whose paths are in content
// Earlier this took the first absolute-path token (the directory for `grep -r`),
// which is why the reason showed the project folder, not setup.md/CONTRIBUTING.md.
const FILE_READ_CMD = /\b(cat|head|tail|less|more|nl|strings|cut|sed|grep|egrep|fgrep|rg|awk|od|xxd|find)\b|\bgit\s+(show|diff|log)\b/;

// Pull file paths out of aggregated read output (grep prefixes, head/tail headers,
// bare path lines from glob / grep -l / find).
function filesFromContent(content: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (p: string) => { const v = (p || '').trim(); if (v && !seen.has(v)) { seen.add(v); out.push(v); } };
  for (const raw of content.split('\n')) {
    const ln = raw.trim();
    if (!ln) continue;
    let m = ln.match(/^==>\s+(.+?)\s+<==$/);                 // head/tail: ==> path <==
    if (m) { push(m[1]); continue; }
    m = ln.match(/^([^\s:][^:]*?):(?:\d+:)?/);               // grep: path:line:… | path:…
    if (m && (m[1].includes('/') || /\.[A-Za-z0-9]{1,8}$/.test(m[1]))) { push(m[1]); continue; }
    if (ln.length < 240 && /^[~./]?[\w./@+-]+\.[A-Za-z0-9]{1,8}$/.test(ln)) push(ln); // bare path
  }
  return out;
}

// Path-like tokens from a shell command (the files being read), flags excluded.
function pathsFromCommand(cmd: string): string[] {
  const toks = cmd.match(/(?:\/|\.{1,2}\/|[\w.@+-]+\/)[^\s"'|>;&]*|\b[\w.@+-]+\.[A-Za-z0-9]{1,8}\b/g) || [];
  return toks.filter((t) => !t.startsWith('-'));
}

function extractIngestedContent(c: any): { content: string; files: string[] } | null {
  const tool = c?.tool_name || '';
  const resp = typeof c?.tool_response === 'string' ? c.tool_response : '';
  if (!resp) return null;
  if (/^read/i.test(tool)) {
    const fp = c?.tool_input?.file_path || c?.tool_input?.path || '';
    return { content: resp, files: fp ? [fp] : [] };
  }
  if (/^(grep|glob)$/i.test(tool)) {
    const fromContent = filesFromContent(resp);
    const hint = c?.tool_input?.path || c?.tool_input?.glob || c?.tool_input?.pattern || '';
    return { content: resp, files: fromContent.length ? fromContent : (hint ? [hint] : []) };
  }
  if (/^bash$/i.test(tool)) {
    const cmd = typeof c?.tool_input?.command === 'string' ? c.tool_input.command : '';
    if (!cmd || !FILE_READ_CMD.test(cmd)) return null;
    const fromContent = filesFromContent(resp);
    return { content: resp, files: fromContent.length ? fromContent : pathsFromCommand(cmd) };
  }
  return null;
}

// Human-readable path: project-relative when under cwd, else trailing segments
// (handles worktree copies and absolute paths).
function relFile(cwd: string, p: string): string {
  if (!p) return p;
  const f = p.trim();
  if (cwd && f.startsWith(cwd + '/')) return f.slice(cwd.length + 1);
  if (f.startsWith('/')) return f.split('/').filter(Boolean).slice(-2).join('/');
  return f.replace(/^\.\//, '');
}
app.post('/api/pdp/hook', async (req, res) => {
  const event = req.body?.hook_event_name || 'unknown';
  const session_id = req.body?.session_id || '';
  const user_email = req.body?.env?.USER || claudeSessionUserStore.get(session_id) || (req.headers['x-os-user'] as string) || '';
  const ts = new Date().toISOString();

  // Full body — no truncation (per-agent id / lifecycle payload investigation)
  console.log(`[HOOK:${event}] session=${session_id} user=${user_email} data=${JSON.stringify(req.body)}`);

  // PostToolBatch — scan content an agent READ for prompt injection. The payload
  // lives in file content, not the user prompt, so it never reaches SubmitPrompt.
  // Here we run the same injection classifier over every file-read tool_response —
  // Read tool OR Bash read (cat/grep/head/…) — on a hit we record a prompt_injection
  // block (trust −15) and log a Cedar SubmitPrompt decision, identical to
  // UserPromptSubmit. This fires whether or not Claude acts on the payload, so an
  // injection Claude refuses still lands in the decisions feed.
  if (event === 'PostToolBatch') {
    if (!require('./api/securityConfig').isEnabled('prompt_injection')) {
      // Prompt Injection toggle OFF — do not scan ingested content or attribute
      // any injection. Claude Code still blocks injections on its own.
      return res.json({});
    }
    const calls = Array.isArray(req.body?.tool_calls) ? req.body.tool_calls : [];
    // Resolve WHO read the files in this batch — Claude Code stamps the subagent's
    // agent_id/agent_type on the batch body (absent for the main agent). Drives the
    // injection principal + decision-log Principal cell: subagent → Agent::os:id,
    // main → Developer::os. Built inline (no spawn-queue side effects in the hook path).
    const batchAgentId   = req.body?.agent_id || '';
    const batchAgentKind = batchAgentId ? 'subagent' : 'main';
    const batchAgentName = batchAgentId
      ? `${req.body?.agent_type || 'subagent'}#${String(batchAgentId).slice(0, 8)}`
      : (req.body?.agent_type || 'claude-code');
    // What the reader was asked to do + its PIP, so the injection decision carries
    // the same context as a RunBash decision (identity, scope, git/jira, zone).
    const batchPip      = getPIPContext(user_email);
    const batchSub      = batchAgentId ? resolveSubagent(session_id, batchAgentId) : undefined;
    const batchSI       = sessionIntentStore.get(session_id);
    const batchDeclared = batchSub?.declared_scope || batchSI?.prompt || '';
    const batchInitial  = batchSub?.initial_scope  || batchSI?.initial_scope || batchSI?.prompt || '';
    const cwd = req.body?.cwd || '';
    for (const c of calls) {
      const ingested = extractIngestedContent(c);
      if (!ingested) continue;
      const { content, files: rawFiles } = ingested;
      // Specific, project-relative files this read touched (deduped, readable).
      const relFiles = Array.from(new Set(rawFiles.map((f) => relFile(cwd, f)).filter(Boolean)));
      const fpLabel = relFiles[0] || relFile(cwd, cwd) || 'ingested content';
      const dedupeKey = `${session_id}::${relFiles.join('|') || content.length}`;
      if (scannedFileInjections.has(dedupeKey)) continue;

      const result = classifyPrompt(content, session_id, user_email);
      const isInjection = result.scores.injection_score > 50;
      const isJailbreak = result.scores.jailbreak_score > 50;
      if (!isInjection && !isJailbreak) continue;

      scannedFileInjections.add(dedupeKey);
      const detection = isInjection ? 'prompt_injection' : 'jailbreak_attempt';

      // Accumulate ALL flagged files for this session, then build a comma-joined,
      // capped list so the quarantine reason names every file (matching what the
      // agent surfaces in-terminal) instead of a coarse directory.
      const fileSet = injectedFilesBySession.get(session_id) || new Set<string>();
      (relFiles.length ? relFiles : [fpLabel]).forEach((f) => fileSet.add(f));
      injectedFilesBySession.set(session_id, fileSet);
      const allFiles = Array.from(fileSet).sort();
      const fileList = allFiles.length > 5
        ? `${allFiles.slice(0, 5).join(', ')}, +${allFiles.length - 5} more`
        : allFiles.join(', ');
      const reasonText = `${detection} detected in ${fileList || fpLabel}`;

      recordBlock(user_email, {
        type: detection,
        prompt: `read:${fpLabel} — ${content.slice(0, 160)}`.slice(0, 200),
        score: isInjection ? result.scores.injection_score : result.scores.jailbreak_score,
        timestamp: ts,
      });

      // Quarantine on detected injection (AAI-UAP-001), gated by the master
      // switch — re-clipping with the cumulative list updates the record so the
      // dashboard shows every flagged file, not just the last one scanned.
      try {
        if (require('./api/securityConfig').isEnabled('quarantine_access')) {
          const ca = require('./connector/discovery/enroll').sessionStore.get(session_id)?.coding_agent || 'claude-code';
          require('./api/quarantine').clip({ osUser: user_email, codingAgent: ca, sessionId: session_id, policyId: 'AAI-UAP-001', reason: reasonText });
        }
      } catch (e) { /* never break the scan */ }

      let cedarResult; let injPayload: any;
      try {
        injPayload = buildClaudeCodeInjectionPayload({
          osUser:        user_email,
          projectName:   (req.body?.cwd || '').split('/').pop() || 'unknown',
          sessionId:     session_id,
          prompt:        content.slice(0, 500),
          promptHistory: [],
          isInjection,
          isJailbreak,
          scores:        result.scores,
          trustScore:    getPersistentTrust(user_email),
          agentType:       batchAgentKind,
          agentId:         batchAgentId,
          agentName:       batchAgentName,
          parentSessionId: session_id,
          declaredScope:   batchDeclared,
          initialScope:    batchInitial,
          sourcePath:      fpLabel,
          pipCtx:          batchPip,
        });
        cedarResult = await evaluateCedar(injPayload);
      } catch (e: any) {
        console.error('[FileInjection:Cedar] SubmitPrompt eval failed:', e.message);
      }

      logDecision({
        timestamp:    ts,
        session_id,
        user_email,
        tool:         'prompt',
        server:       'claude-code',
        sensitivity:  result.sensitivity,
        effect:       cedarResult && cedarResult.decision === 'allow' ? 'Permit' : 'Deny',
        reason:       (cedarResult && cedarResult.policy_name) || reasonText,
        intent:       'prompt_injection_in_read',
        trust_score:  getPersistentTrust(user_email),
        scores:       result.scores,
        prompt:       content.slice(0, 200),
        agent_type:   batchAgentKind,
        ...cedarFields(injPayload || {}),
      });
      console.log(`[FileInjection] ${detection} in ${fileList || fpLabel} session=${session_id} score=${result.scores.injection_score} decision=${cedarResult?.decision ?? 'error'} trust=${getPersistentTrust(user_email)}`);
    }
  }

  // PermissionDenied — Claude blocked something, record for trust degradation
  if (event === 'PermissionDenied') {
    const tool = req.body?.tool_name || '';
    const reason = req.body?.reason || 'Claude auto-mode denied';
    if (user_email) {
      recordBlock(user_email, { type: 'prompt_injection', prompt: `Claude blocked: ${tool} — ${reason}`.slice(0, 200), score: 60, timestamp: ts });
    }
    logDecision({ timestamp: ts, session_id, user_email, tool: `PermissionDenied:${tool}`, server: 'claude-code', sensitivity: 'critical', effect: 'Deny', reason: `Claude blocked: ${reason}`.slice(0, 300), intent: 'blocked_by_claude', agent_type: 'main' });
  }

  // ConfigChange — alert on config tampering
  if (event === 'ConfigChange') {
    const path = req.body?.path || '';
    logDecision({ timestamp: ts, session_id, user_email, tool: 'ConfigChange', server: 'claude-code', sensitivity: 'critical', effect: 'Deny', reason: `Config modified: ${path}`, intent: 'config_change' });
  }

  // SubagentStart — the runtime now reveals the per-instance agent_id. Join it to
  // the oldest queued spawn so the subagent's name + scope are attributable on every
  // subsequent tool call. agent_type is empty on this payload (confirmed via logs),
  // so the name comes from the spawn join, not the hook.
  if (event === 'SubagentStart') {
    const agent_id = extractAgentId(req.body);
    const bound = bindSpawnToAgent(session_id, agent_id);
    logDecision({ timestamp: ts, session_id, user_email, tool: 'SubagentStart', server: 'claude-code', sensitivity: 'medium', effect: 'Permit', reason: `Subagent started: ${bound ? displayName(bound) : agent_id || 'unknown'}`.slice(0, 200), intent: 'delegate', agent_type: 'subagent' });
  }

  // SubagentStop / TaskCompleted — lifecycle close. agent_id is present here too;
  // bind defensively in case SubagentStart was missed, then record.
  if (event === 'SubagentStop' || event === 'TaskCompleted') {
    const agent_id = extractAgentId(req.body);
    const bound = agent_id ? bindSpawnToAgent(session_id, agent_id) : undefined;
    logDecision({ timestamp: ts, session_id, user_email, tool: event, server: 'claude-code', sensitivity: 'medium', effect: 'Permit', reason: `${event}: ${bound ? displayName(bound) : agent_id || ''}`.slice(0, 200), intent: 'delegate', agent_type: 'subagent' });
  }

  // TaskCreated — task fan-out (not a subagent spawn); log only.
  if (event === 'TaskCreated') {
    const task = req.body?.task || req.body?.description || req.body?.prompt || '';
    logDecision({ timestamp: ts, session_id, user_email, tool: event, server: 'claude-code', sensitivity: 'medium', effect: 'Permit', reason: `${event}: ${task}`.slice(0, 200), intent: 'delegate', agent_type: 'subagent' });
  }

  // FileChanged — flag sensitive file modifications
  if (event === 'FileChanged') {
    const path = req.body?.path || '';
    logDecision({ timestamp: ts, session_id, user_email, tool: 'FileChanged', server: 'claude-code', sensitivity: 'high', effect: 'Permit', reason: `Sensitive file modified: ${path}`, intent: 'file_change' });
  }

  // PostToolUseFailure — log failures
  if (event === 'PostToolUseFailure') {
    const tool = req.body?.tool_name || '';
    const error = req.body?.error || req.body?.tool_error || '';
    logDecision({ timestamp: ts, session_id, user_email, tool: `Failed:${tool}`, server: 'claude-code', sensitivity: 'medium', effect: 'Deny', reason: `Tool failed: ${error}`.slice(0, 200), intent: 'error' });
  }

  // InstructionsLoaded — log what instructions Claude loaded
  if (event === 'InstructionsLoaded') {
    const file = req.body?.path || req.body?.file || '';
    logDecision({ timestamp: ts, session_id, user_email, tool: 'InstructionsLoaded', server: 'claude-code', sensitivity: 'medium', effect: 'Permit', reason: `Instructions loaded: ${file}`, intent: 'instructions' });
  }

  res.json({});
});

// Session control routes
import { sessionControlRouter } from './api/sessionControl';
app.use('/api', sessionControlRouter);

// Security feature flags (Settings toggles), quarantine (AAI), live stream + trust
import { securityConfigRouter } from './api/securityConfig';
import { quarantineRouter }     from './api/quarantine';
import { streamRouter }         from './api/stream';
import { ruleConfigRouter }     from './api/ruleConfig';
import { approverConfigRouter } from './api/approverConfig';
import { policySetsRouter } from './api/policySets';
app.use('/api', securityConfigRouter);
app.use('/api', quarantineRouter);
app.use('/api', streamRouter);
app.use('/api', ruleConfigRouter);
app.use('/api', approverConfigRouter);
app.use('/api', policySetsRouter);

// Insights API — standalone, read-only surface for the internal product team.
// Routes: /api/insights/*, /api/identities/:id/*, /api/intent-profile
import { insightsRouter } from './api/insights';
app.use('/api', insightsRouter);

// Adaptive Access Isolation (AAI) API — Home page policy board.
// Routes: /api/aai/policies, /api/aai/policies/:policyId
import { aaiRouter } from './api/aai';
app.use('/api', aaiRouter);

// Ask Reva AI — Bedrock-backed threat-hunting assistant. Route: POST /api/ask
import { askRouter } from './api/ask';
app.use('/api', askRouter);

// Classification config routes
import { getCommandRules, setCommandRules, getFileZoneRules, setFileZoneRules } from './api/pdpEvaluate';
import { getAllBlocks } from './api/intentClassifier';
app.get('/api/config/commands', (_req, res) => res.json({ rules: getCommandRules() }));
app.post('/api/config/commands', (req, res) => { setCommandRules(req.body.rules || []); res.json({ ok: true }); });
app.get('/api/config/filezones', (_req, res) => res.json({ rules: getFileZoneRules() }));
app.post('/api/config/filezones', (req, res) => { setFileZoneRules(req.body.rules || []); res.json({ ok: true }); });
app.get('/api/blocks', (_req, res) => {
  const allBlocks = getAllBlocks();
  const result: Record<string, any[]> = {};
  for (const [sid, blocks] of allBlocks) { result[sid] = blocks; }
  res.json({ blocks: result });
});

// Raw SVID list — short-lived credentials (JIT). Powers the dashboard's JIT tile
// and is also consumable directly. Includes active, expired, and revoked.
import { listAllSVIDs } from './api/svid';
app.get('/api/svid', (_req, res) => {
  res.json({ svids: listAllSVIDs() });
});

// ── Health ────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'reva-plugin', timestamp: new Date().toISOString() });
});

// ── Dashboard (React) — must be LAST ─────────────────────────────
const dashboardPath = path.join(__dirname, '../dashboard/dist');
app.use(express.static(dashboardPath));
app.get('*', (req, res) => {
  if (req.path === '/' || req.path.startsWith('/mcp') || req.path.startsWith('/.well-known') || req.path.startsWith('/oauth')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(path.join(dashboardPath, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Reva plugin running on port ${PORT}`);
});

export default app;
