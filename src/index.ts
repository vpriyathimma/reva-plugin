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

// HITL routes
import { hitlRouter } from './api/hitlConfig';
app.use('/api', hitlRouter);

// Generic hook handler — all 26 Claude Code lifecycle hooks
import { logDecision } from './connector/discovery/enroll';
import { recordBlock } from './api/intentClassifier';
app.post('/api/pdp/hook', (req, res) => {
  const event = req.body?.hook_event_name || 'unknown';
  const session_id = req.body?.session_id || '';
  const user_email = req.body?.env?.USER || '';
  const ts = new Date().toISOString();

  // Full body — no truncation (per-agent id / lifecycle payload investigation)
  console.log(`[HOOK:${event}] session=${session_id} user=${user_email} data=${JSON.stringify(req.body)}`);

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

  // SubagentStart/Stop, TaskCreated/Completed — log sub-agent lifecycle
  if (event === 'SubagentStart' || event === 'TaskCreated') {
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
