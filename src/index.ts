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

// Session control routes
import { sessionControlRouter } from './api/sessionControl';
app.use('/api', sessionControlRouter);

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
