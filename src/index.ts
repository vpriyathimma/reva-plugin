import express       from 'express';
import cors          from 'cors';
import dotenv        from 'dotenv';
import session       from 'express-session';

dotenv.config();

import { authorize }              from './connector/oauth/authorize';
import { callback }               from './connector/oauth/callback';
import { parseDiscoveryPayload }  from './connector/discovery/configReader';
import { scanAllServers }         from './connector/discovery/toolScanner';
import { classifyTools }          from './connector/discovery/classifier';
import { enrollSession }          from './connector/discovery/enroll';
import { verifyConnectorToken }   from './connector/oauth/token';
import inventoryRouter            from './api/inventory';

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret:            process.env.JWT_SIGNING_SECRET || 'reva-session-secret',
  resave:            false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 3600000 },
}));

// ── OAuth ─────────────────────────────────────────────────────────
app.get('/oauth/authorize', authorize);
app.get('/oauth/callback',  callback);

// ── Discovery — called by Cowork on session start ─────────────────
app.post('/api/discover', async (req, res) => {
  try {
    // Verify connector token
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');
    const user  = verifyConnectorToken(token);

    if (!user) {
      return res.status(401).json({ error: 'Invalid or expired connector token' });
    }

    const payload  = parseDiscoveryPayload(req.body);
    const rawTools = await scanAllServers(payload.servers);
    const tools    = classifyTools(rawTools);
    const session  = enrollSession(payload.session_id, user.email, tools);

    return res.json({
      status:       'enrolled',
      session_id:   session.session_id,
      user:         user.email,
      server_count: session.server_count,
      tool_count:   session.tool_count,
      locked:       session.locked,
      tools: tools.map(t => ({
        server:      t.server_name,
        tool:        t.tool_name,
        sensitivity: t.sensitivity,
      })),
    });

  } catch (err: any) {
    console.error('Discovery error:', err.message);
    return res.status(400).json({ error: err.message });
  }
});

// ── API routes ────────────────────────────────────────────────────
app.use('/api', inventoryRouter);

// ── Health ────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'reva-plugin', timestamp: new Date().toISOString() });
});

app.get('/', (_req, res) => {
  res.json({ service: 'reva-plugin', status: 'running', version: '1.0.0' });
});

app.listen(PORT, () => {
  console.log(`Reva plugin running on port ${PORT}`);
});

export default app;
