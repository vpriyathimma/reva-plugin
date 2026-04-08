import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import session from 'express-session';

dotenv.config();

import { authorize } from './connector/oauth/authorize';
import { callback }  from './connector/oauth/callback';

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret:            process.env.JWT_SIGNING_SECRET || 'reva-session-secret',
  resave:            false,
  saveUninitialized: false,
  cookie:            { secure: process.env.NODE_ENV === 'production', maxAge: 3600000 },
}));

// ── OAuth routes ──────────────────────────────────────────────────
app.get('/oauth/authorize', authorize);
app.get('/oauth/callback',  callback);

// ── Health check ──────────────────────────────────────────────────
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
