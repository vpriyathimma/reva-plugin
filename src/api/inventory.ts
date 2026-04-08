import { Router } from 'express';
import { sessionStore, decisionLog } from '../connector/discovery/enroll';

const router = Router();

// GET /api/inventory — all enrolled sessions and their tools
router.get('/inventory', (_req, res) => {
  const sessions = Array.from(sessionStore.values()).map(s => ({
    session_id:   s.session_id,
    user_email:   s.user_email,
    enrolled_at:  s.enrolled_at,
    server_count: s.server_count,
    tool_count:   s.tool_count,
    locked:       s.locked,
    tools: s.tools.map(t => ({
      server:      t.server_name,
      tool:        t.tool_name,
      sensitivity: t.sensitivity,
      description: t.description,
    })),
  }));

  res.json({ sessions, total: sessions.length });
});

// GET /api/decisions — PDP decision log
router.get('/decisions', (_req, res) => {
  const limit  = 50;
  const recent = decisionLog.slice(-limit).reverse();
  res.json({ decisions: recent, total: decisionLog.length });
});

// GET /api/sessions — active sessions summary
router.get('/sessions', (_req, res) => {
  const sessions = Array.from(sessionStore.values()).map(s => ({
    session_id:  s.session_id,
    user_email:  s.user_email,
    enrolled_at: s.enrolled_at,
    tool_count:  s.tool_count,
    locked:      s.locked,
  }));
  res.json({ sessions, total: sessions.length });
});

// GET /api/audit — full decision log
router.get('/audit', (_req, res) => {
  res.json({ decisions: decisionLog, total: decisionLog.length });
});

export default router;
