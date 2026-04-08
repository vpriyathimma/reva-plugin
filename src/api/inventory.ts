import { Router } from 'express';
import { sessionStore, decisionLog } from '../connector/discovery/enroll';

const router = Router();

// GET /api/registry — MCP Server Registry (enterprise view)
router.get('/registry', (_req, res) => {
  const registry: any[] = [];

  sessionStore.forEach(session => {
    // Group tools by server
    const serverMap = new Map<string, any>();

    session.tools.forEach((tool: any) => {
      if (!serverMap.has(tool.server_name)) {
        serverMap.set(tool.server_name, {
          server_name:  tool.server_name,
          server_url:   tool.server_url,
          server_type:  tool.server_type,
          enrolled_at:  session.enrolled_at,
          session_id:   session.session_id,
          user:         session.user_email,
          tools:        [],
          risk_summary: { critical: 0, high: 0, medium: 0, low: 0 },
        });
      }

      const srv = serverMap.get(tool.server_name);
      srv.tools.push({
        name:               tool.tool_name,
        description:        tool.description,
        sensitivity:        tool.sensitivity,
        sensitivity_reason: tool.sensitivity_reason,
      });
      srv.risk_summary[tool.sensitivity]++;
    });

    serverMap.forEach(srv => registry.push(srv));
  });

  res.json({
    total_servers: registry.length,
    registry,
  });
});

// GET /api/inventory — raw session + tool list
router.get('/inventory', (_req, res) => {
  const sessions = Array.from(sessionStore.values());
  res.json({ sessions, total: sessions.length });
});

// GET /api/decisions
router.get('/decisions', (_req, res) => {
  const recent = decisionLog.slice(-50).reverse();
  res.json({ decisions: recent, total: decisionLog.length });
});

// GET /api/sessions
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

// GET /api/audit
router.get('/audit', (_req, res) => {
  res.json({ decisions: decisionLog, total: decisionLog.length });
});

export default router;
