import { Router } from 'express';
import { sessionStore, decisionLog } from '../connector/discovery/enroll';
import { knownServers } from './knownServers';

const router = Router();

// GET /api/registry — deduplicated by server_name across all sessions
router.get('/registry', (_req, res) => {
  const serverMap = new Map<string, any>();

  sessionStore.forEach(session => {
    session.tools.forEach((tool: any) => {
      const key = tool.server_name;

      if (!serverMap.has(key)) {
        serverMap.set(key, {
          server_name:  tool.server_name,
          server_url:   tool.server_url,
          server_type:  tool.server_type,
          enrolled_at:  session.enrolled_at,
          user:         session.user_email,
          tools:        [],
          risk_summary: { critical: 0, high: 0, medium: 0, low: 0 },
        });
      }

      const srv = serverMap.get(key);

      // Deduplicate tools by name within same server
      const exists = srv.tools.find((t: any) => t.name === tool.tool_name);
      if (!exists) {
        srv.tools.push({
          name:               tool.tool_name,
          description:        tool.description,
          sensitivity:        tool.sensitivity,
          sensitivity_reason: tool.sensitivity_reason,
        });
        srv.risk_summary[tool.sensitivity] = (srv.risk_summary[tool.sensitivity] || 0) + 1;
      }
    });
  });

  const registry = Array.from(serverMap.values());
  res.json({ total_servers: registry.length, registry });
});

// GET /api/registry/tools — known servers with full Tool Registry data
router.get('/registry/tools', (_req, res) => {
  const result: any[] = [];

  for (const [serverUrl, data] of Object.entries(knownServers)) {
    const tools = Object.entries(data.tools).map(([toolName, entry]) => ({
      tool_name:   toolName,
      intent:      entry.intent,
      sensitivity: entry.sensitivity,
      source:      entry.source,
      version:     entry.version,
    }));

    result.push({
      server_url: serverUrl,
      version:    data.version,
      history:    data.history,
      tools,
    });
  }

  // Also include enrolled servers not in knownServers
  sessionStore.forEach(session => {
    session.tools.forEach((tool: any) => {
      const alreadyIncluded = result.find(r =>
        tool.server_url?.includes(r.server_url) || r.server_url?.includes(tool.server_url)
      );
      if (!alreadyIncluded && tool.server_type !== 'stdio') {
        const existing = result.find(r => r.server_url === tool.server_url);
        if (!existing && tool.server_url) {
          result.push({
            server_url: tool.server_url,
            server_name: tool.server_name,
            version:    1,
            history:    [],
            tools:      [{
              tool_name:   tool.tool_name,
              intent:      ['unknown'],
              sensitivity: tool.sensitivity,
              source:      'auto',
              version:     1,
            }],
          });
        }
      }
    });
  });

  res.json({ servers: result });
});

// GET /api/inventory
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
