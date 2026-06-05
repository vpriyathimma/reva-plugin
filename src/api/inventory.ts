import { Router } from 'express';
import { activeMcpServers } from '../connector/hooks/beforeToolCall';
import { sessionStore, decisionLog } from '../connector/discovery/enroll';
import { knownServers, resolveServer } from './knownServers';
import { discoveredServers, dynamicTools, getServerTools } from './mcpProbe';

const router = Router();

// GET /api/registry — deduplicated by server_name, correct status + tool count
router.get('/registry', (_req, res) => {
  const serverMap = new Map<string, any>();

  sessionStore.forEach(session => {
    session.tools.forEach((tool: any) => {
      const key = tool.server_name;
      if (serverMap.has(key)) return; // dedup — first session wins

      // Resolve against known servers by URL (primary) then name (stdio fallback)
      const match = resolveServer(tool.server_name, tool.server_url || '');

      // Determine display status
      let displayType: string;
      if (match?.entry.oauth_protected) {
        displayType = 'OAUTH-PROTECTED';
      } else if (tool.server_type === 'stdio') {
        displayType = 'STDIO';
      } else if (match) {
        displayType = 'STREAMABLE-HTTP';
      } else {
        displayType = tool.server_type?.toUpperCase() || 'UNKNOWN';
      }

      // Use known tools if available, else scanner tools
      let tools: any[];
      let riskSummary: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };

      if (match) {
        tools = Object.entries(match.entry.tools).map(([name, entry]) => ({
          name,
          description:        '',
          sensitivity:        entry.sensitivity,
          sensitivity_reason: `${entry.source} · intent: ${entry.intent.join(', ')}`,
        }));
        tools.forEach(t => { riskSummary[t.sensitivity] = (riskSummary[t.sensitivity] || 0) + 1; });
      } else {
        // Unknown server — use whatever scanner found
        tools = [];
        session.tools
          .filter((t: any) => t.server_name === key)
          .forEach((t: any) => {
            if (!tools.find((x: any) => x.name === t.tool_name)) {
              tools.push({
                name:               t.tool_name,
                description:        t.description,
                sensitivity:        t.sensitivity,
                sensitivity_reason: t.sensitivity_reason,
              });
              riskSummary[t.sensitivity] = (riskSummary[t.sensitivity] || 0) + 1;
            }
          });
      }

      serverMap.set(key, {
        server_name:  tool.server_name,
        server_url:   tool.server_url || '',
        server_type:  displayType,
        enrolled_at:  session.enrolled_at,
        user:         session.user_email,
        tools,
        risk_summary: riskSummary,
        has_registry: !!match,
      });
    });
  });

  const registry = Array.from(serverMap.values());
  res.json({ total_servers: registry.length, registry });
});

// GET /api/registry/tools — full Tool Registry data for dashboard
router.get('/registry/tools', (_req, res) => {
  const result: any[] = [];

  for (const [key, entry] of Object.entries(knownServers)) {
    const tools = Object.entries(entry.tools).map(([toolName, t]) => ({
      tool_name:   toolName,
      intent:      t.intent,
      sensitivity: t.sensitivity,
      source:      t.source,
      version:     t.version,
    }));

    result.push({
      key,
      display_name:    entry.display_name,
      url_patterns:    entry.url_patterns,
      oauth_protected: entry.oauth_protected,
      version:         entry.version,
      history:         entry.history,
      tools,
    });
  }

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
    active_mcp_servers: [...(activeMcpServers.get(s.session_id) || new Set())],
    session_id:     s.session_id,
    user_email:     s.user_email,
    enrolled_at:    s.enrolled_at,
    tool_count:     s.tool_count,
    locked:         s.locked,
    agent_id:       s.agent_id     || '',
    os_type:        s.os_type      || '',
    hostname:       s.hostname     || '',
    model:          s.model        || '',
    project_name:   s.project_name || '',
    mcp_servers_discovered: s.mcp_servers_discovered || [],
    spiffe_id:         s.spiffe_id        || '',
    oauth_email:       s.oauth_email      || '',
    developer_name:    s.developer_name   || '',
    account_uuid:      s.account_uuid     || '',
    org_uuid:          s.org_uuid         || '',
    user_id:           s.user_id          || '',
    github_repo_paths: s.github_repo_paths || {},
    git_email:         s.git_email        || '',
    git_name:          s.git_name         || '',
    git_branch:        s.git_branch       || '',
    git_remote_url:    s.git_remote_url   || '',
    jira_ticket_id:    s.jira_ticket_id   || '',
    connection_type:   s.connection_type   || 'local',
    ssh_client_ip:     s.ssh_client_ip    || '',
    remote_os:         s.remote_os        || '',
    entrypoint:        s.entrypoint       || '',
  }));
  res.json({ sessions, total: sessions.length });
});

// GET /api/audit
router.get('/audit', (_req, res) => {
  res.json({ decisions: decisionLog, total: decisionLog.length });
});

// GET /api/mcp-discovery — live MCP probe results + dynamic tool capture
router.get('/mcp-discovery', (_req, res) => {
  const servers: any[] = [];

  // Probed servers (from tools/list)
  discoveredServers.forEach((probe, name) => {
    const dynamic = dynamicTools.get(name);
    const dynamicList = dynamic ? Array.from(dynamic.values()) : [];
    servers.push({
      server_name:  probe.server_name,
      server_url:   probe.server_url,
      status:       probe.status,
      probed_at:    probe.probed_at,
      latency_ms:   probe.latency_ms,
      tools_probed: probe.tools,
      tools_dynamic: dynamicList,
      tool_count:   probe.tools.length || dynamicList.length,
    });
  });

  // Dynamic-only servers (captured via PreToolUse but never probed)
  dynamicTools.forEach((tools, name) => {
    if (!discoveredServers.has(name)) {
      servers.push({
        server_name:   name,
        server_url:    '',
        status:        'dynamic_only',
        probed_at:     '',
        latency_ms:    0,
        tools_probed:  [],
        tools_dynamic: Array.from(tools.values()),
        tool_count:    tools.size,
      });
    }
  });

  res.json({ servers, total: servers.length });
});

export default router;
