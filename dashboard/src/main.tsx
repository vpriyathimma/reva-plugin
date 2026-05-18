import React, { useEffect, useState, useMemo } from 'react';
import ReactDOM from 'react-dom/client';

// ── API ──────────────────────────────────────────────────────────
const API = '';

async function fetchJSON(path: string) {
  const r = await fetch(`${API}${path}`);
  return r.json();
}

// ── Types ────────────────────────────────────────────────────────
interface Decision {
  timestamp: string; session_id: string; user_email: string;
  tool: string; server: string; sensitivity: string;
  effect: 'Permit' | 'Deny' | 'HITL'; reason: string;
  intent?: string; trust_score?: number; scores?: Record<string, any>;
  prompt?: string; prompt_history?: string[];
  agent_type?: string; command_risk?: string; file_zone?: string;
  cedar_decision?: string; cedar_policy_name?: string;
  cedar_latency_ms?: number; cedar_decision_id?: string;
}

interface Session {
  session_id: string; user_email: string; enrolled_at: string;
  tool_count: number; locked: boolean; active_mcp_servers?: string[];
  agent_id?: string; os_type?: string; hostname?: string;
  model?: string; project_name?: string; mcp_servers_discovered?: string[];
}

interface ServerEntry {
  server_name: string; server_url: string; server_type: string;
  enrolled_at: string; user: string; tools: any[]; risk_summary: Record<string, number>;
  has_registry: boolean;
}

// ── Design Tokens ────────────────────────────────────────────────
const T = {
  accent:     '#5B4DC7',
  accentLight:'#EEEDFE',
  accentMid:  '#D4D1F7',
  green:      '#0D9668',
  greenBg:    '#ECFDF5',
  red:        '#DC2626',
  redBg:      '#FEF2F2',
  amber:      '#D97706',
  amberBg:    '#FFFBEB',
  blue:       '#2563EB',
  blueBg:     '#EFF6FF',
  gray50:     '#FAFAFA',
  gray100:    '#F4F4F5',
  gray200:    '#E4E4E7',
  gray300:    '#D4D4D8',
  gray400:    '#A1A1AA',
  gray500:    '#71717A',
  gray600:    '#52525B',
  gray700:    '#3F3F46',
  gray900:    '#18181B',
  mono:       "'JetBrains Mono', monospace",
  radius:     '8px',
  radiusLg:   '12px',
};

const SENSITIVITY_COLORS: Record<string, { fg: string; bg: string }> = {
  critical: { fg: T.red,   bg: T.redBg   },
  high:     { fg: T.amber, bg: T.amberBg },
  medium:   { fg: T.blue,  bg: T.blueBg  },
  low:      { fg: T.green, bg: T.greenBg },
};

const EFFECT_COLORS: Record<string, { fg: string; bg: string }> = {
  Permit: { fg: T.green, bg: T.greenBg },
  Deny:   { fg: T.red,   bg: T.redBg   },
  HITL:   { fg: T.amber, bg: T.amberBg },
};

// ── Shared Components ────────────────────────────────────────────
function Badge({ text, fg, bg }: { text: string; fg: string; bg: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 10px', borderRadius: '20px',
      fontSize: 11, fontWeight: 600, letterSpacing: '0.3px',
      textTransform: 'uppercase', color: fg, background: bg,
      whiteSpace: 'nowrap',
    }}>{text}</span>
  );
}

function SensitivityBadge({ level }: { level: string }) {
  const c = SENSITIVITY_COLORS[level] || { fg: T.gray500, bg: T.gray100 };
  return <Badge text={level} fg={c.fg} bg={c.bg} />;
}

function EffectBadge({ effect }: { effect: string }) {
  const c = EFFECT_COLORS[effect] || { fg: T.gray500, bg: T.gray100 };
  return <Badge text={effect} fg={c.fg} bg={c.bg} />;
}

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div style={{
      background: '#fff', border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg,
      padding: '20px 24px', minWidth: 0,
    }}>
      <div style={{ fontSize: 11, fontWeight: 500, color: T.gray400, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || T.gray900, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: T.gray400, marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

function SectionHeader({ title, sub }: { title: string; sub?: string }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <h2 style={{ fontSize: 20, fontWeight: 700, color: T.gray900 }}>{title}</h2>
      {sub && <p style={{ fontSize: 13, color: T.gray500, marginTop: 4 }}>{sub}</p>}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div style={{
      padding: '48px 24px', textAlign: 'center', color: T.gray400,
      fontSize: 14, border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg,
    }}>{message}</div>
  );
}

const tableStyle: React.CSSProperties = {
  width: '100%', borderCollapse: 'collapse', fontSize: 13,
};
const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '10px 14px', color: T.gray400,
  fontWeight: 500, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.4px',
  borderBottom: `1px solid ${T.gray200}`, background: T.gray50,
};
const tdStyle: React.CSSProperties = {
  padding: '10px 14px', borderBottom: `1px solid ${T.gray100}`,
  verticalAlign: 'top',
};
const monoStyle: React.CSSProperties = {
  fontFamily: T.mono, fontSize: 12, color: T.accent,
};

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── Section A: Claude Code Agents ─────────────────────────────────
function ClaudeCodeAgents({ sessions, decisions }: { sessions: Session[]; decisions: Decision[] }) {
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null);

  const agents = useMemo(() => {
    const map = new Map<string, {
      user: string; agent_id: string; os_type: string; hostname: string; model: string;
      sessions: Session[]; lastSeen: string; totalDecisions: number; denyCount: number;
      mcpServers: Set<string>; projects: Set<string>;
    }>();
    sessions.forEach(s => {
      const key = s.user_email;
      if (!map.has(key)) map.set(key, {
        user: key, agent_id: '', os_type: '', hostname: '', model: '',
        sessions: [], lastSeen: s.enrolled_at, totalDecisions: 0, denyCount: 0,
        mcpServers: new Set(), projects: new Set(),
      });
      const entry = map.get(key)!;
      entry.sessions.push(s);
      if (new Date(s.enrolled_at) > new Date(entry.lastSeen)) entry.lastSeen = s.enrolled_at;
      // Take latest non-empty values
      if (s.agent_id) entry.agent_id = s.agent_id;
      if (s.os_type) entry.os_type = s.os_type;
      if (s.hostname) entry.hostname = s.hostname;
      if (s.model) entry.model = s.model;
      if (s.project_name) entry.projects.add(s.project_name);
      (s.active_mcp_servers || []).forEach(m => entry.mcpServers.add(m));
      (s.mcp_servers_discovered || []).forEach(m => entry.mcpServers.add(m));
    });
    decisions.forEach(d => {
      const entry = map.get(d.user_email);
      if (entry) {
        entry.totalDecisions++;
        if (d.effect === 'Deny') entry.denyCount++;
      }
    });
    return Array.from(map.values());
  }, [sessions, decisions]);

  const onlineThreshold = 30 * 60 * 1000;
  const onlineCount = agents.filter(a => Date.now() - new Date(a.lastSeen).getTime() < onlineThreshold).length;

  const detailRow = (label: string, value: string | React.ReactNode) => (
    <div style={{ display: 'flex', padding: '8px 0', borderBottom: `1px solid ${T.gray100}` }}>
      <div style={{ width: 160, fontSize: 12, color: T.gray400, fontWeight: 500, flexShrink: 0 }}>{label}</div>
      <div style={{ fontSize: 13, color: T.gray900 }}>{value}</div>
    </div>
  );

  return (
    <div>
      <SectionHeader title="Claude Code Agents" sub="All discovered Claude Code instances tied to developers" />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 28 }}>
        <StatCard label="Total Developers" value={agents.length} color={T.accent} />
        <StatCard label="Online Now" value={onlineCount} sub="Last 30 minutes" color={T.green} />
        <StatCard label="Total Sessions" value={sessions.length} />
        <StatCard label="Governed" value={agents.filter(a => a.totalDecisions > 0).length} sub={`${agents.filter(a => a.totalDecisions === 0).length} ungoverned`} color={T.green} />
      </div>

      {agents.length === 0 ? <EmptyState message="No agents discovered yet. Start a Claude Code session to populate." /> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {agents.map(a => {
            const isOnline = Date.now() - new Date(a.lastSeen).getTime() < onlineThreshold;
            const denyRate = a.totalDecisions > 0 ? Math.round((a.denyCount / a.totalDecisions) * 100) : 0;
            const isExpanded = expandedAgent === a.user;
            return (
              <div key={a.user} style={{ border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, overflow: 'hidden' }}>
                <div onClick={() => setExpandedAgent(isExpanded ? null : a.user)}
                  style={{ padding: '16px 20px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{ width: 36, height: 36, borderRadius: 8, background: isOnline ? T.greenBg : T.gray100, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ fontSize: 14, color: isOnline ? T.green : T.gray400 }}>◉</span>
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontWeight: 600, fontSize: 14 }}>{a.user}</span>
                      <span style={{ fontSize: 11, color: isOnline ? T.green : T.gray400 }}>{isOnline ? 'Online' : 'Offline'}</span>
                    </div>
                    <div style={{ fontSize: 12, color: T.gray400, marginTop: 2 }}>
                      {a.agent_id && <span style={{ fontFamily: T.mono, fontSize: 11, marginRight: 12 }}>{a.agent_id}</span>}
                      {a.model ? a.model : 'plan default'} · {a.os_type || '—'} · {a.sessions.length} session{a.sessions.length !== 1 ? 's' : ''}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: 16, fontWeight: 700 }}>{a.totalDecisions}</div>
                      <div style={{ fontSize: 10, color: T.gray400 }}>decisions</div>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: 16, fontWeight: 700, color: denyRate > 20 ? T.red : denyRate > 5 ? T.amber : T.green }}>{denyRate}%</div>
                      <div style={{ fontSize: 10, color: T.gray400 }}>deny rate</div>
                    </div>
                  </div>
                  <span style={{ color: T.gray400, fontSize: 12, transition: 'transform 0.2s', transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)' }}>▼</span>
                </div>

                {isExpanded && (
                  <div style={{ borderTop: `1px solid ${T.gray200}`, padding: '16px 20px' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 32 }}>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: T.accent, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.4px' }}>Agent Details</div>
                        {detailRow('Agent ID', <span style={{ fontFamily: T.mono, fontSize: 12 }}>{a.agent_id || '—'}</span>)}
                        {detailRow('Developer', a.user)}
                        {detailRow('Owner', a.user)}
                        {detailRow('Operating System', a.os_type || '—')}
                        {detailRow('Hostname', a.hostname || '—')}
                        {detailRow('Model', a.model || 'plan default')}
                        {detailRow('Last Active', timeAgo(a.lastSeen))}
                        {detailRow('Status', <span style={{ color: isOnline ? T.green : T.gray400, fontWeight: 600 }}>{isOnline ? 'Online' : 'Offline'}</span>)}
                      </div>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: T.accent, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.4px' }}>Activity</div>
                        {detailRow('Sessions', String(a.sessions.length))}
                        {detailRow('Projects', a.projects.size > 0 ? Array.from(a.projects).join(', ') : '—')}
                        {detailRow('Total Decisions', String(a.totalDecisions))}
                        {detailRow('Deny Rate', <span style={{ fontWeight: 600, color: denyRate > 20 ? T.red : T.green }}>{denyRate}%</span>)}
                        {detailRow('MCP Servers', a.mcpServers.size > 0
                          ? <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{Array.from(a.mcpServers).map(s => <span key={s} style={{ fontFamily: T.mono, fontSize: 11, background: T.gray100, padding: '1px 8px', borderRadius: 4 }}>{s}</span>)}</div>
                          : '—'
                        )}
                      </div>
                    </div>

                    {/* Session History */}
                    <div style={{ marginTop: 20 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: T.accent, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.4px' }}>Session History</div>
                      <table style={tableStyle}>
                        <thead><tr>
                          {['Session ID', 'Project', 'Model', 'Tools', 'MCP Servers', 'Enrolled'].map(h => <th key={h} style={thStyle}>{h}</th>)}
                        </tr></thead>
                        <tbody>{a.sessions.map(s => (
                          <tr key={s.session_id}>
                            <td style={{ ...tdStyle, ...monoStyle, fontSize: 11 }}>{s.session_id.slice(0, 16)}…</td>
                            <td style={tdStyle}>{s.project_name || '—'}</td>
                            <td style={{ ...tdStyle, fontSize: 12 }}>{s.model || 'plan default'}</td>
                            <td style={tdStyle}>{s.tool_count}</td>
                            <td style={tdStyle}>{(s.mcp_servers_discovered || []).length > 0 ? (s.mcp_servers_discovered || []).join(', ') : '—'}</td>
                            <td style={{ ...tdStyle, fontSize: 11, color: T.gray500 }}>{timeAgo(s.enrolled_at)}</td>
                          </tr>
                        ))}</tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Section B: MCP Discovery ─────────────────────────────────────
function MCPDiscovery({ registry, decisions, mcpDiscovery }: { registry: ServerEntry[]; decisions: Decision[]; mcpDiscovery: any[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  // Merge mcpDiscovery with decision-based stats
  const serverStats = useMemo(() => {
    const stats = new Map<string, { calls: number; reads: number; writes: number; denies: number }>();
    decisions.forEach(d => {
      if (d.tool === 'prompt') return;
      const server = d.server || 'claude-code';
      if (!stats.has(server)) stats.set(server, { calls: 0, reads: 0, writes: 0, denies: 0 });
      const s = stats.get(server)!;
      s.calls++;
      if (d.effect === 'Deny') s.denies++;
      if (d.intent === 'read') s.reads++;
      else s.writes++;
    });
    return stats;
  }, [decisions]);

  // Build unified server list from mcpDiscovery (primary) + registry (fallback)
  const servers = useMemo(() => {
    const map = new Map<string, any>();

    // MCP probe results first
    mcpDiscovery.forEach(s => {
      const allTools = [
        ...(s.tools_probed || []).map((t: any) => ({ ...t, source: 'probe' })),
        ...(s.tools_dynamic || []).map((t: any) => ({ name: t.tool_name, sensitivity: t.sensitivity || 'medium', source: 'dynamic', call_count: t.call_count, last_called: t.last_called })),
      ];
      map.set(s.server_name, {
        server_name: s.server_name,
        server_url:  s.server_url || '',
        status:      s.status,
        tools:       allTools,
        tool_count:  allTools.length,
        probed_at:   s.probed_at,
        latency_ms:  s.latency_ms,
      });
    });

    // Add registry servers not already in probe results
    registry.forEach(s => {
      if (!map.has(s.server_name)) {
        map.set(s.server_name, {
          server_name: s.server_name,
          server_url:  s.server_url || '',
          status:      'registry',
          tools:       s.tools.map(t => ({ name: t.name, sensitivity: t.sensitivity, source: 'registry' })),
          tool_count:  s.tools.length,
        });
      }
    });

    return Array.from(map.values());
  }, [mcpDiscovery, registry]);

  const totalTools = servers.reduce((a, s) => a + s.tool_count, 0);
  const discoveredCount = servers.filter(s => s.status === 'discovered').length;
  const authRequiredCount = servers.filter(s => s.status === 'auth_required').length;

  const STATUS_BADGE: Record<string, { fg: string; bg: string; label: string }> = {
    discovered:    { fg: T.green, bg: T.greenBg, label: 'Discovered' },
    auth_required: { fg: T.amber, bg: T.amberBg, label: 'Auth Required' },
    dynamic_only:  { fg: T.blue,  bg: T.blueBg,  label: 'Dynamic' },
    unreachable:   { fg: T.red,   bg: T.redBg,   label: 'Unreachable' },
    registry:      { fg: T.gray500, bg: T.gray100, label: 'Registry' },
  };

  return (
    <div>
      <SectionHeader title="MCP Discovery" sub="Live tool discovery via MCP protocol + dynamic capture from usage" />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 28 }}>
        <StatCard label="MCP Servers" value={servers.length} color={T.accent} />
        <StatCard label="Total Tools" value={totalTools} />
        <StatCard label="Discovered (live)" value={discoveredCount} sub={`via tools/list`} color={T.green} />
        <StatCard label="Auth Required" value={authRequiredCount} sub="tools captured on use" color={authRequiredCount > 0 ? T.amber : T.green} />
      </div>

      {servers.length === 0 ? <EmptyState message="No MCP servers discovered. Start a Claude Code session to trigger probe." /> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {servers.map(server => {
            const stats = serverStats.get(server.server_name);
            const isExpanded = expanded === server.server_name;
            const statusBadge = STATUS_BADGE[server.status] || STATUS_BADGE.registry;
            return (
              <div key={server.server_name} style={{ border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, overflow: 'hidden' }}>
                <div onClick={() => setExpanded(isExpanded ? null : server.server_name)}
                  style={{ padding: '16px 20px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontWeight: 600, fontSize: 14 }}>{server.server_name}</span>
                      <Badge text={statusBadge.label} fg={statusBadge.fg} bg={statusBadge.bg} />
                      <span style={{ fontSize: 11, color: T.gray400 }}>{server.tool_count} tools</span>
                    </div>
                    {server.server_url && <div style={{ fontSize: 11, color: T.gray400, fontFamily: T.mono, marginTop: 4 }}>{server.server_url}</div>}
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    {stats && <span style={{ fontSize: 11, color: T.gray500 }}>{stats.calls} calls</span>}
                    {stats && stats.denies > 0 && <span style={{ fontSize: 11, color: T.red, fontWeight: 600 }}>{stats.denies} denied</span>}
                    {server.latency_ms > 0 && <span style={{ fontSize: 11, color: T.gray400 }}>{server.latency_ms}ms</span>}
                  </div>
                  <span style={{ color: T.gray400, fontSize: 12, transition: 'transform 0.2s', transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)' }}>▼</span>
                </div>

                {isExpanded && (
                  <div style={{ borderTop: `1px solid ${T.gray200}` }}>
                    {server.tools.length === 0 ? (
                      <div style={{ padding: '20px', color: T.gray400, fontSize: 13, textAlign: 'center' }}>
                        {server.status === 'auth_required' ? 'Tools will appear here as they are used. Auth required for full probe.' : 'No tools discovered yet.'}
                      </div>
                    ) : (
                      <table style={tableStyle}>
                        <thead><tr>
                          {['Tool Name', 'Sensitivity', 'Source', 'Calls', 'Description'].map(h => <th key={h} style={thStyle}>{h}</th>)}
                        </tr></thead>
                        <tbody>{server.tools.map((tool: any, i: number) => {
                          const toolDecisions = decisions.filter(d => d.tool?.includes(tool.name));
                          return (
                            <tr key={i}>
                              <td style={{ ...tdStyle, ...monoStyle, fontSize: 11 }}>{tool.name}</td>
                              <td style={tdStyle}><SensitivityBadge level={tool.sensitivity} /></td>
                              <td style={tdStyle}>
                                <Badge
                                  text={tool.source}
                                  fg={tool.source === 'probe' ? T.green : tool.source === 'dynamic' ? T.blue : T.gray500}
                                  bg={tool.source === 'probe' ? T.greenBg : tool.source === 'dynamic' ? T.blueBg : T.gray100}
                                />
                              </td>
                              <td style={tdStyle}>{tool.call_count || toolDecisions.length || 0}</td>
                              <td style={{ ...tdStyle, fontSize: 11, color: T.gray500, maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{tool.description || '—'}</td>
                            </tr>
                          );
                        })}</tbody>
                      </table>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Section C: Usage Analytics & Risk ────────────────────────────
function UsageAnalytics({ decisions, sessions }: { decisions: Decision[]; sessions: Session[] }) {
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [selectedUser, setSelectedUser] = useState<string | null>(null);

  // Per-user risk scores
  const userRisk = useMemo(() => {
    const map = new Map<string, { user: string; total: number; denies: number; hitls: number; hitlApproved: number; hitlTimeout: number; guardrailBlocks: number; promptDenials: number; avgTrust: number; trustSum: number; decisions: Decision[] }>();
    decisions.forEach(d => {
      if (!map.has(d.user_email)) map.set(d.user_email, { user: d.user_email, total: 0, denies: 0, hitls: 0, hitlApproved: 0, hitlTimeout: 0, guardrailBlocks: 0, promptDenials: 0, avgTrust: 0, trustSum: 0, decisions: [] });
      const u = map.get(d.user_email)!;
      u.total++;
      u.decisions.push(d);
      if (d.trust_score !== undefined) u.trustSum += d.trust_score;
      if (d.effect === 'Deny') u.denies++;
      if (d.effect === 'HITL') u.hitls++;
      if (d.reason?.includes('HITL approved')) u.hitlApproved++;
      if (d.reason?.includes('timeout')) u.hitlTimeout++;
      if (d.tool === 'prompt' && d.effect === 'Deny') u.promptDenials++;
      if (d.scores?.injection_score > 50 || d.scores?.jailbreak_score > 50 || d.scores?.escalation_score > 50) u.guardrailBlocks++;
    });
    return Array.from(map.values()).map(u => {
      const denyRate = u.total > 0 ? u.denies / u.total : 0;
      const guardrailRate = u.total > 0 ? u.guardrailBlocks / u.total : 0;
      const promptDenialRate = u.total > 0 ? u.promptDenials / u.total : 0;
      const hitlApprovalRate = u.hitls > 0 ? u.hitlApproved / u.hitls : 1;
      const hitlTimeoutRate = u.hitls > 0 ? u.hitlTimeout / u.hitls : 0;
      const riskScore = Math.round((0.3 * denyRate + 0.25 * guardrailRate + 0.2 * promptDenialRate + 0.15 * (1 - hitlApprovalRate) + 0.1 * hitlTimeoutRate) * 100);
      return { ...u, denyRate, riskScore, hitlApprovalRate, avgTrust: u.total > 0 ? Math.round(u.trustSum / u.total) : 0 };
    }).sort((a, b) => b.riskScore - a.riskScore);
  }, [decisions]);

  // Aggregate stats
  const totalDecisions = decisions.length;
  const totalDenies = decisions.filter(d => d.effect === 'Deny').length;
  const totalHITL = decisions.filter(d => d.effect === 'HITL').length;
  const avgLatency = decisions.filter(d => d.cedar_latency_ms).reduce((a, d) => a + (d.cedar_latency_ms || 0), 0) / (decisions.filter(d => d.cedar_latency_ms).length || 1);

  // Session timeline
  const sessionDecisions = selectedSession
    ? decisions.filter(d => d.session_id === selectedSession).sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    : [];

  // User detail
  const userDetail = selectedUser ? userRisk.find(u => u.user === selectedUser) : null;

  // Guardrail score keys to display
  const GUARDRAIL_KEYS = [
    'injection_score', 'jailbreak_score', 'escalation_score', 'exfiltration_score',
    'sod_score', 'velocity_score', 'after_hours_score', 'bypass_attempts_score',
    'bulk_operation_score', 'intent_mismatch_score', 'intent_pool_score',
  ];

  return (
    <div>
      <SectionHeader title="Usage Analytics & Risk" sub="Per-user risk scoring, guardrail breakdown, and session drill-down" />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 28 }}>
        <StatCard label="Total Decisions" value={totalDecisions} color={T.accent} />
        <StatCard label="Denies" value={totalDenies} sub={`${totalDecisions > 0 ? Math.round((totalDenies / totalDecisions) * 100) : 0}% deny rate`} color={T.red} />
        <StatCard label="HITL Triggers" value={totalHITL} color={T.amber} />
        <StatCard label="Avg Cedar Latency" value={`${Math.round(avgLatency)}ms`} />
      </div>

      {/* User Risk Table */}
      {!selectedUser && !selectedSession && (
        <>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Risk Scores by Developer</div>
          {userRisk.length === 0 ? <EmptyState message="No usage data yet." /> : (
            <div style={{ border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, overflow: 'hidden', marginBottom: 32 }}>
              <table style={tableStyle}>
                <thead><tr>
                  {['Developer', 'Risk Score', 'Decisions', 'Deny Rate', 'HITL', 'Avg Trust', 'Actions'].map(h => <th key={h} style={thStyle}>{h}</th>)}
                </tr></thead>
                <tbody>{userRisk.map(u => (
                  <tr key={u.user}>
                    <td style={{ ...tdStyle, fontWeight: 500 }}>{u.user}</td>
                    <td style={tdStyle}>
                      <span style={{
                        display: 'inline-block', padding: '2px 12px', borderRadius: 20, fontWeight: 700, fontSize: 12,
                        color: u.riskScore > 40 ? T.red : u.riskScore > 15 ? T.amber : T.green,
                        background: u.riskScore > 40 ? T.redBg : u.riskScore > 15 ? T.amberBg : T.greenBg,
                      }}>{u.riskScore}</span>
                    </td>
                    <td style={tdStyle}>{u.total}</td>
                    <td style={tdStyle}><span style={{ fontWeight: 600, color: u.denyRate > 0.2 ? T.red : T.gray600 }}>{Math.round(u.denyRate * 100)}%</span></td>
                    <td style={tdStyle}>{u.hitls} <span style={{ color: T.gray400, fontSize: 11 }}>({Math.round(u.hitlApprovalRate * 100)}% approved)</span></td>
                    <td style={tdStyle}>{u.avgTrust}</td>
                    <td style={tdStyle}>
                      <button onClick={() => setSelectedUser(u.user)} style={{ fontSize: 11, padding: '4px 12px', borderRadius: 6, background: T.accentLight, color: T.accent, border: 'none', cursor: 'pointer', fontWeight: 600 }}>Detail</button>
                    </td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}

          {/* Decision Feed */}
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Decision Feed</div>
          <div style={{ border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, overflow: 'hidden' }}>
            <table style={tableStyle}>
              <thead><tr>
                {['Time', 'User', 'Tool', 'Intent', 'Sensitivity', 'Decision', 'Trust', 'Prompt', 'Cedar Policy', 'Latency'].map(h => <th key={h} style={thStyle}>{h}</th>)}
              </tr></thead>
              <tbody>{decisions.slice(0, 50).map((d, i) => (
                <tr key={i} style={{ cursor: 'pointer' }} onClick={() => setSelectedSession(d.session_id)}>
                  <td style={{ ...tdStyle, color: T.gray500, fontSize: 11, whiteSpace: 'nowrap' }}>{new Date(d.timestamp).toLocaleTimeString()}</td>
                  <td style={{ ...tdStyle, fontSize: 12 }}>{d.user_email}</td>
                  <td style={{ ...tdStyle, ...monoStyle, fontSize: 11 }}>{d.tool}</td>
                  <td style={{ ...tdStyle, fontSize: 12 }}>{d.intent || '—'}</td>
                  <td style={tdStyle}><SensitivityBadge level={d.sensitivity} /></td>
                  <td style={tdStyle}><EffectBadge effect={d.effect} /></td>
                  <td style={{ ...tdStyle, fontSize: 12, fontWeight: 600, color: (d.trust_score ?? 70) < 30 ? T.red : (d.trust_score ?? 70) < 50 ? T.amber : T.gray600 }}>{d.trust_score ?? '—'}</td>
                  <td style={{ ...tdStyle, fontSize: 11, color: T.gray500, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.prompt || '—'}</td>
                  <td style={{ ...tdStyle, fontSize: 11, color: T.gray500 }}>{d.cedar_policy_name || '—'}</td>
                  <td style={{ ...tdStyle, fontSize: 11, color: T.gray400 }}>{d.cedar_latency_ms ? `${d.cedar_latency_ms}ms` : '—'}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </>
      )}

      {/* User Detail Drill-down */}
      {selectedUser && userDetail && !selectedSession && (
        <div>
          <button onClick={() => setSelectedUser(null)} style={{ fontSize: 12, color: T.accent, background: 'none', border: 'none', cursor: 'pointer', marginBottom: 16, fontWeight: 600 }}>← Back to risk table</button>
          <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 20 }}>{userDetail.user} — Risk Detail</div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 28 }}>
            <StatCard label="Risk Score" value={userDetail.riskScore} color={userDetail.riskScore > 40 ? T.red : userDetail.riskScore > 15 ? T.amber : T.green} />
            <StatCard label="Avg Trust Score" value={userDetail.avgTrust} />
            <StatCard label="Deny Rate" value={`${Math.round(userDetail.denyRate * 100)}%`} color={userDetail.denyRate > 0.2 ? T.red : T.green} />
          </div>

          {/* Guardrail Breakdown */}
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Guardrail Score Breakdown</div>
          <div style={{ border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, overflow: 'hidden', marginBottom: 28 }}>
            <table style={tableStyle}>
              <thead><tr>
                {['Guardrail', 'Max Score', 'Avg Score', 'Triggers (>50)'].map(h => <th key={h} style={thStyle}>{h}</th>)}
              </tr></thead>
              <tbody>{GUARDRAIL_KEYS.map(key => {
                const vals = userDetail.decisions.filter(d => d.scores?.[key] !== undefined).map(d => d.scores![key] as number);
                const max = vals.length > 0 ? Math.max(...vals) : 0;
                const avg = vals.length > 0 ? Math.round(vals.reduce((a, b) => a + b, 0) / vals.length) : 0;
                const triggers = vals.filter(v => v > 50).length;
                return (
                  <tr key={key}>
                    <td style={{ ...tdStyle, ...monoStyle, fontSize: 11 }}>{key.replace(/_/g, ' ')}</td>
                    <td style={{ ...tdStyle, fontWeight: 600, color: max > 50 ? T.red : T.gray600 }}>{max}</td>
                    <td style={tdStyle}>{avg}</td>
                    <td style={tdStyle}>{triggers > 0 ? <span style={{ color: T.red, fontWeight: 600 }}>{triggers}</span> : '0'}</td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>

          {/* User Decisions */}
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Decision History</div>
          <div style={{ border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, overflow: 'hidden' }}>
            <table style={tableStyle}>
              <thead><tr>
                {['Time', 'Tool', 'Decision', 'Sensitivity', 'Trust', 'Agent Type', 'Cmd Risk', 'Zone', 'Prompt'].map(h => <th key={h} style={thStyle}>{h}</th>)}
              </tr></thead>
              <tbody>{userDetail.decisions.slice(0, 100).map((d, i) => (
                <tr key={i} style={{ cursor: 'pointer' }} onClick={() => setSelectedSession(d.session_id)}>
                  <td style={{ ...tdStyle, fontSize: 11, color: T.gray500, whiteSpace: 'nowrap' }}>{new Date(d.timestamp).toLocaleTimeString()}</td>
                  <td style={{ ...tdStyle, ...monoStyle, fontSize: 11 }}>{d.tool}</td>
                  <td style={tdStyle}><EffectBadge effect={d.effect} /></td>
                  <td style={tdStyle}><SensitivityBadge level={d.sensitivity} /></td>
                  <td style={{ ...tdStyle, fontWeight: 600, fontSize: 12 }}>{d.trust_score ?? '—'}</td>
                  <td style={{ ...tdStyle, fontSize: 11 }}>{d.agent_type || '—'}</td>
                  <td style={{ ...tdStyle, fontSize: 11 }}>{d.command_risk || '—'}</td>
                  <td style={{ ...tdStyle, fontSize: 11 }}>{d.file_zone || '—'}</td>
                  <td style={{ ...tdStyle, fontSize: 11, color: T.gray500, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.prompt || '—'}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      )}

      {/* Session Timeline Drill-down */}
      {selectedSession && (
        <div>
          <button onClick={() => setSelectedSession(null)} style={{ fontSize: 12, color: T.accent, background: 'none', border: 'none', cursor: 'pointer', marginBottom: 16, fontWeight: 600 }}>← Back</button>
          <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Session Timeline</div>
          <div style={{ fontSize: 12, color: T.gray400, fontFamily: T.mono, marginBottom: 20 }}>{selectedSession}</div>

          {sessionDecisions.length === 0 ? <EmptyState message="No decisions recorded for this session." /> : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 0, border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, overflow: 'hidden' }}>
              {sessionDecisions.map((d, i) => (
                <div key={i} style={{ padding: '14px 20px', borderBottom: i < sessionDecisions.length - 1 ? `1px solid ${T.gray100}` : 'none', display: 'flex', gap: 16, alignItems: 'flex-start' }}>
                  <div style={{ minWidth: 64, fontSize: 11, color: T.gray400, paddingTop: 2 }}>{new Date(d.timestamp).toLocaleTimeString()}</div>
                  <div style={{ minWidth: 60 }}><EffectBadge effect={d.effect} /></div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ ...monoStyle, fontSize: 12 }}>{d.tool}</span>
                      <SensitivityBadge level={d.sensitivity} />
                      {d.intent && <span style={{ fontSize: 11, color: T.gray500 }}>intent: {d.intent}</span>}
                      {d.trust_score !== undefined && <span style={{ fontSize: 11, fontWeight: 600, color: d.trust_score < 30 ? T.red : T.gray500 }}>trust: {d.trust_score}</span>}
                      {d.agent_type && d.agent_type !== 'main' && <Badge text={d.agent_type} fg={T.amber} bg={T.amberBg} />}
                      {d.command_risk && d.command_risk !== '' && <span style={{ fontSize: 11, color: d.command_risk === 'destructive' ? T.red : d.command_risk === 'restricted' ? T.amber : T.gray400 }}>cmd: {d.command_risk}</span>}
                      {d.file_zone && d.file_zone !== '' && <span style={{ fontSize: 11, color: T.gray400 }}>zone: {d.file_zone}</span>}
                    </div>
                    {d.prompt && <div style={{ fontSize: 11, color: T.gray500, marginTop: 4, fontStyle: 'italic' }}>"{d.prompt}"</div>}
                    {d.reason && d.reason !== 'Tool call permitted' && <div style={{ fontSize: 11, color: d.effect === 'Deny' ? T.red : T.gray400, marginTop: 2 }}>{d.reason}</div>}
                    {d.cedar_policy_name && <div style={{ fontSize: 10, color: T.gray400, marginTop: 2 }}>Policy: {d.cedar_policy_name} · {d.cedar_latency_ms}ms</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Section D: Admin Classification Config ───────────────────────
function AdminConfig() {
  // Command classifications — editable
  const [commands, setCommands] = useState([
    { pattern: 'rm |drop table|truncate|delete from|mkfs|dd if=|>/dev/|kill -9|pkill|rmdir', risk: 'destructive' },
    { pattern: 'npm install|pip install|yarn install|git push|git pull|git merge|git rebase|curl|wget|ssh |scp |docker build|docker run|kubectl|terraform|chmod|chown|nohup|psql|mysql|mongosh|pg_dump|mysqldump', risk: 'restricted' },
    { pattern: '*', risk: 'safe' },
  ]);

  // File zone classifications — editable
  const [zones, setZones] = useState([
    { pattern: '.env|secrets|.pem|.key', zone: 'secrets' },
    { pattern: 'package.json|tsconfig|.claude/', zone: 'config' },
    { pattern: 'tests/|test/|.test.|.spec.', zone: 'tests' },
    { pattern: 'src/|lib/|app/', zone: 'src' },
    { pattern: 'docs/|README', zone: 'docs' },
    { pattern: '*', zone: 'other' },
  ]);

  const [editingCmd, setEditingCmd] = useState<number | null>(null);
  const [editingZone, setEditingZone] = useState<number | null>(null);
  const [addingCmd, setAddingCmd] = useState(false);
  const [addingZone, setAddingZone] = useState(false);
  const [newCmd, setNewCmd] = useState({ pattern: '', risk: 'restricted' });
  const [newZone, setNewZone] = useState({ pattern: '', zone: 'other' });

  const RISK_OPTIONS = ['safe', 'restricted', 'destructive'];
  const ZONE_OPTIONS = ['secrets', 'config', 'tests', 'src', 'docs', 'other'];

  const riskColors: Record<string, { fg: string; bg: string }> = {
    safe:        { fg: T.green, bg: T.greenBg },
    restricted:  { fg: T.amber, bg: T.amberBg },
    destructive: { fg: T.red,   bg: T.redBg },
  };

  const inputStyle: React.CSSProperties = {
    fontSize: 12, padding: '6px 10px', borderRadius: 6,
    border: `1px solid ${T.gray200}`, fontFamily: T.mono, width: '100%',
  };
  const selectStyle: React.CSSProperties = {
    fontSize: 12, padding: '6px 10px', borderRadius: 6,
    border: `1px solid ${T.gray200}`,
  };
  const btnPrimary: React.CSSProperties = {
    fontSize: 11, padding: '5px 14px', borderRadius: 6,
    background: T.accent, color: '#fff', border: 'none', cursor: 'pointer', fontWeight: 600,
  };
  const btnSecondary: React.CSSProperties = {
    fontSize: 11, padding: '5px 14px', borderRadius: 6,
    background: T.gray100, color: T.gray600, border: 'none', cursor: 'pointer', fontWeight: 500,
  };

  return (
    <div>
      <SectionHeader title="Admin Classification Config" sub="Configure command risk levels, file zone mappings, and generate Cedar policy templates" />

      {/* Command Classification */}
      <div style={{ marginBottom: 40 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <div style={{ fontSize: 14, fontWeight: 600 }}>Command Classification</div>
          <button onClick={() => setAddingCmd(true)} style={btnPrimary}>+ Add Pattern</button>
        </div>
        <div style={{ border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, overflow: 'hidden' }}>
          <table style={tableStyle}>
            <thead><tr>
              {['Pattern (regex)', 'Risk Level', 'Actions'].map(h => <th key={h} style={thStyle}>{h}</th>)}
            </tr></thead>
            <tbody>
              {addingCmd && (
                <tr>
                  <td style={tdStyle}><input value={newCmd.pattern} onChange={e => setNewCmd({ ...newCmd, pattern: e.target.value })} placeholder="regex pattern" style={inputStyle} /></td>
                  <td style={tdStyle}>
                    <select value={newCmd.risk} onChange={e => setNewCmd({ ...newCmd, risk: e.target.value })} style={selectStyle}>
                      {RISK_OPTIONS.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                  <td style={tdStyle}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={() => { setCommands([...commands.slice(0, -1), newCmd, commands[commands.length - 1]]); setAddingCmd(false); setNewCmd({ pattern: '', risk: 'restricted' }); }} style={btnPrimary}>Save</button>
                      <button onClick={() => setAddingCmd(false)} style={btnSecondary}>Cancel</button>
                    </div>
                  </td>
                </tr>
              )}
              {commands.map((cmd, i) => (
                <tr key={i}>
                  <td style={tdStyle}>
                    {editingCmd === i ? (
                      <input value={cmd.pattern} onChange={e => { const c = [...commands]; c[i] = { ...c[i], pattern: e.target.value }; setCommands(c); }} style={inputStyle} />
                    ) : (
                      <span style={{ fontFamily: T.mono, fontSize: 11, color: T.gray700, wordBreak: 'break-all' }}>{cmd.pattern === '*' ? '(default — all other commands)' : cmd.pattern}</span>
                    )}
                  </td>
                  <td style={tdStyle}>
                    {editingCmd === i ? (
                      <select value={cmd.risk} onChange={e => { const c = [...commands]; c[i] = { ...c[i], risk: e.target.value }; setCommands(c); }} style={selectStyle}>
                        {RISK_OPTIONS.map(r => <option key={r} value={r}>{r}</option>)}
                      </select>
                    ) : (
                      <Badge text={cmd.risk} fg={riskColors[cmd.risk]?.fg || T.gray500} bg={riskColors[cmd.risk]?.bg || T.gray100} />
                    )}
                  </td>
                  <td style={tdStyle}>
                    {cmd.pattern !== '*' && (
                      editingCmd === i ? (
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button onClick={() => setEditingCmd(null)} style={btnPrimary}>Done</button>
                          <button onClick={() => { setCommands(commands.filter((_, j) => j !== i)); setEditingCmd(null); }} style={{ ...btnSecondary, color: T.red }}>Delete</button>
                        </div>
                      ) : (
                        <button onClick={() => setEditingCmd(i)} style={btnSecondary}>Edit</button>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* File Zone Classification */}
      <div style={{ marginBottom: 40 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <div style={{ fontSize: 14, fontWeight: 600 }}>File Zone Classification</div>
          <button onClick={() => setAddingZone(true)} style={btnPrimary}>+ Add Pattern</button>
        </div>
        <div style={{ border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, overflow: 'hidden' }}>
          <table style={tableStyle}>
            <thead><tr>
              {['Path Pattern', 'Zone', 'Actions'].map(h => <th key={h} style={thStyle}>{h}</th>)}
            </tr></thead>
            <tbody>
              {addingZone && (
                <tr>
                  <td style={tdStyle}><input value={newZone.pattern} onChange={e => setNewZone({ ...newZone, pattern: e.target.value })} placeholder="path pattern" style={inputStyle} /></td>
                  <td style={tdStyle}>
                    <select value={newZone.zone} onChange={e => setNewZone({ ...newZone, zone: e.target.value })} style={selectStyle}>
                      {ZONE_OPTIONS.map(z => <option key={z} value={z}>{z}</option>)}
                    </select>
                  </td>
                  <td style={tdStyle}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={() => { setZones([...zones.slice(0, -1), newZone, zones[zones.length - 1]]); setAddingZone(false); setNewZone({ pattern: '', zone: 'other' }); }} style={btnPrimary}>Save</button>
                      <button onClick={() => setAddingZone(false)} style={btnSecondary}>Cancel</button>
                    </div>
                  </td>
                </tr>
              )}
              {zones.map((z, i) => (
                <tr key={i}>
                  <td style={tdStyle}>
                    {editingZone === i ? (
                      <input value={z.pattern} onChange={e => { const zs = [...zones]; zs[i] = { ...zs[i], pattern: e.target.value }; setZones(zs); }} style={inputStyle} />
                    ) : (
                      <span style={{ fontFamily: T.mono, fontSize: 11, color: T.gray700 }}>{z.pattern === '*' ? '(default — all other paths)' : z.pattern}</span>
                    )}
                  </td>
                  <td style={tdStyle}>
                    {editingZone === i ? (
                      <select value={z.zone} onChange={e => { const zs = [...zones]; zs[i] = { ...zs[i], zone: e.target.value }; setZones(zs); }} style={selectStyle}>
                        {ZONE_OPTIONS.map(zo => <option key={zo} value={zo}>{zo}</option>)}
                      </select>
                    ) : (
                      <span style={{ fontSize: 12, fontWeight: 500, color: z.zone === 'secrets' ? T.red : z.zone === 'src' ? T.accent : T.gray600 }}>{z.zone}</span>
                    )}
                  </td>
                  <td style={tdStyle}>
                    {z.pattern !== '*' && (
                      editingZone === i ? (
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button onClick={() => setEditingZone(null)} style={btnPrimary}>Done</button>
                          <button onClick={() => { setZones(zones.filter((_, j) => j !== i)); setEditingZone(null); }} style={{ ...btnSecondary, color: T.red }}>Delete</button>
                        </div>
                      ) : (
                        <button onClick={() => setEditingZone(i)} style={btnSecondary}>Edit</button>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Policy Suggestion Engine */}
      <div>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Policy Suggestion Engine</div>
        <div style={{ border: `1px solid ${T.gray200}`, borderRadius: T.radiusLg, padding: 24 }}>
          <p style={{ fontSize: 13, color: T.gray500, marginBottom: 16 }}>
            Based on current classifications, these Cedar policy templates can be generated for review and deployment to AVP.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {commands.filter(c => c.pattern !== '*').map((cmd, i) => (
              <div key={`cmd-${i}`} style={{ background: T.gray50, borderRadius: T.radius, padding: '12px 16px' }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: T.accent, marginBottom: 6 }}>
                  {cmd.risk === 'destructive' ? 'FORBID' : 'PERMIT WHEN'} — Command: {cmd.risk}
                </div>
                <pre style={{ fontFamily: T.mono, fontSize: 11, color: T.gray700, whiteSpace: 'pre-wrap', margin: 0 }}>
{cmd.risk === 'destructive'
  ? `forbid (principal, action == Action::"RunBash", resource)
when { resource.command_risk == "destructive" };`
  : `permit (principal, action == Action::"RunBash", resource)
when {
  resource.command_risk == "${cmd.risk}"
  && context.approver_consent == true
};`}
                </pre>
              </div>
            ))}
            {zones.filter(z => z.zone === 'secrets').map((z, i) => (
              <div key={`zone-${i}`} style={{ background: T.gray50, borderRadius: T.radius, padding: '12px 16px' }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: T.red, marginBottom: 6 }}>FORBID — File Zone: secrets</div>
                <pre style={{ fontFamily: T.mono, fontSize: 11, color: T.gray700, whiteSpace: 'pre-wrap', margin: 0 }}>
{`forbid (principal, action, resource)
when { resource.file_zone == "secrets" };`}
                </pre>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── App Shell ────────────────────────────────────────────────────
type TabKey = 'inventory' | 'discovery' | 'analytics' | 'admin';

const NAV_ITEMS: { key: TabKey; label: string; icon: string }[] = [
  { key: 'inventory', label: 'Claude Code Agents', icon: '◉' },
  { key: 'discovery', label: 'MCP Discovery',   icon: '⬡' },
  { key: 'analytics', label: 'Usage & Risk',    icon: '◈' },
  { key: 'admin',     label: 'Admin Config',    icon: '⚙' },
];

function App() {
  const [tab, setTab] = useState<TabKey>('inventory');
  const [loading, setLoading] = useState(true);
  const [registry, setRegistry] = useState<ServerEntry[]>([]);
  const [mcpDiscovery, setMcpDiscovery] = useState<any[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [decisions, setDecisions] = useState<Decision[]>([]);

  useEffect(() => {
    const load = async () => {
      try {
        const [reg, sess, dec, mcpDisc] = await Promise.all([
          fetchJSON('/api/registry'), fetchJSON('/api/sessions'), fetchJSON('/api/decisions'), fetchJSON('/api/mcp-discovery'),
        ]);
        setRegistry(reg.registry || []);
        setSessions(sess.sessions || []);
        setDecisions(dec.decisions || []);
        setMcpDiscovery(mcpDisc.servers || []);
      } catch (e) { console.error('Load error:', e); }
      finally { setLoading(false); }
    };
    load();
    const iv = setInterval(load, 10000);
    return () => clearInterval(iv);
  }, []);

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#fff' }}>
      {/* Sidebar */}
      <div style={{
        width: 240, borderRight: `1px solid ${T.gray200}`, display: 'flex', flexDirection: 'column',
        flexShrink: 0, position: 'sticky', top: 0, height: '100vh',
      }}>
        {/* Logo */}
        <div style={{ padding: '24px 24px 28px', borderBottom: `1px solid ${T.gray200}` }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 8, background: T.accent,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: '#fff', fontWeight: 700, fontSize: 14,
            }}>R</div>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15, color: T.gray900 }}>Reva</div>
              <div style={{ fontSize: 11, color: T.gray400 }}>Governance Console</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ padding: '12px 12px', flex: 1 }}>
          {NAV_ITEMS.map(item => {
            const active = tab === item.key;
            return (
              <button key={item.key} onClick={() => setTab(item.key)} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                width: '100%', padding: '10px 12px', marginBottom: 2,
                borderRadius: T.radius, border: 'none', cursor: 'pointer',
                background: active ? T.accentLight : 'transparent',
                color: active ? T.accent : T.gray500,
                fontWeight: active ? 600 : 400, fontSize: 13,
                textAlign: 'left', transition: 'all 0.15s',
              }}>
                <span style={{ fontSize: 14, width: 20, textAlign: 'center' }}>{item.icon}</span>
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Footer */}
        <div style={{ padding: '16px 24px', borderTop: `1px solid ${T.gray200}`, fontSize: 11, color: T.gray400 }}>
          Claude Code Plugin v1.0
        </div>
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, padding: '32px 40px', maxWidth: 1200, minWidth: 0 }}>
        {loading ? (
          <div style={{ padding: 64, textAlign: 'center', color: T.gray400, fontSize: 14 }}>Loading...</div>
        ) : (
          <>
            {tab === 'inventory' && <ClaudeCodeAgents sessions={sessions} decisions={decisions} />}
            {tab === 'discovery' && <MCPDiscovery registry={registry} decisions={decisions} mcpDiscovery={mcpDiscovery} />}
            {tab === 'analytics' && <UsageAnalytics decisions={decisions} sessions={sessions} />}
            {tab === 'admin' && <AdminConfig />}
          </>
        )}
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />);
