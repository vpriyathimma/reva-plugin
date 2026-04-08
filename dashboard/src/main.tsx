import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';

const API = '';

const COLORS: Record<string, string> = {
  critical: '#E24B4A',
  high:     '#EF9F27',
  medium:   '#378ADD',
  low:      '#1D9E75',
};

const BADGES: Record<string, string> = {
  critical: '#FCEBEB',
  high:     '#FAEEDA',
  medium:   '#E6F1FB',
  low:      '#E1F5EE',
};

function Badge({ level }: { level: string }) {
  return (
    <span style={{
      background:   BADGES[level] || '#F1EFE8',
      color:        COLORS[level] || '#444',
      padding:      '2px 10px',
      borderRadius: 12,
      fontSize:     12,
      fontWeight:   600,
      textTransform: 'uppercase',
      letterSpacing: 0.5,
    }}>{level}</span>
  );
}

function RiskBar({ summary }: { summary: any }) {
  const total = Object.values(summary).reduce((a: any, b: any) => a + b, 0) as number;
  if (!total) return null;
  return (
    <div style={{ display: 'flex', height: 6, borderRadius: 4, overflow: 'hidden', gap: 1, margin: '8px 0' }}>
      {['critical', 'high', 'medium', 'low'].map(level =>
        summary[level] ? (
          <div key={level} style={{
            flex:       summary[level],
            background: COLORS[level],
            title:      `${level}: ${summary[level]}`,
          }} />
        ) : null
      )}
    </div>
  );
}

function ServerCard({ server, expanded, onToggle }: any) {
  return (
    <div style={{
      background:   '#fff',
      border:       '1px solid #E8E7E0',
      borderRadius: 12,
      marginBottom: 16,
      overflow:     'hidden',
    }}>
      <div
        onClick={onToggle}
        style={{
          padding:    '16px 20px',
          cursor:     'pointer',
          display:    'flex',
          alignItems: 'center',
          gap:        12,
        }}
      >
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, fontSize: 15, color: '#2C2C2A' }}>
            {server.server_name}
          </div>
          <div style={{ fontSize: 12, color: '#888', marginTop: 2 }}>
            {server.server_type.toUpperCase()} · {server.tools.length} tools · {server.user}
          </div>
          <RiskBar summary={server.risk_summary} />
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {['critical', 'high', 'medium', 'low'].map(level =>
            server.risk_summary[level] ? (
              <span key={level} style={{
                background: COLORS[level],
                color:      '#fff',
                borderRadius: 10,
                padding:    '2px 8px',
                fontSize:   11,
                fontWeight: 600,
              }}>{level[0].toUpperCase()} {server.risk_summary[level]}</span>
            ) : null
          )}
        </div>
        <div style={{ color: '#888', fontSize: 18 }}>{expanded ? '▲' : '▼'}</div>
      </div>

      {expanded && (
        <div style={{ borderTop: '1px solid #F1EFE8', padding: '0 20px 16px' }}>
          {server.server_url && (
            <div style={{ fontSize: 11, color: '#888', padding: '8px 0', fontFamily: 'monospace' }}>
              {server.server_url}
            </div>
          )}
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #F1EFE8' }}>
                <th style={{ textAlign: 'left', padding: '8px 0', color: '#888', fontWeight: 500 }}>Tool</th>
                <th style={{ textAlign: 'left', padding: '8px 0', color: '#888', fontWeight: 500 }}>Sensitivity</th>
                <th style={{ textAlign: 'left', padding: '8px 0', color: '#888', fontWeight: 500 }}>Reason</th>
              </tr>
            </thead>
            <tbody>
              {server.tools.map((tool: any, i: number) => (
                <tr key={i} style={{ borderBottom: '1px solid #F9F8F5' }}>
                  <td style={{ padding: '8px 0', fontFamily: 'monospace', color: '#3C3489' }}>{tool.name}</td>
                  <td style={{ padding: '8px 0' }}><Badge level={tool.sensitivity} /></td>
                  <td style={{ padding: '8px 0', color: '#5F5E5A', fontSize: 12 }}>{tool.sensitivity_reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function App() {
  const [registry, setRegistry]   = useState<any[]>([]);
  const [sessions, setSessions]   = useState<any[]>([]);
  const [decisions, setDecisions] = useState<any[]>([]);
  const [expanded, setExpanded]   = useState<Set<string>>(new Set());
  const [tab, setTab]             = useState<'registry' | 'sessions' | 'decisions'>('registry');
  const [loading, setLoading]     = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const [reg, sess, dec] = await Promise.all([
          fetch(`${API}/api/registry`).then(r => r.json()),
          fetch(`${API}/api/sessions`).then(r => r.json()),
          fetch(`${API}/api/decisions`).then(r => r.json()),
        ]);
        setRegistry(reg.registry || []);
        setSessions(sess.sessions || []);
        setDecisions(dec.decisions || []);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  const toggleExpand = (name: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  };

  const totalTools    = registry.reduce((a, s) => a + s.tools.length, 0);
  const criticalCount = registry.reduce((a, s) => a + (s.risk_summary.critical || 0), 0);
  const highCount     = registry.reduce((a, s) => a + (s.risk_summary.high || 0), 0);

  const tabStyle = (active: boolean) => ({
    padding:      '8px 20px',
    borderRadius: 8,
    cursor:       'pointer',
    fontWeight:   active ? 600 : 400,
    background:   active ? '#EEEDFE' : 'transparent',
    color:        active ? '#534AB7' : '#5F5E5A',
    border:       'none',
    fontSize:     14,
  });

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', background: '#F9F8F5', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ background: '#26215C', padding: '0 32px', display: 'flex', alignItems: 'center', height: 56 }}>
        <span style={{ color: '#fff', fontWeight: 700, fontSize: 18, letterSpacing: -0.5 }}>Reva</span>
        <span style={{ color: '#AFA9EC', fontSize: 14, marginLeft: 8 }}>MCP Server Registry</span>
      </div>

      <div style={{ maxWidth: 1100, margin: '0 auto', padding: '32px 24px' }}>
        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 32 }}>
          {[
            { label: 'MCP Servers',    value: registry.length, color: '#534AB7' },
            { label: 'Tools Enrolled', value: totalTools,       color: '#0F6E56' },
            { label: 'Critical Tools', value: criticalCount,    color: '#A32D2D' },
            { label: 'High Risk Tools', value: highCount,       color: '#854F0B' },
          ].map(stat => (
            <div key={stat.label} style={{
              background: '#fff', borderRadius: 12,
              padding: '20px 24px', border: '1px solid #E8E7E0',
            }}>
              <div style={{ fontSize: 28, fontWeight: 700, color: stat.color }}>{stat.value}</div>
              <div style={{ fontSize: 13, color: '#888', marginTop: 4 }}>{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 4, marginBottom: 24, background: '#fff', borderRadius: 10, padding: 4, border: '1px solid #E8E7E0', width: 'fit-content' }}>
          {(['registry', 'sessions', 'decisions'] as const).map(t => (
            <button key={t} style={tabStyle(tab === t)} onClick={() => setTab(t)}>
              {t === 'registry' ? 'MCP Server Registry' : t === 'sessions' ? 'Active Sessions' : 'Decision Feed'}
            </button>
          ))}
        </div>

        {loading && <div style={{ color: '#888', padding: 32, textAlign: 'center' }}>Loading...</div>}

        {/* Registry Tab */}
        {!loading && tab === 'registry' && (
          <div>
            {registry.length === 0 && (
              <div style={{ background: '#fff', borderRadius: 12, padding: 48, textAlign: 'center', color: '#888', border: '1px solid #E8E7E0' }}>
                No MCP servers enrolled yet. Run a discovery call to populate the registry.
              </div>
            )}
            {registry.map(server => (
              <ServerCard
                key={server.server_name}
                server={server}
                expanded={expanded.has(server.server_name)}
                onToggle={() => toggleExpand(server.server_name)}
              />
            ))}
          </div>
        )}

        {/* Sessions Tab */}
        {!loading && tab === 'sessions' && (
          <div style={{ background: '#fff', borderRadius: 12, border: '1px solid #E8E7E0', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ background: '#F9F8F5', borderBottom: '1px solid #E8E7E0' }}>
                  {['Session ID', 'User', 'Enrolled At', 'Tools', 'Locked'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '12px 16px', color: '#5F5E5A', fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sessions.map((s, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid #F1EFE8' }}>
                    <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: 12 }}>{s.session_id}</td>
                    <td style={{ padding: '12px 16px' }}>{s.user_email}</td>
                    <td style={{ padding: '12px 16px', color: '#888' }}>{new Date(s.enrolled_at).toLocaleString()}</td>
                    <td style={{ padding: '12px 16px' }}>{s.tool_count}</td>
                    <td style={{ padding: '12px 16px' }}>{s.locked ? '🔒 Yes' : 'No'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Decisions Tab */}
        {!loading && tab === 'decisions' && (
          <div style={{ background: '#fff', borderRadius: 12, border: '1px solid #E8E7E0', overflow: 'hidden' }}>
            {decisions.length === 0 && (
              <div style={{ padding: 48, textAlign: 'center', color: '#888' }}>No decisions yet.</div>
            )}
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ background: '#F9F8F5', borderBottom: '1px solid #E8E7E0' }}>
                  {['Time', 'User', 'Tool', 'Sensitivity', 'Decision', 'Reason'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '12px 16px', color: '#5F5E5A', fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {decisions.map((d, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid #F1EFE8' }}>
                    <td style={{ padding: '12px 16px', color: '#888', fontSize: 11 }}>{new Date(d.timestamp).toLocaleTimeString()}</td>
                    <td style={{ padding: '12px 16px' }}>{d.user_email}</td>
                    <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: '#3C3489' }}>{d.tool}</td>
                    <td style={{ padding: '12px 16px' }}><Badge level={d.sensitivity} /></td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{ color: d.effect === 'Permit' ? '#0F6E56' : d.effect === 'Deny' ? '#A32D2D' : '#854F0B', fontWeight: 600 }}>
                        {d.effect}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px', color: '#5F5E5A' }}>{d.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />);
