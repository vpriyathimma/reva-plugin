import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';

const API = '';

const COLORS: Record<string, string> = {
  critical: '#E24B4A',
  high:     '#EF9F27',
  medium:   '#378ADD',
  low:      '#1D9E75',
  unknown:  '#888888',
};

const BADGES: Record<string, string> = {
  critical: '#FCEBEB',
  high:     '#FAEEDA',
  medium:   '#E6F1FB',
  low:      '#E1F5EE',
  unknown:  '#F1EFE8',
};

const INTENTS = ['read', 'write', 'modify', 'destructive', 'communicate', 'govern', 'exfiltrate'];
const SENSITIVITIES = ['low', 'medium', 'high', 'critical'];

function Badge({ level }: { level: string }) {
  return (
    <span style={{
      background:    BADGES[level] || '#F1EFE8',
      color:         COLORS[level] || '#444',
      padding:       '2px 10px',
      borderRadius:  12,
      fontSize:      12,
      fontWeight:    600,
      textTransform: 'uppercase',
      letterSpacing: 0.5,
    }}>{level}</span>
  );
}

function SourceBadge({ source }: { source: string }) {
  const colors: Record<string, { bg: string; color: string }> = {
    known:    { bg: '#E1F5EE', color: '#0F6E56' },
    metadata: { bg: '#E6F1FB', color: '#2563EB' },
    admin:    { bg: '#EDE9FE', color: '#534AB7' },
    auto:     { bg: '#F1EFE8', color: '#888' },
  };
  const c = colors[source] || colors.auto;
  return (
    <span style={{
      background:   c.bg,
      color:        c.color,
      padding:      '2px 8px',
      borderRadius: 8,
      fontSize:     11,
      fontWeight:   600,
    }}>{source}</span>
  );
}

function RiskBar({ summary }: { summary: any }) {
  const total = Object.values(summary).reduce((a: any, b: any) => a + b, 0) as number;
  if (!total) return null;
  return (
    <div style={{ display: 'flex', height: 6, borderRadius: 4, overflow: 'hidden', gap: 1, margin: '8px 0' }}>
      {['critical', 'high', 'medium', 'low'].map(level =>
        summary[level] ? (
          <div key={level} style={{ flex: summary[level], background: COLORS[level] }} />
        ) : null
      )}
    </div>
  );
}

function EditToolRow({ tool, serverUrl, onSave, onCancel }: any) {
  const [intent,      setIntent]      = useState(tool.intent?.[0] || 'read');
  const [sensitivity, setSensitivity] = useState(tool.sensitivity || 'medium');
  const [reason,      setReason]      = useState('');

  const save = async () => {
    await fetch(`${API}/api/pdp/intents`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        server_url:  serverUrl,
        tool_name:   tool.tool_name,
        intent:      [intent],
        sensitivity,
        reason:      reason || 'Admin override',
      }),
    });
    onSave({ ...tool, intent: [intent], sensitivity, source: 'admin', version: (tool.version || 1) + 1 });
  };

  return (
    <tr style={{ background: '#FAFAFE', borderBottom: '1px solid #E8E7E0' }}>
      <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontSize: 12, color: '#3C3489' }}>
        {tool.tool_name}
      </td>
      <td style={{ padding: '10px 12px' }}>
        <select
          value={intent}
          onChange={e => setIntent(e.target.value)}
          style={{ fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid #E8E7E0', background: '#fff' }}
        >
          {INTENTS.map(i => <option key={i} value={i}>{i}</option>)}
        </select>
      </td>
      <td style={{ padding: '10px 12px' }}>
        <select
          value={sensitivity}
          onChange={e => setSensitivity(e.target.value)}
          style={{ fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid #E8E7E0', background: '#fff' }}
        >
          {SENSITIVITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </td>
      <td style={{ padding: '10px 12px' }}>
        <input
          placeholder="Reason (optional)"
          value={reason}
          onChange={e => setReason(e.target.value)}
          style={{ fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid #E8E7E0', width: 160 }}
        />
      </td>
      <td style={{ padding: '10px 12px' }}>—</td>
      <td style={{ padding: '10px 12px' }}>
        <button onClick={save} style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, background: '#534AB7', color: '#fff', border: 'none', cursor: 'pointer', marginRight: 6 }}>
          Save
        </button>
        <button onClick={onCancel} style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, background: '#F1EFE8', color: '#444', border: 'none', cursor: 'pointer' }}>
          Cancel
        </button>
      </td>
    </tr>
  );
}

function AddToolRow({ serverUrl, onSave, onCancel }: any) {
  const [toolName,    setToolName]    = useState('');
  const [intent,      setIntent]      = useState('read');
  const [sensitivity, setSensitivity] = useState('medium');
  const [reason,      setReason]      = useState('');

  const save = async () => {
    if (!toolName.trim()) return;
    await fetch(`${API}/api/pdp/intents`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        server_url:  serverUrl,
        tool_name:   toolName.trim(),
        intent:      [intent],
        sensitivity,
        reason:      reason || 'Admin added',
      }),
    });
    onSave({ tool_name: toolName.trim(), intent: [intent], sensitivity, source: 'admin', version: 1 });
  };

  return (
    <tr style={{ background: '#F5F3FF', borderBottom: '1px solid #E8E7E0' }}>
      <td style={{ padding: '10px 12px' }}>
        <input
          placeholder="exact tool name"
          value={toolName}
          onChange={e => setToolName(e.target.value)}
          style={{ fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid #534AB7', fontFamily: 'monospace', width: 180 }}
        />
      </td>
      <td style={{ padding: '10px 12px' }}>
        <select value={intent} onChange={e => setIntent(e.target.value)}
          style={{ fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid #E8E7E0', background: '#fff' }}>
          {INTENTS.map(i => <option key={i} value={i}>{i}</option>)}
        </select>
      </td>
      <td style={{ padding: '10px 12px' }}>
        <select value={sensitivity} onChange={e => setSensitivity(e.target.value)}
          style={{ fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid #E8E7E0', background: '#fff' }}>
          {SENSITIVITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </td>
      <td style={{ padding: '10px 12px' }}>
        <input placeholder="Reason" value={reason} onChange={e => setReason(e.target.value)}
          style={{ fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid #E8E7E0', width: 160 }} />
      </td>
      <td style={{ padding: '10px 12px' }}>—</td>
      <td style={{ padding: '10px 12px' }}>
        <button onClick={save} style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, background: '#0F6E56', color: '#fff', border: 'none', cursor: 'pointer', marginRight: 6 }}>
          Add
        </button>
        <button onClick={onCancel} style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, background: '#F1EFE8', color: '#444', border: 'none', cursor: 'pointer' }}>
          Cancel
        </button>
      </td>
    </tr>
  );
}

function ToolRegistry({ serverUrl, serverName }: { serverUrl: string; serverName: string }) {
  const [tools,     setTools]     = useState<any[]>([]);
  const [version,   setVersion]   = useState(1);
  const [history,   setHistory]   = useState<any[]>([]);
  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const [addingNew,  setAddingNew]  = useState(false);
  const [loading,    setLoading]    = useState(true);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    fetch(`${API}/api/registry/tools`)
      .then(r => r.json())
      .then(data => {
        const match = data.servers?.find((s: any) =>
          serverUrl?.includes(s.server_url) || s.server_url?.includes(serverUrl) || s.server_name === serverName
        );
        if (match) {
          setTools(match.tools || []);
          setVersion(match.version || 1);
          setHistory(match.history || []);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [serverUrl, serverName]);

  const handleSave = (updatedTool: any, idx: number) => {
    const next = [...tools];
    next[idx]  = updatedTool;
    setTools(next);
    setVersion(v => v + 1);
    setHistory(h => [...h, { v: version + 1, by: 'admin', at: new Date().toISOString(), reason: 'Updated via UI' }]);
    setEditingIdx(null);
  };

  const handleAdd = (newTool: any) => {
    setTools(t => [...t, newTool]);
    setVersion(v => v + 1);
    setAddingNew(false);
  };

  if (loading) return <div style={{ padding: 16, color: '#888', fontSize: 13 }}>Loading tool registry...</div>;

  return (
    <div style={{ borderTop: '1px solid #EEEDFE', padding: '12px 0 0 0' }}>
      {/* Tool Registry header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 4px 10px 4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: '#534AB7' }}>Tool Registry</span>
          <span style={{ fontSize: 11, color: '#888', background: '#F1EFE8', padding: '2px 8px', borderRadius: 8 }}>
            v{version}
          </span>
          {history.length > 0 && (
            <button
              onClick={() => setShowHistory(!showHistory)}
              style={{ fontSize: 11, color: '#534AB7', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}
            >
              {showHistory ? 'Hide history' : `History (${history.length})`}
            </button>
          )}
        </div>
        <button
          onClick={() => { setAddingNew(true); setEditingIdx(null); }}
          style={{ fontSize: 11, padding: '4px 12px', borderRadius: 6, background: '#534AB7', color: '#fff', border: 'none', cursor: 'pointer' }}
        >
          + Add Tool
        </button>
      </div>

      {/* Version history */}
      {showHistory && history.length > 0 && (
        <div style={{ background: '#F9F8F5', borderRadius: 8, padding: 10, marginBottom: 10, fontSize: 11, color: '#5F5E5A' }}>
          {[...history].reverse().map((h, i) => (
            <div key={i} style={{ padding: '3px 0', borderBottom: i < history.length - 1 ? '1px solid #E8E7E0' : 'none' }}>
              <span style={{ color: '#534AB7', fontWeight: 600 }}>v{h.v}</span>
              {' '}{h.reason}{' · '}{h.by}{' · '}{new Date(h.at).toLocaleString()}
            </div>
          ))}
        </div>
      )}

      {/* Tools not in registry notice */}
      {tools.length === 0 && !addingNew && (
        <div style={{ padding: '16px 4px', color: '#888', fontSize: 13 }}>
          Tools unidentified — add them manually using Tool Registry.
        </div>
      )}

      {/* Tool table */}
      {(tools.length > 0 || addingNew) && (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: '#F9F8F5', borderBottom: '1px solid #E8E7E0' }}>
              {['Tool Name', 'Intent', 'Sensitivity', 'Reason', 'Source / Ver', 'Actions'].map(h => (
                <th key={h} style={{ textAlign: 'left', padding: '8px 12px', color: '#888', fontWeight: 500, fontSize: 11 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {addingNew && (
              <AddToolRow
                serverUrl={serverUrl}
                onSave={handleAdd}
                onCancel={() => setAddingNew(false)}
              />
            )}
            {tools.map((tool, idx) =>
              editingIdx === idx ? (
                <EditToolRow
                  key={idx}
                  tool={tool}
                  serverUrl={serverUrl}
                  onSave={(updated: any) => handleSave(updated, idx)}
                  onCancel={() => setEditingIdx(null)}
                />
              ) : (
                <tr key={idx} style={{ borderBottom: '1px solid #F1EFE8' }}>
                  <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#3C3489', fontSize: 12 }}>
                    {tool.tool_name}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{ fontSize: 12, color: '#534AB7', fontWeight: 500 }}>
                      {Array.isArray(tool.intent) ? tool.intent.join(', ') : tool.intent}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <Badge level={tool.sensitivity} />
                  </td>
                  <td style={{ padding: '8px 12px', color: '#888', fontSize: 11 }}>—</td>
                  <td style={{ padding: '8px 12px' }}>
                    <SourceBadge source={tool.source} />
                    <span style={{ marginLeft: 6, fontSize: 11, color: '#888' }}>v{tool.version}</span>
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <button
                      onClick={() => { setEditingIdx(idx); setAddingNew(false); }}
                      style={{ fontSize: 11, padding: '3px 10px', borderRadius: 6, background: '#F1EFE8', color: '#534AB7', border: '1px solid #E8E7E0', cursor: 'pointer' }}
                    >
                      Edit
                    </button>
                  </td>
                </tr>
              )
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}

function ServerCard({ server, expanded, onToggle }: any) {
  const [activeTab, setActiveTab] = useState<'tools' | 'registry'>('tools');

  const tabStyle = (active: boolean) => ({
    padding:    '6px 14px',
    borderRadius: 6,
    cursor:     'pointer',
    fontWeight: active ? 600 : 400,
    background: active ? '#EEEDFE' : 'transparent',
    color:      active ? '#534AB7' : '#888',
    border:     'none',
    fontSize:   12,
  });

  return (
    <div style={{ background: '#fff', border: '1px solid #E8E7E0', borderRadius: 12, marginBottom: 16, overflow: 'hidden' }}>
      <div onClick={onToggle} style={{ padding: '16px 20px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, fontSize: 15, color: '#2C2C2A' }}>{server.server_name}</div>
          <div style={{ fontSize: 12, color: '#888', marginTop: 2 }}>
            {server.server_type.toUpperCase()} · {server.tools.length} tools · {server.user}
          </div>
          <RiskBar summary={server.risk_summary} />
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {['critical', 'high', 'medium', 'low'].map(level =>
            server.risk_summary[level] ? (
              <span key={level} style={{ background: COLORS[level], color: '#fff', borderRadius: 10, padding: '2px 8px', fontSize: 11, fontWeight: 600 }}>
                {level[0].toUpperCase()} {server.risk_summary[level]}
              </span>
            ) : null
          )}
        </div>
        <div style={{ color: '#888', fontSize: 18 }}>{expanded ? '▲' : '▼'}</div>
      </div>

      {expanded && (
        <div style={{ borderTop: '1px solid #F1EFE8', padding: '12px 20px 16px' }}>
          {server.server_url && (
            <div style={{ fontSize: 11, color: '#888', paddingBottom: 10, fontFamily: 'monospace' }}>
              {server.server_url}
            </div>
          )}

          {/* Sub-tabs */}
          <div style={{ display: 'flex', gap: 4, marginBottom: 14, background: '#F9F8F5', borderRadius: 8, padding: 3, width: 'fit-content' }}>
            <button style={tabStyle(activeTab === 'tools')}    onClick={() => setActiveTab('tools')}>Tools</button>
            <button style={tabStyle(activeTab === 'registry')} onClick={() => setActiveTab('registry')}>Tool Registry</button>
          </div>

          {/* Tools tab */}
          {activeTab === 'tools' && (
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
          )}

          {/* Tool Registry tab */}
          {activeTab === 'registry' && (
            <ToolRegistry serverUrl={server.server_url} serverName={server.server_name} />
          )}
        </div>
      )}
    </div>
  );
}

function App() {
  const [registry,  setRegistry]  = useState<any[]>([]);
  const [sessions,  setSessions]  = useState<any[]>([]);
  const [decisions, setDecisions] = useState<any[]>([]);
  const [expanded,  setExpanded]  = useState<Set<string>>(new Set());
  const [tab,       setTab]       = useState<'registry' | 'sessions' | 'decisions'>('registry');
  const [loading,   setLoading]   = useState(true);

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

  const toggleExpand = (name: string) =>
    setExpanded(prev => { const n = new Set(prev); n.has(name) ? n.delete(name) : n.add(name); return n; });

  const totalTools    = registry.reduce((a, s) => a + s.tools.length, 0);
  const criticalCount = registry.reduce((a, s) => a + (s.risk_summary.critical || 0), 0);
  const highCount     = registry.reduce((a, s) => a + (s.risk_summary.high || 0), 0);

  const tabStyle = (active: boolean) => ({
    padding: '8px 20px', borderRadius: 8, cursor: 'pointer',
    fontWeight: active ? 600 : 400, background: active ? '#EEEDFE' : 'transparent',
    color: active ? '#534AB7' : '#5F5E5A', border: 'none', fontSize: 14,
  });

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', background: '#F9F8F5', minHeight: '100vh' }}>
      <div style={{ background: '#26215C', padding: '0 32px', display: 'flex', alignItems: 'center', height: 56 }}>
        <span style={{ color: '#fff', fontWeight: 700, fontSize: 18, letterSpacing: -0.5 }}>Reva</span>
        <span style={{ color: '#AFA9EC', fontSize: 14, marginLeft: 8 }}>MCP Server Registry</span>
      </div>

      <div style={{ maxWidth: 1100, margin: '0 auto', padding: '32px 24px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 32 }}>
          {[
            { label: 'MCP Servers',    value: registry.length, color: '#534AB7' },
            { label: 'Tools Enrolled', value: totalTools,       color: '#0F6E56' },
            { label: 'Critical Tools', value: criticalCount,    color: '#A32D2D' },
            { label: 'High Risk Tools', value: highCount,       color: '#854F0B' },
          ].map(stat => (
            <div key={stat.label} style={{ background: '#fff', borderRadius: 12, padding: '20px 24px', border: '1px solid #E8E7E0' }}>
              <div style={{ fontSize: 28, fontWeight: 700, color: stat.color }}>{stat.value}</div>
              <div style={{ fontSize: 13, color: '#888', marginTop: 4 }}>{stat.label}</div>
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', gap: 4, marginBottom: 24, background: '#fff', borderRadius: 10, padding: 4, border: '1px solid #E8E7E0', width: 'fit-content' }}>
          {(['registry', 'sessions', 'decisions'] as const).map(t => (
            <button key={t} style={tabStyle(tab === t)} onClick={() => setTab(t)}>
              {t === 'registry' ? 'MCP Server Registry' : t === 'sessions' ? 'Active Sessions' : 'Decision Feed'}
            </button>
          ))}
        </div>

        {loading && <div style={{ color: '#888', padding: 32, textAlign: 'center' }}>Loading...</div>}

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
