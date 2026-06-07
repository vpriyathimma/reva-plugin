// ============================================================================
// Reva — Insights API  (src/api/insights.ts)
// ----------------------------------------------------------------------------
// A STANDALONE, READ-ONLY API surface for the internal product team. It mirrors
// every tile and section of the AI Coding Agents Governance "Insights" page and
// returns render-ready shapes so a product frontend can render verbatim.
//
// IMPORTANT: this module does not touch the demo dashboard's data flow. The
// dashboard keeps its own in-browser derivation; this is an additive layer that
// reuses the same in-memory stores (sessions, decisions, quarantine, blocks,
// trust, SVID) so the numbers always agree with the dashboard.
//
// Mount:  app.use('/api', insightsRouter)   // see src/index.ts
//
// Endpoints (all GET):
//   Tiles
//     /api/insights/agents
//     /api/insights/prompts-blocked
//     /api/insights/jit
//     /api/insights/quarantines
//     /api/insights/low-trust
//   Identities (filter-aware — drives both tile counts and the table)
//     /api/insights/identities?filter=all|prompts-blocked|jit|quarantined|low-trust
//   Sections
//     /api/insights/permit-deny?by=session|identity&range=<window>
//     /api/insights/high-deny
//     /api/insights/usage
//     /api/insights/summary           (everything in one payload — convenience)
//   Developer detail (two sub-sections behind the Identity / Session toggle)
//     /api/identities/:id/identity
//     /api/identities/:id/sessions
//     /api/identities/:id/jit
//   Intent profile
//     /api/intent-profile?trace=<traceId>   (or ?session=<id>&seq=<n>)
// ============================================================================

import { Router, Request, Response } from 'express';
import { sessionStore, decisionLog, EnrolledSession, DecisionLog } from '../connector/discovery/enroll';
import { listQuarantines, QuarantineRecord } from './quarantine';
import { getPersistentTrust, TRUST_BASELINE } from './intentClassifier';
import { listAllSVIDs } from './svid';
import { getSelectedApprover, getKnownApprovers } from './approverConfig';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────
const LOW_TRUST_THRESHOLD = 60;
const BLOCKED_INTENTS = new Set([
  'prompt_injection_in_read', 'blocked_by_claude', 'jailbreak_attempt', 'prompt_injection',
]);
const DENY_REASON_COLORS: Record<string, string> = {
  'Prompt Injection': '#DC2626',
  'Intent Drift':     '#F59E0B',
  'Low Trust':        '#7C3AED',
  'Quarantine':       '#0EA5E9',
  'Policy Denial':    '#64748B',
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — ported verbatim from the dashboard derivation so shapes/counts match
// ─────────────────────────────────────────────────────────────────────────────
function isRealUser(u: string): boolean {
  if (!u) return false;
  const x = String(u).trim().toLowerCase();
  if (!x || x.includes('$') || x === 'unknown' || x === 'developer') return false;
  if (x.startsWith('claude-code-hook') || x.startsWith('cowork-hook')) return false;
  if (x.includes('@reva.ai') && x.includes('hook')) return false;
  return true;
}
function principalOf(osUser: string): string { return 'Developer::"' + osUser + '"'; }
function userKey(email: string): string { return (email || '').includes('@') ? email.split('@')[0] : (email || ''); }

// Identity key — mirrors the dashboard's osUserOf(): prefer the developer's name,
// then the email local-part, then user_id. Keeps roster ids identical to the UI.
function osUserOf(sess: EnrolledSession): string {
  return (sess.developer_name && sess.developer_name.trim())
    || (sess.user_email ? sess.user_email.split('@')[0] : '')
    || sess.user_id || 'developer';
}

function relTime(iso?: string): string {
  if (!iso) return '';
  const ms = Date.now() - new Date(iso).getTime();
  const m = Math.floor(ms / 60000);
  if (m < 1) return 'now'; if (m < 60) return m + 'm';
  const h = Math.floor(m / 60); if (h < 24) return h + 'h'; return Math.floor(h / 24) + 'd';
}

function normTool(t?: string): string {
  const x = (t || '').toLowerCase();
  if (x.startsWith('mcp') || x.includes('__')) return 'MCP*';
  if (x.includes('read') || x === 'cat') return 'ReadFile';
  if (x.includes('bash') || x.includes('run')) return 'RunBash';
  if (x.includes('multiedit') || x.includes('edit')) return 'EditFile';
  if (x.includes('write')) return 'WriteFile';
  if (x.includes('agent') || x.includes('task') || x.includes('spawn')) return 'SpawnAgent';
  return t || 'Other';
}

function denyBucket(d: DecisionLog): string {
  const s = ((d.reason || '') + ' ' + (d.intent || '')).toLowerCase();
  if (s.includes('inject') || s.includes('jailbreak')) return 'Prompt Injection';
  if (s.includes('drift') || s.includes('scope')) return 'Intent Drift';
  if (s.includes('low trust') || s.includes('trust degraded') || s.includes('below threshold') ||
      (s.includes('trust') && (s.includes('≤') || s.includes('<=')))) return 'Low Trust';
  if (s.includes('surge') || s.includes('spawn') || s.includes('budget') || s.includes('denial rate') ||
      s.includes('blast radius') || s.includes('quarant') || s.includes('isolation') ||
      s.includes('on hold') || s.includes('paused') || s.includes('access is on hold')) return 'Quarantine';
  return 'Policy Denial';
}

function codingAgentLabel(ca: string): string {
  return ca === 'codex' ? 'Codex' : ca === 'kiro' ? 'Kiro' : 'Claude Code';
}

// A decision is a "prompt block" when it was not permitted AND its intent/reason
// places it in the injection/jailbreak/Claude-blocked family — the same family
// the donut's "Prompt Injection" bucket counts.
function isBlockedDecision(d: DecisionLog): boolean {
  if (d.effect === 'Permit') return false;
  if (d.intent && BLOCKED_INTENTS.has(d.intent)) return true;
  const s = ((d.reason || '') + ' ' + (d.intent || '')).toLowerCase();
  return s.includes('inject') || s.includes('jailbreak') || s.includes('blocked by claude');
}

// Coding agent for a decision: prefer the owning session's coding_agent; fall
// back to the `server` field the claude-code path stamps.
function decisionAgent(d: DecisionLog): string {
  const sess = sessionStore.get(d.session_id);
  if (sess && sess.coding_agent) return sess.coding_agent;
  if ((d.server || '').toLowerCase() === 'claude-code') return 'claude-code';
  return 'claude-code';
}

// ─────────────────────────────────────────────────────────────────────────────
// Roster — one row per (developer × coding-agent). Mirrors the dashboard's
// deriveAll() roster so the product API and the demo agree row-for-row.
// ─────────────────────────────────────────────────────────────────────────────
export interface RosterRow {
  id:            string;   // `Developer::"<user>"#<coding_agent>`  (URL-encode for path use)
  principal:     string;   // `Developer::"<user>"`
  codingAgent:   string;   // claude-code | codex | kiro
  codingAgentLabel: string;
  surface:       string;
  kind:          'dev';
  email:         string;
  owner:         string;
  model:         string;
  os:            string;
  sessions:      number;   // active (non-terminated) session count
  trust:         number;
  state:         'Active' | 'Quarantined';
  // security signals (per identity, aggregated from decisions)
  promptsBlocked: number;  // # blocked prompt decisions for this identity
  jitCount:       number;  // # short-lived creds issued to this identity
  jitActive:      number;
  quarantined:    boolean;
  lowTrust:       boolean;
  // identity fields
  svid:          string;
  svidFallback:  boolean;
  accountUuid:   string;
  orgUuid:       string;
  kiro: {
    accountType: string; email: string; region: string; startUrl: string; profileArn: string;
  } | null;
  // raw session ids backing this row (for /sessions and /jit joins)
  sessionIds:    string[];
}

function buildRoster() {
  const sessions = Array.from(sessionStore.values());
  const quarantines = listQuarantines();

  // group sessions by developer (skip placeholders)
  const byUser = new Map<string, EnrolledSession[]>();
  sessions.forEach((sess) => {
    const u = osUserOf(sess);
    if (!isRealUser(u)) return;
    if (!byUser.has(u)) byUser.set(u, []);
    byUser.get(u)!.push(sess);
  });

  // decisions per user
  const decByUser = new Map<string, DecisionLog[]>();
  decisionLog.forEach((d) => {
    const u = userKey(d.user_email || '');
    if (!isRealUser(u)) return;
    if (!decByUser.has(u)) decByUser.set(u, []);
    decByUser.get(u)!.push(d);
  });

  const quarantineFor = (u: string, sess: EnrolledSession): QuarantineRecord | null => {
    const cands = new Set([u, sess.user_email, sess.oauth_email,
      (sess.user_email || '').split('@')[0], (sess.oauth_email || '').split('@')[0]]
      .filter(Boolean).map((x) => String(x).toLowerCase()));
    return quarantines.find((q) => {
      const qu = String(q.osUser || '').toLowerCase();
      return cands.has(qu) || cands.has(qu.split('@')[0]);
    }) || null;
  };

  const svids = listAllSVIDs();
  const roster: RosterRow[] = [];

  for (const [u, allSessions] of byUser) {
    const byAgent = new Map<string, EnrolledSession[]>();
    allSessions.forEach((x) => {
      const ca = x.coding_agent || 'claude-code';
      if (!byAgent.has(ca)) byAgent.set(ca, []);
      byAgent.get(ca)!.push(x);
    });

    for (const [codingAgent, sList] of byAgent) {
      const latest = sList[sList.length - 1];
      const firstNonEmpty = (k: keyof EnrolledSession) => { for (const x of sList) { if (x[k]) return x[k] as string; } return ''; };
      const stableSpiffe = firstNonEmpty('spiffe_id');
      // Trust: the block-penalty store may be keyed by full email or local-part;
      // take the most-penalized across candidate keys (mirrors the dashboard).
      const trustKeys = [latest.user_email, u, firstNonEmpty('oauth_email')].filter(Boolean) as string[];
      let trust = TRUST_BASELINE;
      for (const k of trustKeys) trust = Math.min(trust, getPersistentTrust(k));
      const qRec = quarantineFor(u, latest);
      const isQ = !!qRec;

      // identity-level decisions for this user (block attribution scoped to this agent)
      const userDecs = decByUser.get(u) || [];
      const agentDecs = userDecs.filter((d) => decisionAgent(d) === codingAgent);
      const promptsBlocked = agentDecs.filter(isBlockedDecision).length;

      // JIT creds issued to this developer (matched by email)
      const email = (firstNonEmpty('oauth_email') || firstNonEmpty('user_email') || u) as string;
      const myJit = svids.filter((s) => sameEmail(s.developer_email, email) || sameEmail(s.developer_email, u));
      const jitActive = myJit.filter((s) => s.status === 'active').length;

      roster.push({
        id: principalOf(u) + '#' + codingAgent,
        principal: principalOf(u),
        codingAgent,
        codingAgentLabel: codingAgentLabel(codingAgent),
        surface: latest.surface || '',
        kind: 'dev',
        email,
        owner: u,
        model: latest.model || '—',
        os: latest.os_type || latest.remote_os || '—',
        sessions: sList.length,
        trust,
        state: isQ ? 'Quarantined' : 'Active',
        promptsBlocked,
        jitCount: myJit.length,
        jitActive,
        quarantined: isQ,
        lowTrust: trust <= LOW_TRUST_THRESHOLD,
        svid: stableSpiffe || ('agent-hash:' + (latest.session_id || '').slice(0, 8) + ' (fallback)'),
        svidFallback: !stableSpiffe,
        accountUuid: firstNonEmpty('account_uuid'),
        orgUuid: firstNonEmpty('org_uuid'),
        kiro: codingAgent === 'kiro' ? {
          accountType: firstNonEmpty('kiro_account_type'),
          email: firstNonEmpty('kiro_email'),
          region: firstNonEmpty('kiro_region'),
          startUrl: firstNonEmpty('kiro_start_url'),
          profileArn: firstNonEmpty('kiro_profile_arn'),
        } : null,
        sessionIds: sList.map((x) => x.session_id),
      });
    }
  }
  return roster;
}

function sameEmail(a?: string, b?: string): boolean {
  if (!a || !b) return false;
  return a.toLowerCase() === b.toLowerCase() || userKey(a).toLowerCase() === userKey(b).toLowerCase();
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity filters — the SINGLE source of truth shared by tile counts and table
// ─────────────────────────────────────────────────────────────────────────────
type FilterKey = 'all' | 'prompts-blocked' | 'jit' | 'quarantined' | 'low-trust';

function filterRoster(roster: RosterRow[], key: FilterKey): RosterRow[] {
  switch (key) {
    case 'prompts-blocked': return roster.filter((r) => r.promptsBlocked > 0);
    case 'jit':             return roster.filter((r) => r.jitCount > 0);
    case 'quarantined':     return roster.filter((r) => r.quarantined);
    case 'low-trust':       return roster.filter((r) => r.lowTrust);
    case 'all':
    default:                return roster;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tile derivations
// ─────────────────────────────────────────────────────────────────────────────
function tileAgents(roster: RosterRow[]) {
  return {
    tile: 'Agents',
    count: roster.length,
    filter: 'all',
  };
}

function tilePromptsBlocked(roster: RosterRow[], agentScope: string | null) {
  // Total across all blocked decisions, plus a per-agent breakdown.
  const byAgent: Record<string, number> = {};
  let total = 0;
  decisionLog.forEach((d) => {
    if (!isBlockedDecision(d)) return;
    if (!isRealUser(userKey(d.user_email || ''))) return;
    const ca = decisionAgent(d);
    if (agentScope && ca !== agentScope) return;
    byAgent[ca] = (byAgent[ca] || 0) + 1;
    total++;
  });
  return {
    tile: 'Prompts Blocked',
    count: total,
    byAgent,                            // { 'claude-code': n, codex: n, kiro: n }
    scope: agentScope || 'all',
    affectedIdentities: roster.filter((r) => r.promptsBlocked > 0).length,
    filter: 'prompts-blocked',
  };
}

function tileJit(roster: RosterRow[]) {
  const svids = listAllSVIDs();
  const active = svids.filter((s) => s.status === 'active').length;
  const expired = svids.filter((s) => s.status === 'expired').length;
  const revoked = svids.filter((s) => s.status === 'revoked').length;
  return {
    tile: 'JIT (Just-in-Time Access)',
    label: 'Short-lived credentials',
    count: svids.length,                // total issued (latest per developer×project)
    active,
    expired,
    revoked,
    recipients: roster.filter((r) => r.jitCount > 0).length,
    ttlMinutes: parseInt(process.env.SVID_TTL_MINUTES || '10', 10),
    filter: 'jit',
  };
}

function tileQuarantines() {
  const list = listQuarantines();
  const startToday = new Date(); startToday.setHours(0, 0, 0, 0);
  const newToday = list.filter((q) => q.since && new Date(q.since) >= startToday).length;
  return {
    tile: 'Active Quarantines',
    count: list.length,
    newToday,
    filter: 'quarantined',
  };
}

function tileLowTrust(roster: RosterRow[]) {
  return {
    tile: 'Low Trust (≤ 60)',
    threshold: LOW_TRUST_THRESHOLD,
    baseline: TRUST_BASELINE,
    count: roster.filter((r) => r.lowTrust).length,
    filter: 'low-trust',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Section derivations
// ─────────────────────────────────────────────────────────────────────────────
function sectionPermitDeny(by: string, range: string) {
  const decs = decisionLog;
  const permit = decs.filter((d) => d.effect === 'Permit').length;
  const deny = decs.filter((d) => d.effect !== 'Permit').length;
  const total = permit + deny;
  const permitPct = total ? Math.round((permit / total) * 100) : 100;
  const denyPct = 100 - permitPct;

  const reasonCounts: Record<string, number> = {
    'Prompt Injection': 0, 'Intent Drift': 0, 'Low Trust': 0, 'Quarantine': 0, 'Policy Denial': 0,
  };
  decs.filter((d) => d.effect !== 'Permit').forEach((d) => { reasonCounts[denyBucket(d)]++; });
  const denyTotal = deny || 1;
  const legend = Object.keys(reasonCounts).map((k) => ({
    label: k,
    value: Math.round((reasonCounts[k] / denyTotal) * 100),
    count: reasonCounts[k],
    color: DENY_REASON_COLORS[k],
  }));

  return {
    section: 'Permit / Deny Rate',
    by,                  // 'session' | 'identity' (pivot toggle; counts are decision-level today)
    range,               // requested window — note: in-memory store is not yet time-sliced
    permitPct, denyPct,
    permit, deny, total,
    legend,
  };
}

function sectionHighDeny(roster: RosterRow[]) {
  const decByUser = new Map<string, DecisionLog[]>();
  decisionLog.forEach((d) => {
    const u = userKey(d.user_email || '');
    if (!isRealUser(u)) return;
    if (!decByUser.has(u)) decByUser.set(u, []);
    decByUser.get(u)!.push(d);
  });
  const rows: any[] = [];
  for (const [u, ds] of decByUser) {
    const t = ds.length; if (!t) continue;
    const dn = ds.filter((d) => d.effect !== 'Permit').length;
    const rate = Math.round((dn / t) * 100);
    const r = roster.find((x) => x.owner === u);
    rows.push({
      id: u,
      principal: principalOf(u),
      model: (r && r.model) || '—',
      decisions: t,
      denials: dn,
      denyRate: rate,
      dir: rate >= 50 ? 'up' : 'down',
    });
  }
  rows.sort((a, b) => b.denyRate - a.denyRate);
  return { section: 'Identities with High Deny Rate', rows };
}

function sectionUsage() {
  const usageMap = new Map<string, { tool: string; n: number; permits: number }>();
  decisionLog.forEach((d) => {
    const t = normTool(d.tool);
    const e = usageMap.get(t) || { tool: t, n: 0, permits: 0 };
    e.n++; if (d.effect === 'Permit') e.permits++;
    usageMap.set(t, e);
  });
  const order = ['ReadFile', 'RunBash', 'EditFile', 'WriteFile', 'SpawnAgent', 'MCP*'];
  const rows = Array.from(usageMap.values())
    .map((u) => ({ tool: u.tool, count: u.n, permits: u.permits, permitPct: Math.round((u.permits / u.n) * 100) }))
    .sort((a, b) => (order.indexOf(a.tool) - order.indexOf(b.tool)) || (b.count - a.count));
  return { section: 'Usage by Tool', rows };
}

// ─────────────────────────────────────────────────────────────────────────────
// Developer detail
// ─────────────────────────────────────────────────────────────────────────────
function findRow(roster: RosterRow[], id: string): RosterRow | undefined {
  const decoded = decodeURIComponent(id);
  return roster.find((r) => r.id === decoded || r.id === id || r.principal === decoded);
}

function detailIdentity(row: RosterRow) {
  return {
    section: 'Developer Details · Identity',
    id: row.id,
    principal: row.principal,
    authenticatedAs: row.email,
    owner: row.owner,
    activeSessions: row.sessions,
    svid: row.svid,
    svidFallback: row.svidFallback,
    svidLabel: row.svidFallback ? 'Agent ID (SVID fallback)' : 'SPIFFE / SVID',
    codingAgent: row.codingAgent,
    codingAgentLabel: row.codingAgentLabel,
    surface: row.surface,
    trust: row.trust,
    state: row.state,
    // provider identity (one of the two will be populated)
    accountUuid: row.accountUuid,
    orgUuid: row.orgUuid,
    providerLabel: row.codingAgent === 'codex' ? 'OpenAI' : row.codingAgent === 'kiro' ? 'AWS' : 'Anthropic',
    kiro: row.kiro,    // null unless codingAgent === 'kiro'
  };
}

function detailSessions(row: RosterRow) {
  const out = row.sessionIds.map((sid) => {
    const sx = sessionStore.get(sid);
    if (!sx) return null;
    const connection = sx.entrypoint === 'remote' ? 'Browser' : (sx.connection_type === 'ssh' ? 'SSH' : 'Local');
    return {
      session_id: sx.session_id,
      status: 'active',                     // terminated state is tracked in sessionControl; see /api/session/terminated
      enrolledAt: sx.enrolled_at,
      enrolledRel: relTime(sx.enrolled_at),
      surface: sx.entrypoint || sx.surface || '',
      connection,
      os: sx.os_type || sx.remote_os || '',
      hostname: sx.hostname || '',
      model: sx.model || '',
      project: sx.project_name || '',
      branch: sx.git_branch || '',
      remote: sx.git_remote_url || '',
      sshIp: connection === 'SSH' ? (sx.ssh_client_ip || '') : '',
      jira: sx.jira_ticket_id || '',
      toolCount: sx.tool_count || 0,
      mcpServers: sx.mcp_servers_discovered || [],
    };
  }).filter(Boolean);
  return { section: 'Developer Details · Sessions', count: out.length, sessions: out };
}

function detailJit(row: RosterRow) {
  const svids = listAllSVIDs().filter((s) => sameEmail(s.developer_email, row.email) || sameEmail(s.developer_email, row.owner));
  const records = svids.map((s) => {
    // best-effort join to a backing session for surface/host/branch
    const sess = row.sessionIds.map((id) => sessionStore.get(id)).find((x) => x && (x.project_name === s.project || true));
    const expiresMs = new Date(s.expires_at).getTime();
    const state = s.status === 'active' && expiresMs < Date.now() ? 'expired' : s.status;
    return {
      id: s.id,
      recipient: s.developer_email,        // FOR WHOM JIT was issued
      principal: row.principal,
      spiffeId: s.spiffe_id,
      approver: s.issued_by,               // WHO approved / triggered issuance
      action: s.action,                    // WHICH action it authorizes (push|merge|pr_create|…)
      project: s.project,
      issuedAt: s.issued_at,
      expiresAt: s.expires_at,
      ttlSeconds: Math.max(0, Math.round((expiresMs - new Date(s.issued_at).getTime()) / 1000)),
      remainingSeconds: Math.max(0, Math.round((expiresMs - Date.now()) / 1000)),
      state,
      hasJwt: !!s.jwt,
      session: sess ? {                    // SESSION details
        session_id: sess.session_id,
        hostname: sess.hostname || '',
        branch: sess.git_branch || '',
        surface: sess.entrypoint || sess.surface || '',
        model: sess.model || '',
      } : null,
    };
  });
  return { section: 'Developer Details · JIT Ledger', count: records.length, records };
}

// ─────────────────────────────────────────────────────────────────────────────
// Intent profile — ports the dashboard's ipCompute() so the 5-axis radar can be
// rendered by the product. `trace` matches the dashboard's "trc_" + session-id
// slug, or pass ?session=<id>&seq=<n> to target a specific decision.
// ─────────────────────────────────────────────────────────────────────────────
const IP_MUT_CMD = /\b(rm|rmdir|mv|cp|mkdir|touch|truncate|dd|tee|chmod|chown|ln|shred)\b|\bsed\s+-i\b|\bgit\s+(commit|push|merge|rebase|reset|stash|tag|cherry-pick)\b|\b(npm|yarn|pnpm|pip|pip3|gem|cargo|go|apt|brew)\s+(install|add|remove|uninstall)\b/i;
const IP_READ_CMD = /\b(cat|head|tail|less|more|nl|strings|cut|sed|awk|od|xxd|grep|egrep|fgrep|rg)\b|\bgit\s+(show|diff|log|blame)\b/i;
const IP_ASKED_MUTATE = /\b(edit|update|modify|change|remove|delete|drop|write|creat|add|fix|refactor|renam|install|deploy|push|commit|merge|rewrite|patch|append)/i;
const IP_STOP = new Set(['the','all','files','file','review','summarize','summary','directory','directories','folder','folders','and','for','a','an','to','me','list','please','this','that','its','their','code','project','contents','what','how','each','relate','overall','key','tech','stack','note','obvious','issues','concerns','concise','complete','provide','users']);
function ipClamp(v: number) { return Math.max(0, Math.min(1, v)); }
function ipTokensOf(text: string) { return (String(text || '').toLowerCase().match(/[a-z0-9._-]+/g) || []).map((t) => t.replace(/^[._-]+|[._-]+$/g, '')).filter((t) => t.length > 2 && !IP_STOP.has(t)); }
function ipPathTail(p: string) {
  return String(p || '').split(/\s+/).filter((a) => a.includes('/')).map((seg) => {
    const s = seg.replace(/^[a-z]+:\/\//i, '').split('/').filter(Boolean);
    return s.slice(-2).join(' ');
  }).join(' ').toLowerCase();
}
function ipOutOfScope(pathOrCmd: string, declared: string) {
  const ask = ipTokensOf(declared); if (!ask.length) return false;
  const tail = ipPathTail(pathOrCmd); if (!tail) return false;
  return !ask.some((t) => tail.includes(t));
}
function ipSeverity(v: number) { return v >= 0.85 ? 'Critical' : v >= 0.6 ? 'High' : v >= 0.4 ? 'Medium' : 'Low'; }

function ipCompute(d: DecisionLog) {
  const ctx: any = d.cedar_context || {};
  const sc: any = d.scores || {};
  const oauth = ctx.oauth_email || (d as any).oauth_email || ctx.os_user || d.user_email || '';
  const git = ctx.git_email || (d as any).git_email || '';
  const assignee = ctx.jira_assignee_email || (d as any).jira_assignee_email || '';
  const action = d.cedar_action || d.tool || '—';
  const cr = ctx.command_risk || d.command_risk || '';
  const declared = ctx.declared_scope || ctx.initial_scope || (d as any).declared_scope || 'the requested task';
  const resource = d.cedar_resource || ctx.command || ctx.file_path || '';
  const cmd = ctx.command || (action === 'RunBash' ? resource : '');
  const zone = ctx.file_zone || d.file_zone || '';
  const trust = ctx.trust_score != null ? ctx.trust_score : (d.trust_score != null ? d.trust_score : 70);
  const driftScore = ctx.intent_drift_score != null ? ctx.intent_drift_score : (sc.intent_drift_score || 0);
  const drifted = !!ctx.is_intent_drift || driftScore > 0;

  const askedMutate = IP_ASKED_MUTATE.test(declared);
  const actionMutates = (action === 'EditFile' || action === 'WriteFile' || action === 'MCPWrite') || cr === 'destructive' || cr === 'restricted' || (action === 'RunBash' && IP_MUT_CMD.test(cmd));
  const isContentRead = action === 'ReadFile' || action === 'MCPRead' || (action === 'RunBash' && IP_READ_CMD.test(cmd) && !IP_MUT_CMD.test(cmd));
  const isFileOp = isContentRead || action === 'EditFile' || action === 'WriteFile';

  let actor = 0.05;
  if (git && oauth && git !== oauth) actor += 0.6;
  if (assignee && oauth && assignee !== oauth) actor += 0.3;
  if (trust < 50) actor += 0.1; if (trust < 20) actor += 0.15;
  actor = ipClamp(actor);

  let value = cr === 'destructive' ? 0.85 : cr === 'restricted' ? 0.5 : 0.12;
  if (action === 'EditFile' || action === 'WriteFile') value = Math.max(value, 0.6);
  if (action === 'MCPWrite' || action === 'MCPExecute') value = Math.max(value, 0.5);
  value += (ctx.escalation_score || 0) / 100 * 0.2 + (ctx.exfiltration_score || 0) / 100 * 0.2;
  value = ipClamp(value);

  let actionV: number;
  if (!askedMutate && actionMutates) actionV = cr === 'destructive' ? 0.85 : 0.6;
  else if (actionMutates) actionV = 0.35;
  else actionV = 0.1;
  actionV = ipClamp(actionV);

  let target = 0.08, outScope = false;
  if (isFileOp) {
    const z = zone === 'secrets' ? 0.9 : zone === 'config' ? 0.6 : zone === 'src' ? 0.3 : zone === 'docs' ? 0.22 : 0.16;
    outScope = ipOutOfScope(resource, declared);
    target = ipClamp(outScope ? 0.6 + z * 0.4 : z * 0.5);
  }

  const priors = String(ctx.prior_intents || '').split(/[,|]/).filter(Boolean).length;
  const scope = ipClamp(Math.max(driftScore / 100, target * 0.7, 0.08 + priors * 0.03));

  const axes = { Actor: actor, Target: target, Value: value, Action: actionV, Scope: scope };
  const arr = [actor, target, value, actionV, scope];
  const mx = Math.max(...arr), mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  const agg = ipClamp(0.62 * mx + 0.38 * mean);

  return {
    section: 'Intent Profile',
    trace: 'trc_' + (d.session_id || '').replace(/[^a-z0-9]/gi, '').slice(0, 8),
    sessionId: d.session_id,
    timestamp: d.timestamp,
    axes,
    aggregate: agg,
    severity: ipSeverity(agg),
    baseline: { Actor: 0.4, Target: 0.4, Value: 0.4, Action: 0.4, Scope: 0.4 },
    drifted, driftScore,
    idMismatch: (!!git && !!oauth && git !== oauth) || (!!assignee && !!oauth && assignee !== oauth),
    identity: { authenticated: oauth, git, jiraAssignee: assignee },
    action, commandRisk: cr, declaredScope: declared, resource, fileZone: zone, trust,
    flags: { askedMutate, actionMutates, isContentRead, isFileOp, outOfScope: outScope },
    effect: d.effect, reason: d.reason || '',
  };
}

function traceSlug(sessionId: string) {
  return 'trc_' + (sessionId || '').replace(/[^a-z0-9]/gi, '').slice(0, 8);
}

// ─────────────────────────────────────────────────────────────────────────────
// Router
// ─────────────────────────────────────────────────────────────────────────────
export const insightsRouter = Router();

// ---- Tiles ----
insightsRouter.get('/insights/agents', (_req, res) => {
  res.json(tileAgents(buildRoster()));
});

insightsRouter.get('/insights/prompts-blocked', (req, res) => {
  // ?scope=claude-code|codex|kiro|all   (default: claude-code, per product spec)
  const scopeRaw = String(req.query.scope || 'claude-code').toLowerCase();
  const scope = scopeRaw === 'all' ? null : scopeRaw;
  res.json(tilePromptsBlocked(buildRoster(), scope));
});

insightsRouter.get('/insights/jit', (_req, res) => {
  res.json(tileJit(buildRoster()));
});

insightsRouter.get('/insights/quarantines', (_req, res) => {
  res.json(tileQuarantines());
});

insightsRouter.get('/insights/low-trust', (_req, res) => {
  res.json(tileLowTrust(buildRoster()));
});

// ---- Identities (filter-aware) ----
insightsRouter.get('/insights/identities', (req, res) => {
  const filter = (String(req.query.filter || 'all').toLowerCase() as FilterKey);
  const valid: FilterKey[] = ['all', 'prompts-blocked', 'jit', 'quarantined', 'low-trust'];
  const key = valid.includes(filter) ? filter : 'all';
  const roster = buildRoster();
  const rows = filterRoster(roster, key);
  res.json({
    filter: key,
    count: rows.length,
    total: roster.length,
    identities: rows,
  });
});

// ---- Sections ----
insightsRouter.get('/insights/permit-deny', (req, res) => {
  const by = String(req.query.by || 'session').toLowerCase();
  const range = String(req.query.range || 'last-week');
  res.json(sectionPermitDeny(by, range));
});

insightsRouter.get('/insights/high-deny', (_req, res) => {
  res.json(sectionHighDeny(buildRoster()));
});

insightsRouter.get('/insights/usage', (_req, res) => {
  res.json(sectionUsage());
});

// ---- Summary (everything in one call — convenience for first paint) ----
insightsRouter.get('/insights/summary', (req, res) => {
  const roster = buildRoster();
  const scopeRaw = String(req.query.scope || 'claude-code').toLowerCase();
  const scope = scopeRaw === 'all' ? null : scopeRaw;
  res.json({
    workloadOwner: getKnownApprovers()[0] || '',
    tiles: {
      agents: tileAgents(roster),
      promptsBlocked: tilePromptsBlocked(roster, scope),
      jit: tileJit(roster),
      quarantines: tileQuarantines(),
      lowTrust: tileLowTrust(roster),
    },
    sections: {
      permitDeny: sectionPermitDeny('session', String(req.query.range || 'last-week')),
      highDeny: sectionHighDeny(roster),
      usage: sectionUsage(),
    },
    identities: roster,
    approver: { selected: getSelectedApprover(), known: getKnownApprovers() },
    generatedAt: new Date().toISOString(),
  });
});

// ---- Developer detail (two sub-sections + JIT ledger) ----
insightsRouter.get('/identities/:id/identity', (req, res) => {
  const row = findRow(buildRoster(), req.params.id);
  if (!row) return res.status(404).json({ error: 'identity not found', id: req.params.id });
  res.json(detailIdentity(row));
});

insightsRouter.get('/identities/:id/sessions', (req, res) => {
  const row = findRow(buildRoster(), req.params.id);
  if (!row) return res.status(404).json({ error: 'identity not found', id: req.params.id });
  res.json(detailSessions(row));
});

insightsRouter.get('/identities/:id/jit', (req, res) => {
  const row = findRow(buildRoster(), req.params.id);
  if (!row) return res.status(404).json({ error: 'identity not found', id: req.params.id });
  res.json(detailJit(row));
});

// ---- Intent profile ----
insightsRouter.get('/intent-profile', (req, res) => {
  const trace = req.query.trace ? String(req.query.trace) : '';
  const session = req.query.session ? String(req.query.session) : '';
  const seq = req.query.seq != null ? parseInt(String(req.query.seq), 10) : NaN;

  let target: DecisionLog | undefined;
  if (session) {
    const matches = decisionLog.filter((d) => d.session_id === session);
    target = !isNaN(seq) ? matches[seq] : matches[matches.length - 1];
  } else if (trace) {
    target = [...decisionLog].reverse().find((d) => traceSlug(d.session_id) === trace);
  } else {
    target = decisionLog[decisionLog.length - 1];
  }

  if (!target) return res.status(404).json({ error: 'no matching decision', trace, session });
  res.json(ipCompute(target));
});
