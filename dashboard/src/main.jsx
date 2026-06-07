// Reva — AI Coding Agents Governance Console
// Design prototype ported into the Vite build, verbatim, with a live data layer.
import React from 'react';
import ReactDOM from 'react-dom/client';
import './styles.css';
import './aai.css';


/* ===================== reva-data.js (live data layer) ===================== */
/* ============================================================
   Reva live data layer — fetches the plugin's /api/* endpoints,
   subscribes to /api/stream (SSE) for on-the-fly updates, and
   derives the exact shapes the design components expect. The UI
   is byte-for-byte the design; only the numbers come from here.
   ============================================================ */

const WORKLOAD_OWNER = "Patrick Fuller";
const COVERAGE_TOTAL = 50; // hardcoded denominator until Anthropic Analytics is wired

// ---- external store (module-scoped; everything shares one scope) ----
const RevaStore = {
  state: {
    loading: true,
    sessions: [], decisions: [], quarantine: { quarantined: [], policies: [], capped_sessions: [], spawn_limit: 5 },
    trust: {}, security: null, hitl: null, commands: { safe: [], restricted: [], destructive: [] }, filezones: [], mcp: [], terminated: [], approvers: [], approverSelected: "", policySets: [], svids: [],
  },
  subs: new Set(),
  set(patch) { this.state = { ...this.state, ...patch }; this.subs.forEach((f) => f()); },
  sub(fn) { this.subs.add(fn); return () => this.subs.delete(fn); },
};

async function jget(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(path + " " + r.status);
  return r.json();
}

let _refetching = false;
async function revaRefetch() {
  if (_refetching) return; _refetching = true;
  try {
    const [sess, dec, q, tr, term, svid] = await Promise.all([
      jget("/api/sessions").catch(() => ({ sessions: [] })),
      jget("/api/decisions").catch(() => ({ decisions: [] })),
      jget("/api/quarantine").catch(() => ({ quarantined: [], policies: [], capped_sessions: [], spawn_limit: 5 })),
      jget("/api/trust").catch(() => ({ trust: {} })),
      jget("/api/session/terminated").catch(() => ({ terminated: [] })),
      jget("/api/svid").catch(() => ({ svids: [] })),
    ]);
    RevaStore.set({
      loading: false,
      sessions: sess.sessions || [],
      decisions: dec.decisions || [],
      quarantine: q,
      trust: tr.trust || {},
      terminated: term.terminated || [],
      svids: svid.svids || [],
    });
  } finally { _refetching = false; }
}

async function revaLoadConfigs() {
  const [sec, hitl, cmd, fz, mcp, appr, psets] = await Promise.all([
    jget("/api/config/security").catch(() => null),
    jget("/api/config/hitl").catch(() => null),
    jget("/api/config/commands").catch(() => ({ rules: [] })),
    jget("/api/config/filezones").catch(() => ({ rules: [] })),
    jget("/api/mcp-discovery").catch(() => ({ servers: [] })),
    jget("/api/config/approvers").catch(() => ({ approvers: [], selected: "" })),
    jget("/api/config/policy-sets").catch(() => ({ sets: [] })),
  ]);
  RevaStore.set({ security: sec, hitl, commands: cmd || { safe: [], restricted: [], destructive: [] }, filezones: (fz && fz.zones) || [], mcp: mcp.servers || [], approvers: appr.approvers || [], approverSelected: appr.selected || "", policySets: (psets && psets.sets) || [] });
}

let _started = false;
function revaStart() {
  if (_started) return; _started = true;
  revaRefetch(); revaLoadConfigs();
  // SSE — on-the-fly updates, no polling
  try {
    const es = new EventSource("/api/stream");
    let t = null;
    const debounced = () => { clearTimeout(t); t = setTimeout(revaRefetch, 300); };
    es.onmessage = debounced;
    es.addEventListener("hello", () => {});
    es.onerror = () => { /* EventSource auto-reconnects */ };
  } catch { /* SSE unsupported — fall back to interval */ }
  // safety-net poll (covers SSE drop on proxies)
  setInterval(revaRefetch, 15000);
}

// Session key matches the server's terminate key: "<oauth_email|user_email>::<hostname>".
function sessionTermKey(sess) {
  return `${sess.oauth_email || sess.user_email}::${sess.hostname || "unknown"}`;
}
async function revaTerminateSession(key, terminate) {
  try {
    await fetch(terminate ? "/api/session/terminate" : "/api/session/restore", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key }),
    });
    await revaRefetch();
  } catch (e) {}
}

// React subscription hook
function useReva() {
  const [, force] = React.useReducer((x) => x + 1, 0);
  React.useEffect(() => { revaStart(); return RevaStore.sub(force); }, []);
  const s = RevaStore.state;
  return React.useMemo(() => deriveAll(s), [s]);
}

// ---- helpers ----
function osUserOf(sess) {
  return (sess.developer_name && sess.developer_name.trim())
    || (sess.user_email ? sess.user_email.split("@")[0] : "")
    || sess.user_id || "developer";
}
// Reject unresolved/placeholder principals (e.g. literal "$USER", hook service
// accounts, empty/unknown) so they never surface as governed identities.
function isRealUser(u) {
  if (!u) return false;
  const x = String(u).trim().toLowerCase();
  if (!x || x.includes("$") || x === "unknown" || x === "developer") return false;
  if (x.startsWith("claude-code-hook") || x.startsWith("cowork-hook")) return false;
  if (x.includes("@reva.ai") && x.includes("hook")) return false;
  return true;
}
function principalOf(osUser) { return 'Developer::"' + osUser + '"'; }
function relTime(iso) {
  if (!iso) return "";
  const ms = Date.now() - new Date(iso).getTime();
  const m = Math.floor(ms / 60000);
  if (m < 1) return "now"; if (m < 60) return m + "m";
  const h = Math.floor(m / 60); if (h < 24) return h + "h"; return Math.floor(h / 24) + "d";
}
function denyBucket(d) {
  const s = ((d.reason || "") + " " + (d.intent || "")).toLowerCase();
  if (s.includes("inject") || s.includes("jailbreak")) return "Prompt Injection";
  if (s.includes("drift") || s.includes("scope")) return "Intent Drift";
  if (s.includes("low trust") || s.includes("trust degraded") || s.includes("below threshold") || (s.includes("trust") && (s.includes("≤") || s.includes("<=")))) return "Low Trust";
  // Only denials that came from an actual isolation policy count as Quarantine.
  if (s.includes("surge") || s.includes("spawn") || s.includes("budget") || s.includes("denial rate")
    || s.includes("blast radius") || s.includes("quarant") || s.includes("isolation")
    || s.includes("on hold") || s.includes("paused") || s.includes("access is on hold")) return "Quarantine";
  return "Policy Denial";
}
function normTool(t) {
  const x = (t || "").toLowerCase();
  if (x.startsWith("mcp") || x.includes("__")) return "MCP*";
  if (x.includes("read") || x === "cat") return "ReadFile";
  if (x.includes("bash") || x.includes("run")) return "RunBash";
  if (x.includes("multiedit") || x.includes("edit")) return "EditFile";
  if (x.includes("write")) return "WriteFile";
  if (x.includes("agent") || x.includes("task") || x.includes("spawn")) return "SpawnAgent";
  return t || "Other";
}

// Blocked-prompt detection — same family the donut's "Prompt Injection" bucket
// counts: not permitted AND injection/jailbreak/Claude-blocked intent.
const BLOCKED_INTENTS = new Set(["prompt_injection_in_read", "blocked_by_claude", "jailbreak_attempt", "prompt_injection"]);
function isBlockedDecision(d) {
  if (d.effect === "Permit") return false;
  if (d.intent && BLOCKED_INTENTS.has(d.intent)) return true;
  const s = ((d.reason || "") + " " + (d.intent || "")).toLowerCase();
  return s.includes("inject") || s.includes("jailbreak") || s.includes("blocked by claude");
}
function decisionAgentOf(d, sessById) {
  const sess = sessById.get(d.session_id);
  if (sess && sess.coding_agent) return sess.coding_agent;
  if ((d.server || "").toLowerCase() === "claude-code") return "claude-code";
  return "claude-code";
}
function sameEmailJs(a, b) {
  if (!a || !b) return false;
  const k = (x) => (x.includes("@") ? x.split("@")[0] : x).toLowerCase();
  return a.toLowerCase() === b.toLowerCase() || k(a) === k(b);
}

// ---- derivations (produce the design's exact shapes) ----
function deriveAll(s) {
  const qList = s.quarantine.quarantined || [];
  const cappedSessions = new Set(s.quarantine.capped_sessions || []);
  const termIds = new Set(s.terminated || []);  // terminated session_ids (per-session kill switch)
  // Match a quarantine record against any of a developer's identity forms.
  const quarantineFor = (u, sess) => {
    const cands = new Set([u, sess.user_email, sess.oauth_email,
      (sess.user_email || "").split("@")[0], (sess.oauth_email || "").split("@")[0]]
      .filter(Boolean).map((x) => String(x).toLowerCase()));
    return qList.find((q) => {
      const qu = String(q.osUser || "").toLowerCase();
      return cands.has(qu) || cands.has(qu.split("@")[0]);
    }) || null;
  };

  // group sessions by developer (skip placeholder/unresolved principals)
  const byUser = new Map();
  (s.sessions || []).forEach((sess) => {
    const u = osUserOf(sess);
    if (!isRealUser(u)) return;
    if (!byUser.has(u)) byUser.set(u, []);
    byUser.get(u).push(sess);
  });

  // session lookup by id — used to attribute a decision to its coding agent
  const sessById = new Map();
  (s.sessions || []).forEach((sess) => { if (sess.session_id) sessById.set(sess.session_id, sess); });
  const svids = s.svids || [];

  // recent decisions per user (skip placeholders)
  const decByUser = new Map();
  (s.decisions || []).forEach((d) => {
    const u = (d.user_email || "").includes("@") ? d.user_email.split("@")[0] : (d.user_email || "");
    if (!isRealUser(u)) return;
    if (!decByUser.has(u)) decByUser.set(u, []);
    decByUser.get(u).push(d);
  });

  const roster = [];
  for (const [u, allSessions] of byUser) {
   // One roster row per (developer, coding agent): the same developer appears
   // twice when they use both Claude Code and Codex.
   const byAgent = new Map();
   allSessions.forEach((x) => { const ca = x.coding_agent || "claude-code"; if (!byAgent.has(ca)) byAgent.set(ca, []); byAgent.get(ca).push(x); });
   for (const [codingAgent, sessions] of byAgent) {
    const latest = sessions[sessions.length - 1];
    // Identity fields are developer-level: source from the first session that has them so they
    // stay stable and never blank/flip as new sessions arrive from other surfaces.
    const firstNonEmpty = (k) => { for (const x of sessions) { if (x[k]) return x[k]; } return ""; };
    const stableSpiffe = firstNonEmpty("spiffe_id");  // SPIFFE/SVID: once issued, stays static for the lifecycle
    const trust = (s.trust[u] && s.trust[u].trust != null) ? s.trust[u].trust
      : (s.trust[latest.user_email] && s.trust[latest.user_email].trust != null) ? s.trust[latest.user_email].trust : 70;
    const qRec = quarantineFor(u, latest);
    const isQ = !!qRec;
    const capped = sessions.some((x) => cappedSessions.has(x.session_id));
    const state = isQ ? "Quarantined" : capped ? "Spawn-capped" : "Active";
    const spawnUsed = (decByUser.get(u) || []).filter((d) => normTool(d.tool) === "SpawnAgent" && d.effect === "Permit").length;
    const recent = (decByUser.get(u) || []).slice(0, 3).map((d) => ({ t: relTime(d.timestamp), a: normTool(d.tool), e: d.effect, r: d.reason || "" }));
    const tools = Array.from(new Set((latest.tools || []).map((t) => t.tool_name || t.name).filter(Boolean))).slice(0, 6);
    // Security signals for the new Insights tiles (per identity, scoped to this coding agent).
    // Attribute by session_id: each decision carries one, and these sessions belong
    // to exactly this (developer × coding-agent) row — immune to email/name key drift.
    const mySessIds = new Set(sessions.map((x) => x.session_id).filter(Boolean));
    const agentDecs = (s.decisions || []).filter((d) => mySessIds.has(d.session_id));
    const promptsBlocked = agentDecs.filter(isBlockedDecision).length;
    const myEmail = firstNonEmpty("oauth_email") || firstNonEmpty("user_email") || u;
    const jit = svids
      .filter((sv) => sameEmailJs(sv.developer_email, myEmail) || sameEmailJs(sv.developer_email, u))
      .map((sv) => ({
        id: sv.id, recipient: sv.developer_email, approver: sv.issued_by, action: sv.action,
        project: sv.project, issuedAt: sv.issued_at, expiresAt: sv.expires_at,
        state: sv.status === "active" && new Date(sv.expires_at).getTime() < Date.now() ? "expired" : sv.status,
        spiffeId: sv.spiffe_id, hasJwt: !!sv.jwt,
      }));
    const jitActive = jit.filter((j) => j.state === "active").length;
    roster.push({
      id: principalOf(u) + "#" + codingAgent, principal: principalOf(u), codingAgent, surface: latest.surface || "", kind: "dev",
      email: firstNonEmpty("oauth_email") || firstNonEmpty("user_email") || u,
      model: latest.model || "—",
      os: latest.os_type || latest.remote_os || "—",
      sessions: sessions.filter((x) => !termIds.has(x.session_id)).length, trust, state, owner: u,
      promptsBlocked, jit, jitCount: jit.length, jitActive,
      quarantine: qRec ? { osUser: qRec.osUser, policyId: qRec.policyId, policyName: qRec.policyName, resolution: qRec.resolution, message: qRec.message, status: qRec.status, since: qRec.since } : null,
      svid: stableSpiffe || ("agent-hash:" + (latest.session_id || "").slice(0, 8) + " (fallback)"),
      svidFallback: !stableSpiffe,
      // developer-detail fields
      hostname: latest.hostname || "—",
      gitBranch: latest.git_branch || "",
      gitRemote: latest.git_remote_url || "",
      project: latest.project_name || "",
      connectionType: latest.connection_type || "local",
      sshClientIp: latest.ssh_client_ip || "",
      accountUuid: firstNonEmpty("account_uuid"),
      orgUuid: firstNonEmpty("org_uuid"),
      kiroAccountType: firstNonEmpty("kiro_account_type"),
      kiroEmail: firstNonEmpty("kiro_email"),
      kiroRegion: firstNonEmpty("kiro_region"),
      kiroStartUrl: firstNonEmpty("kiro_start_url"),
      kiroProfileArn: firstNonEmpty("kiro_profile_arn"),
      jiraTicket: latest.jira_ticket_id || "",
      enrolledAt: latest.enrolled_at || "",
      sessionsList: sessions,
      budget: { used: Math.min(spawnUsed, 5), max: 5, note: state === "Spawn-capped" ? "budget reached this session" : (trust <= 60 ? "blocked — trust " + trust + " ≤ 60" : "") },
      tools: tools.length ? tools : ["ReadFile", "EditFile", "RunBash", "WriteFile"],
      mcp: (latest.mcp_servers_discovered || []).slice(0, 6),
      gh: "brokered",
      decisions: recent.length ? recent : [{ t: "", a: "—", e: "Permit", r: "No recent decisions" }],
    });
   }
  }

  // KPIs
  const governed = byUser.size;
  const startToday = new Date(); startToday.setHours(0, 0, 0, 0);
  const newQuarantinesToday = (s.quarantine.quarantined || []).filter((q) => q.since && new Date(q.since) >= startToday).length;
  const promptsBlockedTotal = (s.decisions || []).filter((d) => isBlockedDecision(d) && decisionAgentOf(d, sessById) === "claude-code").length;
  const jitTotal = svids.length;
  const jitActiveTotal = svids.filter((sv) => sv.status === "active" && new Date(sv.expires_at).getTime() > Date.now()).length;
  const kpis = {
    coverage: { governed, total: COVERAGE_TOTAL, ungoverned: Math.max(0, COVERAGE_TOTAL - governed) },
    agents: roster.length,
    promptsBlocked: promptsBlockedTotal,
    jit: jitTotal,
    jitActive: jitActiveTotal,
    active: roster.filter((r) => r.state === "Active").length,
    capped: roster.filter((r) => r.state === "Spawn-capped").length,
    quarantines: (s.quarantine.quarantined || []).length,
    newQuarantinesToday,
    lowtrust: roster.filter((r) => r.trust <= 60).length,
  };

  // Permit/Deny donut
  const decs = s.decisions || [];
  const permit = decs.filter((d) => d.effect === "Permit").length;
  const deny = decs.filter((d) => d.effect !== "Permit").length;
  const total = permit + deny;
  const permitPct = total ? Math.round((permit / total) * 100) : 100;
  const denyPct = 100 - permitPct;
  const reasonColors = { "Prompt Injection": "#DC2626", "Intent Drift": "#F59E0B", "Low Trust": "#7C3AED", "Quarantine": "#0EA5E9", "Policy Denial": "#64748B" };
  const reasonCounts = { "Prompt Injection": 0, "Intent Drift": 0, "Low Trust": 0, "Quarantine": 0, "Policy Denial": 0 };
  decs.filter((d) => d.effect !== "Permit").forEach((d) => { reasonCounts[denyBucket(d)]++; });
  const denyTotal = deny || 1;
  const legend = Object.keys(reasonCounts).map((k) => ({ label: k, value: Math.round((reasonCounts[k] / denyTotal) * 100), color: reasonColors[k] }));

  // High deny rate identities
  const highDeny = [];
  for (const [u, ds] of decByUser) {
    const t = ds.length; if (!t) continue;
    const dn = ds.filter((d) => d.effect !== "Permit").length;
    const rate = Math.round((dn / t) * 100);
    const sess = byUser.get(u) && byUser.get(u)[byUser.get(u).length - 1];
    highDeny.push({ id: u, rid: principalOf(u), type: "dev", deny: rate, dir: rate >= 50 ? "up" : "down", model: (sess && sess.model) || "—" });
  }
  highDeny.sort((a, b) => b.deny - a.deny);

  // Usage by tool
  const usageMap = new Map();
  decs.forEach((d) => {
    const t = normTool(d.tool);
    const e = usageMap.get(t) || { tool: t, n: 0, permits: 0 };
    e.n++; if (d.effect === "Permit") e.permits++;
    usageMap.set(t, e);
  });
  const order = ["ReadFile", "RunBash", "EditFile", "WriteFile", "SpawnAgent", "MCP*"];
  const usage = Array.from(usageMap.values())
    .map((u) => ({ tool: u.tool, n: u.n, permit: Math.round((u.permits / u.n) * 100) }))
    .sort((a, b) => (order.indexOf(a.tool) - order.indexOf(b.tool)) || (b.n - a.n));

  // Decision Logs feed — design's LOGS shape
  const logs = decs.map((d) => {
    const u = (d.user_email || "").includes("@") ? d.user_email.split("@")[0] : (d.user_email || "");
    const isAgent = d.agent_type === "subagent";
    const tnum = d.timestamp ? new Date(d.timestamp) : null;
    const sc = d.scores || {};
    return {
      time: tnum ? tnum.toTimeString().slice(0, 8) : "",
      trace: "trc_" + (d.session_id || "").replace(/[^a-z0-9]/gi, "").slice(0, 8),
      idShort: isAgent ? (d.agent_type || "agent") : u,
      kind: isAgent ? "agent" : "dev",
      action: normTool(d.tool),
      target: (d.prompt || d.command_risk || d.file_zone || d.reason || "—").slice(0, 80),
      effect: d.effect,
      reason: d.reason || "",
      ctx: {
        identity: isAgent ? ('Agent::"' + u + '"') : principalOf(u),
        action: normTool(d.tool),
        file_zone: d.file_zone || "n/a",
        command_class: d.command_risk || "",
        injection_score: sc.injection_score || 0,
        drift_score: sc.intent_drift_score || sc.intent_mismatch_score || 0,
        trust: d.trust_score != null ? d.trust_score : "",
        decision: d.effect,
      },
    };
  });

  // AAI board — merge live quarantined principals into the 4 enforced policies.
  // The other catalog policies keep their illustrative OOTB principals.
  const LIVE_AAI = ["AAI-RBP-002", "AAI-UAP-001", "AAI-RBP-003", "AAI-AIG-003"];
  const liveByPolicy = {};
  (s.quarantine.quarantined || []).forEach((q) => {
    (liveByPolicy[q.policyId] = liveByPolicy[q.policyId] || []).push({
      pid: "user:" + q.osUser, type: "User", trigger: "Runtime",
      reason: q.reason || q.policyName,
      quarantineSec: q.expiresAt ? Math.max(0, Math.round((q.expiresAt - Date.now()) / 1000)) : 0,
      status: q.status,
    });
  });
  let aaiPolicies = [];
  try {
    aaiPolicies = (typeof POLICIES !== "undefined" ? POLICIES : []).map((p) =>
      LIVE_AAI.includes(p.id) ? { ...p, principals: liveByPolicy[p.id] || [], live: true } : p);
  } catch (e) { aaiPolicies = []; }

  return { raw: s, loading: s.loading, roster, kpis, denyDonut: { permitPct, denyPct, legend }, highDeny, usage, logs,
    aaiPolicies, terminated: s.terminated || [], policySets: s.policySets || [],
    quarantine: s.quarantine, security: s.security, hitl: s.hitl, commands: s.commands, filezones: s.filezones, mcp: s.mcp };
}

/* ===================== aai-data.js ===================== */
// =========================================================
// Reva — AAI policy data (all 25 OOTB)
// =========================================================
const POLICIES = [
  // ===== Runtime Behavioral Protection (RBP) =====
  {
    id: "AAI-RBP-001",
    name: "Tool Invocation Surge",
    category: "rbp",
    resolution: "Auto-Restore",
    principals: [
      { pid: "agent:data-pipeline", type: "Agent", trigger: "Runtime", reason: "Extract_records tool invoked 847 times in 5-minute window — baseline threshold is 40 invocations per window", quarantineSec: 1620, status: "Quarantined" },
      { pid: "agent:etl-scheduler", type: "Agent", trigger: "Runtime", reason: "Bulk_insert tool invoked 312 times in 3 minutes — throughput exceeded 8x normal operating range", quarantineSec: 880, status: "Auto-restoring" },
    ],
  },
  {
    id: "AAI-RBP-002",
    name: "High Denial Rate",
    category: "rbp",
    resolution: "HITL",
    principals: [
      { pid: "agent:finbot", type: "Agent", trigger: "Runtime", reason: "6 consecutive policy denials in 58 seconds — agent attempted fund transfers exceeding authorized transaction threshold", quarantineSec: 2820, status: "Quarantined" },
      { pid: "agent:uw-01", type: "Agent", trigger: "Runtime", reason: "8 policy denials in 45 seconds — repeated unauthorized write attempts against restricted customer relationship records", quarantineSec: 2640, status: "Awaiting resolution" },
      { pid: "user:j.smith", type: "User", trigger: "Runtime", reason: "5 policy denials in 60 seconds — attempted rate query operations outside authorized data classification scope", quarantineSec: 2400, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-RBP-003",
    name: "Ephemeral Agent Surge",
    category: "rbp",
    resolution: "Auto-Restore",
    principals: [
      { pid: "agent:orchestrator", type: "Agent", trigger: "Runtime", reason: "Spawned 23 ephemeral sub-agents within 2-minute window — configured maximum is 8 instances per 5-minute rolling period", quarantineSec: 720, status: "Auto-restoring" },
    ],
  },
  {
    id: "AAI-RBP-004",
    name: "Data exfiltration pattern",
    category: "rbp",
    resolution: "HITL",
    principals: [
      { pid: "mcp:analytics-server", type: "MCP", trigger: "Runtime", reason: "Server returned 4.2 GB in aggregated responses within 10-minute window — volume exceeds 15x daily average baseline", quarantineSec: 6300, status: "Awaiting resolution" },
    ],
  },
  {
    id: "AAI-RBP-005",
    name: "HITL timeout escalation",
    category: "rbp",
    resolution: "Manual Admin Grant",
    principals: [
      { pid: "agent:loan-processor", type: "Agent", trigger: "Runtime", reason: "3 consecutive human-in-the-loop approval requests timed out without reviewer response — potential broken approval loop or reviewer unavailability", quarantineSec: 14400, status: "Quarantined" },
    ],
  },

  // ===== Identity-Aware Access (IAA) =====
  {
    id: "AAI-IAA-001",
    name: "Authentication failure lockout",
    category: "iaa",
    resolution: "Auto-Restore",
    principals: [
      { pid: "user:m.chen", type: "User", trigger: "Runtime", reason: "5 failed multi-factor authentication attempts within 3-minute window from recognized device", quarantineSec: 480, status: "Auto-restoring" },
      { pid: "user:t.nakamura", type: "User", trigger: "Runtime", reason: "8 failed password attempts originating from unrecognized device fingerprint — possible credential stuffing", quarantineSec: 660, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-IAA-002",
    name: "Impossible travel detection",
    category: "iaa",
    resolution: "HITL",
    principals: [
      { pid: "user:r.patel", type: "User", trigger: "Runtime", reason: "Authenticated from Mumbai at 09:14 IST then from London at 09:52 IST — travel distance physically impossible within elapsed time", quarantineSec: 5400, status: "Awaiting resolution" },
    ],
  },
  {
    id: "AAI-IAA-003",
    name: "Dormant access reactivation",
    category: "iaa",
    resolution: "HITL",
    principals: [
      { pid: "user:k.tanaka", type: "User", trigger: "Runtime", reason: "No recorded platform activity for 127 days followed by bulk data export request for 2,400 customer records", quarantineSec: 9000, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-IAA-004",
    name: "Session concurrency anomaly",
    category: "iaa",
    resolution: "Auto-Restore",
    principals: [
      { pid: "user:a.garcia", type: "User", trigger: "Runtime", reason: "8 concurrent active sessions detected across 4 geographic regions — maximum allowed concurrent sessions is 3", quarantineSec: 1500, status: "Auto-restoring" },
    ],
  },
  {
    id: "AAI-IAA-005",
    name: "NHI token origin anomaly",
    category: "iaa",
    resolution: "HITL",
    principals: [
      { pid: "nhi:reporting-svc", type: "NHI", trigger: "Runtime", reason: "Service token presented from unregistered IP range 10.42.x.x — expected origin is authorized 10.20.x.x subnet only", quarantineSec: 4080, status: "Quarantined" },
    ],
  },

  // ===== Malicious Website Blocking (MWB) =====
  {
    id: "AAI-MWB-001",
    name: "Malicious URL access attempt",
    category: "mwb",
    resolution: "Auto-Restore",
    principals: [
      { pid: "agent:research-bot", type: "Agent", trigger: "Runtime", reason: "Attempted HTTP fetch to domain flagged on enterprise threat intelligence blocklist — request blocked at network layer", quarantineSec: 900, status: "Auto-restoring" },
    ],
  },
  {
    id: "AAI-MWB-002",
    name: "MCP server untrusted redirect",
    category: "mwb",
    resolution: "HITL",
    principals: [
      { pid: "mcp:vendor-api", type: "MCP", trigger: "Runtime", reason: "Server response contained 302 redirect to external domain not listed on approved integration allowlist — potential server compromise", quarantineSec: 7200, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-MWB-003",
    name: "Phishing content in agent output",
    category: "mwb",
    resolution: "HITL",
    principals: [
      { pid: "agent:email-assistant", type: "Agent", trigger: "Runtime", reason: "Generated output containing homoglyph domain paypa1.com matching documented phishing pattern in threat database", quarantineSec: 3300, status: "Awaiting resolution" },
    ],
  },
  {
    id: "AAI-MWB-004",
    name: "Unapproved external API call",
    category: "mwb",
    resolution: "Manual Admin Grant",
    principals: [
      { pid: "agent:procurement-bot", type: "Agent", trigger: "Runtime", reason: "Attempted outbound API call to vendor endpoint not present in registered integration manifest — unverified third-party dependency", quarantineSec: 10800, status: "Quarantined" },
    ],
  },

  // ===== Unsafe Action Prevention (UAP) =====
  {
    id: "AAI-UAP-001",
    name: "Prompt injection detection",
    category: "uap",
    resolution: "HITL",
    principals: [
      { pid: "agent:supply-coordinator", type: "Agent", trigger: "Runtime", reason: "Injection payload detected in MCP tool response — agent attempted system prompt override to bypass financial approval gate", quarantineSec: 7320, status: "Awaiting resolution" },
    ],
  },
  {
    id: "AAI-UAP-002",
    name: "PII / sensitive data exposure",
    category: "uap",
    resolution: "HITL",
    principals: [
      { pid: "agent:support-bot", type: "Agent", trigger: "Runtime", reason: "Response contained unmasked social security number during customer account lookup — data classification threshold exceeded", quarantineSec: 5760, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-UAP-003",
    name: "Destructive operation attempt",
    category: "uap",
    resolution: "Manual Admin Grant",
    principals: [
      { pid: "agent:db-admin", type: "Agent", trigger: "Runtime", reason: "Attempted DROP TABLE operation on production order_transactions schema without approved change management ticket", quarantineSec: 13200, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-UAP-004",
    name: "Privilege escalation attempt",
    category: "uap",
    resolution: "HITL",
    principals: [
      { pid: "user:d.kumar", type: "User", trigger: "Runtime", reason: "4 attempts to invoke admin-level user management operations within 2 minutes — assigned role is read-only analyst", quarantineSec: 4500, status: "Awaiting resolution" },
    ],
  },

  // ===== Agent Identity Governance (AIG) =====
  {
    id: "AAI-AIG-001",
    name: "Certification dispute hold",
    category: "aig",
    resolution: "HITL",
    principals: [
      { pid: "agent:report-gen", type: "Agent", trigger: "Certification", reason: "Certifier flagged dormant agent during quarterly review — no recorded invocations in 94 days, retains access to customer reporting system", quarantineSec: 259200, status: "In certification" },
      { pid: "nhi:etl-service", type: "NHI", trigger: "Certification", reason: "Certifier flagged service account during access review — designated owner departed organization 6 weeks ago, ownership unresolved", quarantineSec: 248400, status: "In certification" },
    ],
  },
  {
    id: "AAI-AIG-002",
    name: "SoD conflict detection",
    category: "aig",
    resolution: "HITL",
    principals: [
      { pid: "user:l.wong", type: "User", trigger: "Runtime", reason: "Granted both trade-execution and trade-settlement access simultaneously — violates segregation of duties policy FIN-SOD-003", quarantineSec: 8100, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-AIG-003",
    name: "Incident Blast Radius",
    category: "aig",
    resolution: "Manual Admin Grant",
    principals: [
      { pid: "nhi:payment-svc", type: "NHI", trigger: "Manual", reason: "Compromised credential suspected during active incident — full isolation triggered per incident response protocol INC-4471", quarantineSec: 86400, status: "Quarantined" },
      { pid: "nhi:batch-processor", type: "NHI", trigger: "Manual", reason: "Shared credential rotation pending — isolated as precautionary measure during INC-4471 blast radius containment", quarantineSec: 84600, status: "Quarantined" },
      { pid: "agent:settlement-bot", type: "Agent", trigger: "Manual", reason: "Security admin clipped access via access explorer — agent connected to compromised payment-svc through delegation chain, isolated to prevent lateral propagation", quarantineSec: 82800, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-AIG-004",
    name: "Model drift detection",
    category: "aig",
    resolution: "HITL",
    principals: [
      { pid: "agent:underwriter", type: "Agent", trigger: "Runtime", reason: "Runtime model identified as claude-3.5-sonnet — registered model in agent manifest is claude-haiku-4.5, deviation from approved model configuration", quarantineSec: 6480, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-AIG-005",
    name: "Unregistered tool exposure",
    category: "aig",
    resolution: "Manual Admin Grant",
    principals: [
      { pid: "mcp:hr-server", type: "MCP", trigger: "Runtime", reason: "Server advertising delete_employee and modify_salary tools not present in registered tool manifest — potential supply chain compromise or unauthorized server update", quarantineSec: 16200, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-AIG-006",
    name: "Delegation chain depth breach",
    category: "aig",
    resolution: "Manual Admin Grant",
    principals: [
      { pid: "agent:sub-task-4", type: "Agent", trigger: "Runtime", reason: "Agent-to-sub-agent delegation exceeded configured 3-hop maximum depth — chain: orchestrator > planner > executor > sub-task-4", quarantineSec: 11400, status: "Quarantined" },
    ],
  },
  {
    id: "AAI-AIG-007",
    name: "Scope creep — unmanifested tool",
    category: "aig",
    resolution: "HITL",
    principals: [
      { pid: "agent:analytics-bot", type: "Agent", trigger: "Runtime", reason: "Attempted to invoke send_email tool not listed in registered agent tool manifest — potential lateral capability expansion beyond authorized scope", quarantineSec: 5040, status: "Quarantined" },
    ],
  },
];

const CATEGORIES = {
  rbp: { label: "Runtime behavioral", short: "RBP" },
  iaa: { label: "Identity-aware",     short: "IAA" },
  mwb: { label: "Malicious blocking", short: "MWB" },
  uap: { label: "Unsafe action",      short: "UAP" },
  aig: { label: "Agent governance",   short: "AIG" },
};

// Mappings for pills
const TRIGGER_PILL = {
  Runtime: "blue",
  Certification: "purple",
  Manual: "amber",
};
const RESOLUTION_PILL = {
  "Auto-Restore": "green",
  "HITL": "amber",
  "Manual Admin Grant": "red",
  "Launch Certification": "purple",
};
const STATUS_PILL = {
  "Quarantined": "gray",
  "Awaiting resolution": "amber",
  "Approval sent": "amber",
  "In certification": "purple",
  "Auto-restoring": "blue",
  "Resolved": "green",
  "Permanently revoked": "red",
};
const IDENTITY_PILL = {
  Agent: "blue",
  User: "green",
  NHI: "amber",
  MCP: "coral",
};

// Time formatting
function formatDuration(sec) {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  if (sec < 86400) {
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    return m && h < 6 ? `${h}h ${m}m` : `${h}h`;
  }
  return `${Math.floor(sec / 86400)}d`;
}
function timeBadgeTone(sec) {
  if (sec < 3600) return "gray";
  if (sec < 14400) return "amber";
  return "red";
}

Object.assign(window, {
  POLICIES, CATEGORIES,
  TRIGGER_PILL, RESOLUTION_PILL, STATUS_PILL, IDENTITY_PILL,
  formatDuration, timeBadgeTone,
});

/* ===================== primitives.jsx ===================== */
/* global React */
const { useState, useRef, useEffect } = React;

/* ---------- Icons (inline, stroke-based, 1.6 weight) ---------- */
function Icon({ name, size = 18, color = "currentColor", style }) {
  const p = { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: color, strokeWidth: 1.7, strokeLinecap: "round", strokeLinejoin: "round", style };
  const paths = {
    search: <><circle cx="11" cy="11" r="7" /><path d="M21 21l-3.6-3.6" /></>,
    plus: <><path d="M12 5v14M5 12h14" /></>,
    chevDown: <path d="M6 9l6 6 6-6" />,
    chevRight: <path d="M9 6l6 6-6 6" />,
    kebab: <><circle cx="12" cy="5" r="1.4" fill={color} stroke="none"/><circle cx="12" cy="12" r="1.4" fill={color} stroke="none"/><circle cx="12" cy="19" r="1.4" fill={color} stroke="none"/></>,
    copy: <><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></>,
    check: <path d="M20 6L9 17l-5-5" />,
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
    list: <><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></>,
    shield: <path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />,
    user: <><circle cx="12" cy="8" r="3.4"/><path d="M5.5 20a6.5 6.5 0 0 1 13 0"/></>,
    bot: <><rect x="4" y="8" width="16" height="11" rx="3"/><path d="M12 8V4M9 5l3-1 3 1"/><circle cx="9.5" cy="13.5" r="1" fill={color} stroke="none"/><circle cx="14.5" cy="13.5" r="1" fill={color} stroke="none"/></>,
    x: <path d="M6 6l12 12M18 6L6 18" />,
    filter: <path d="M3 5h18l-7 8v6l-4-2v-4z" />,
    download: <><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></>,
    columns: <><rect x="3" y="4" width="7" height="16" rx="1.5"/><rect x="14" y="4" width="7" height="16" rx="1.5"/></>,
    sitemap: <><rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v3M6 16v-2h12v2"/></>,
    sparkles: <><path d="M12 3l1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6z"/><path d="M18.5 14l.7 2 2 .7-2 .7-.7 2-.7-2-2-.7 2-.7z"/></>,
    fileCode: <><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M10.5 12l-2 2 2 2M13.5 12l2 2-2 2"/></>,
    trash: <><path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13"/></>,
    calendar: <><rect x="4" y="5" width="16" height="16" rx="2"/><path d="M4 9h16M8 3v4M16 3v4"/></>,
    flame: <path d="M12 3s5 3.5 5 8a5 5 0 0 1-10 0c0-2 1-3.5 2.5-4.5C9 8 10 5 12 3z" />,
    coin: <><circle cx="12" cy="12" r="8"/><path d="M9.6 9.6a2.4 1.8 0 0 1 4.8 0c0 1.1-1 1.7-2.4 2S9.6 13 9.6 14.4a2.4 1.8 0 0 0 4.8 0M12 7v1.4M12 15.4V17"/></>,
    play: <path d="M7 5l12 7-12 7z" />,
    pin: <><path d="M12 21s6-5.3 6-10a6 6 0 0 0-12 0c0 4.7 6 10 6 10z"/><circle cx="12" cy="11" r="2"/></>,
    bars: <><path d="M5 20V10M12 20V4M19 20v-7"/></>,
    rotate: <><path d="M20 11a8 8 0 1 0-1 5"/><path d="M20 5v6h-6"/></>,
    ext: <><path d="M14 4h6v6"/><path d="M20 4l-9 9"/><path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4"/></>,
    alert: <><path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17h.01"/></>,
    bell: <><path d="M18 8a6 6 0 1 0-12 0c0 7-3 8-3 8h18s-3-1-3-8"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></>,
    lock: <><rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/></>,
    info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></>,
    home: <><path d="M4 11l8-7 8 7"/><path d="M6 10v9h12v-9"/></>,
    plug: <><path d="M9 3v5M15 3v5"/><path d="M7 8h10v3a5 5 0 0 1-10 0z"/><path d="M12 16v5"/></>,
    send: <><path d="M5 12l15-7-7 15-2.5-5.5z"/></>,
    layers: <><path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/></>,
    arrowLeft: <path d="M19 12H5M12 19l-7-7 7-7" />,
    arrowRight: <path d="M5 12h14M12 5l7 7-7 7" />,
    arrowUp: <path d="M12 19V5M5 12l7-7 7 7" />,
    arrowDown: <path d="M12 5v14M19 12l-7 7-7-7" />,
    sort: <path d="M7 15l5 5 5-5M7 9l5-5 5 5" />,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    shuffle: <><path d="M16 3h5v5M4 20l17-17M21 16v5h-5M15 15l6 6M4 4l5 5"/></>,
    rocket: <><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09zM12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2zM9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/></>,
    zap: <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />,
    more: <><circle cx="5" cy="12" r="1.4" fill={color} stroke="none"/><circle cx="12" cy="12" r="1.4" fill={color} stroke="none"/><circle cx="19" cy="12" r="1.4" fill={color} stroke="none"/></>,
    users: <><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/></>,
    key: <><circle cx="8" cy="15" r="4"/><path d="M10.85 12.15L21 2M16 7l3 3M19 4l3 3"/></>,
    server: <><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/></>,
    activity: <path d="M22 12h-4l-3 9L9 3l-3 9H2" />,
    flag: <><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V4s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22V15"/></>,
    umbrella: <><path d="M12 12v7a2 2 0 0 0 4 0M12 2v1.5M3 12a9 9 0 0 1 18 0z"/></>,
    box: <><path d="M21 8l-9-5-9 5 9 5 9-5zM3 8v8l9 5 9-5V8M12 13v8"/></>,
    heartShield: <><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9.2 10.8c0-1 .8-1.6 1.6-1.6.6 0 1 .3 1.2.6.2-.3.6-.6 1.2-.6.8 0 1.6.6 1.6 1.6 0 1.4-2 2.8-2.8 3.4-.8-.6-2.8-2-2.8-3.4z"/></>,
    settingsGear: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></>,
    cloud: <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" />,
    checkCircle: <><circle cx="12" cy="12" r="9"/><path d="M9 12l2 2 4-4"/></>,
    shieldAlert: <><path d="M12 3l8 3v6c0 4.5-3.5 8-8 9-4.5-1-8-4.5-8-9V6l8-3z"/><path d="M12 8v4M12 16h.01"/></>,
  };
  return <svg {...p}>{paths[name] || null}</svg>;
}

function Pill({ tone = "gray", dot, children, style }) {
  return <span className={`pill pill-${tone}`} style={style}>{dot && <span className="dot" />}{children}</span>;
}

function Trend({ dir, children }) {
  const arrow = dir === "up" ? "▲" : dir === "down" ? "▼" : "—";
  return <span className={`trend trend-${dir}`}><span style={{ fontSize: 9 }}>{arrow}</span>{children}</span>;
}

function Toggle({ on, onClick }) {
  return <button className={`toggle ${on ? "on" : ""}`} onClick={onClick} aria-pressed={on} />;
}

function Kebab() {
  return <button className="kebab" onClick={(e) => e.stopPropagation()}><Icon name="kebab" size={18} /></button>;
}

function Search({ placeholder = "Search", width }) {
  return (
    <div className="search" style={width ? { minWidth: width } : null}>
      <Icon name="search" size={16} color="var(--ink-4)" />
      <input placeholder={placeholder} />
    </div>
  );
}

function Segmented({ options, value, onChange }) {
  return (
    <div className="seg">
      {options.map((o) => (
        <button key={o} className={value === o ? "active" : ""} onClick={() => onChange(o)}>{o}</button>
      ))}
    </div>
  );
}

function SelectChip({ children }) {
  return <button className="selchip">{children}<Icon name="chevDown" size={15} color="var(--ink-4)" /></button>;
}

/* Trust meter */
function TrustMeter({ value }) {
  const color = value >= 75 ? "var(--green)" : value >= 60 ? "var(--amber)" : "var(--red)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div className="meter" style={{ width: 56 }}><span style={{ width: `${value}%`, background: color }} /></div>
      <span className="mono" style={{ fontSize: 12.5, fontWeight: 600, color: "var(--ink-2)" }}>{value}</span>
    </div>
  );
}

/* Donut chart — segments [{label,value,color}] with centered value */
function Donut({ segments, size = 168, thickness = 22, center }) {
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const total = segments.reduce((s, x) => s + x.value, 0);
  let offset = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-3)" strokeWidth={thickness} />
        {segments.map((s, i) => {
          const len = (s.value / total) * c;
          const el = (
            <circle key={i} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={s.color}
              strokeWidth={thickness} strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-offset}
              strokeLinecap="butt" />
          );
          offset += len;
          return el;
        })}
      </g>
      {center && (
        <>
          <text x="50%" y="48%" textAnchor="middle" dominantBaseline="middle" style={{ fontSize: 26, fontWeight: 700, fill: "var(--ink)" }}>{center.value}</text>
          <text x="50%" y="62%" textAnchor="middle" dominantBaseline="middle" style={{ fontSize: 11.5, fontWeight: 600, fill: "var(--ink-3)" }}>{center.label}</text>
        </>
      )}
    </svg>
  );
}

Object.assign(window, { Icon, Pill, Trend, Toggle, Kebab, Search, Segmented, SelectChip, TrustMeter, Donut });

/* ===================== logos.jsx ===================== */
/* global React */
/* Brand logo marks for integration tiles. Simple, recognizable, used as identifiers. */

function ClaudeBurst({ size = 24, color = "#D97757" }) {
  const rays = [];
  const n = 11;
  for (let i = 0; i < n; i++) {
    const a = (i / n) * Math.PI * 2 - Math.PI / 2;
    rays.push(<line key={i}
      x1={12 + Math.cos(a) * 2.6} y1={12 + Math.sin(a) * 2.6}
      x2={12 + Math.cos(a) * 9.6} y2={12 + Math.sin(a) * 9.6}
      stroke={color} strokeWidth={2.3} strokeLinecap="round" />);
  }
  return <svg width={size} height={size} viewBox="0 0 24 24">{rays}</svg>;
}

function Initials({ text, bg = "var(--surface-3)", fg = "var(--ink-3)", size = 24 }) {
  return (
    <div style={{ width: size, height: size, borderRadius: 7, background: bg, color: fg,
      display: "grid", placeItems: "center", fontSize: size * 0.4, fontWeight: 700, letterSpacing: "-.02em" }}>{text}</div>
  );
}

function Mark({ brand, size = 24 }) {
  const s = size;
  switch (brand) {
    case "anthropic":
      return <ClaudeBurst size={s} />;
    case "aws":
      return (
        <svg width={s} height={s} viewBox="0 0 40 40">
          <text x="20" y="20" textAnchor="middle" fontSize="11" fontWeight="700" fill="#232F3E" fontFamily="Inter">aws</text>
          <path d="M9 25c7 4 15 4 22 0" stroke="#FF9900" strokeWidth="2.4" fill="none" strokeLinecap="round" />
          <path d="M29 23.5l2.5-.6-.6 2.5z" fill="#FF9900" />
        </svg>
      );
    case "s3":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <path d="M6 7h12l-1.2 11.2a1.5 1.5 0 0 1-1.5 1.3H8.7a1.5 1.5 0 0 1-1.5-1.3z" fill="#3F8624" />
          <ellipse cx="12" cy="7" rx="6" ry="1.8" fill="#5FA83C" />
        </svg>
      );
    case "cognito":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <path d="M12 3l7 4v6c0 4-3 6.5-7 8-4-1.5-7-4-7-8V7z" fill="#DD344C" />
          <circle cx="12" cy="10" r="2.2" fill="#fff" /><path d="M8.5 16a3.5 3.5 0 0 1 7 0z" fill="#fff" />
        </svg>
      );
    case "entra":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <path d="M12 3L4 20h4l4-9 4 9h4z" fill="#0A7BD4" />
          <path d="M12 3L4 20h4l4-9z" fill="#33B1E1" />
        </svg>
      );
    case "okta":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="8" fill="none" stroke="#00297A" strokeWidth="3.6" />
        </svg>
      );
    case "oktaverify":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <circle cx="11" cy="12" r="7" fill="none" stroke="#00297A" strokeWidth="3.2" />
          <path d="M16 7l4 2-1.5 4" stroke="#16A34A" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "crowdstrike":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <path d="M3 8c4-1 7 1 9 4 2-3 5-5 9-4-3 2-4 5-9 9-5-4-6-7-9-9z" fill="#E01A22" />
        </svg>
      );
    case "github":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <circle cx="6.5" cy="7" r="2" fill="#181717" /><circle cx="6.5" cy="17" r="2" fill="#181717" /><circle cx="16" cy="7" r="2" fill="#181717" />
          <path d="M6.5 9v6M16 9v2c0 2.5-2 3-4 3.2" stroke="#181717" strokeWidth="1.8" fill="none" strokeLinecap="round" />
        </svg>
      );
    case "bedrock":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <path d="M12 3l7 4v10l-7 4-7-4V7z" fill="none" stroke="#FF9900" strokeWidth="1.8" />
          <path d="M12 8.5l3 1.7v3.6l-3 1.7-3-1.7v-3.6z" fill="#FF9900" />
        </svg>
      );
    case "n8n":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <circle cx="5" cy="12" r="2.2" fill="#EA4B71" /><circle cx="12" cy="7" r="2.2" fill="#EA4B71" /><circle cx="12" cy="17" r="2.2" fill="#EA4B71" /><circle cx="19" cy="12" r="2.2" fill="#EA4B71" />
          <path d="M6.8 11l3.4-2.4M6.8 13l3.4 2.4M13.8 8.6L17.2 11M13.8 15.4L17.2 13" stroke="#EA4B71" strokeWidth="1.5" />
        </svg>
      );
    case "slack":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <g strokeWidth="3.4" strokeLinecap="round">
            <path d="M9 5.5v6" stroke="#36C5F0" /><path d="M14.5 9h-6" stroke="#2EB67D" />
            <path d="M15 12.5v6" stroke="#ECB22E" /><path d="M9.5 15h6" stroke="#E01E5A" />
          </g>
        </svg>
      );
    case "microsoft":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <rect x="4" y="4" width="7" height="7" fill="#F25022" /><rect x="13" y="4" width="7" height="7" fill="#7FBA00" />
          <rect x="4" y="13" width="7" height="7" fill="#00A4EF" /><rect x="13" y="13" width="7" height="7" fill="#FFB900" />
        </svg>
      );
    case "langchain":
      return <Initials text="LC" bg="#E7F6EE" fg="#1C8A4E" size={s} />;
    case "crewai":
      return <Initials text="C" bg="#1F2430" fg="#fff" size={s} />;
    case "custom":
      return <Initials text="+" bg="var(--surface-3)" fg="var(--ink-3)" size={s} />;
    case "otel":
      return (
        <svg width={s} height={s} viewBox="0 0 24 24">
          <circle cx="12" cy="9" r="3" fill="none" stroke="#F5A800" strokeWidth="2" />
          <circle cx="12" cy="9" r="1.2" fill="#425CC7" />
          <path d="M8 15l-2 3M16 15l2 3M12 13v5" stroke="#425CC7" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      );
    default:
      return <Initials text={(brand || "?").slice(0, 2).toUpperCase()} size={s} />;
  }
}

function LogoTile({ brand, size = 44, mark = 24 }) {
  return (
    <div style={{
      width: size, height: size, borderRadius: 12, background: "#fff",
      border: "1px solid var(--border)", display: "grid", placeItems: "center", flex: "none",
    }}>
      <Mark brand={brand} size={mark} />
    </div>
  );
}

Object.assign(window, { Mark, LogoTile, ClaudeBurst });

/* ===================== insights.jsx ===================== */
/* global React, Icon, Pill, Trend, Donut, SelectChip, Segmented, Search */
/* Insights — AISPM dashboard with integrated, tile-filtered identity roster */

function KpiTile({ label, value, sub, foot, tone, active, onClick }) {
  return (
    <button onClick={onClick} className="kpi" style={{
      textAlign: "left", border: `1.5px solid ${active ? "var(--blue)" : "var(--border)"}`,
      background: active ? "#E8F0FF" : "var(--surface)", borderRadius: "var(--r-lg)",
      boxShadow: active ? "0 0 0 3px rgba(37,99,235,.18)" : "var(--shadow-card)",
      padding: "16px 18px", display: "flex", flexDirection: "column", gap: 4, cursor: "pointer",
      transition: "border-color .15s, box-shadow .15s, background .15s",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
        {tone && <span style={{ width: 7, height: 7, borderRadius: "50%", background: `var(--${tone})` }} />}
        <span style={{ fontSize: 12.5, color: "var(--ink-3)", fontWeight: 600 }}>{label}</span>
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginTop: 2 }}>
        <span style={{ fontSize: 28, fontWeight: 700, color: "var(--ink)", letterSpacing: "-0.02em" }}>{value}</span>
        {sub}
      </div>
      <div style={{ marginTop: 2 }}>{foot}</div>
    </button>
  );
}

function CardHead({ title, right }) {
  return (
    <div style={{ display: "flex", alignItems: "center", padding: "16px 18px", borderBottom: "1px solid var(--border)" }}>
      <div className="section-title">{title}</div>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>{right}</div>
    </div>
  );
}

const FILTERS = {
  all:           { label: "All identities",   test: () => true },
  agents:        { label: "Agents",            test: (r) => r.kind === "dev" },
  promptsBlocked:{ label: "Prompts blocked",   test: (r) => (r.promptsBlocked || 0) > 0 },
  jit:           { label: "JIT access",        test: (r) => (r.jitCount || 0) > 0 },
  coverage:      { label: "Governed users",    test: (r) => r.kind === "dev" },
  active:        { label: "Active",            test: (r) => r.state === "Active" },
  capped:        { label: "Spawn-capped",      test: (r) => r.state === "Spawn-capped" },
  quarantined:   { label: "Quarantined",       test: (r) => r.state === "Quarantined" },
  lowtrust:      { label: "Low trust (≤ 60)",  test: (r) => r.trust <= 60 },
};

function Insights() {
  const reva = useReva();
  const ROSTER = reva.roster, RosterTable = window.RosterTable, AgentDetail = window.AgentDetail;
  const [by, setBy] = React.useState("Session");
  const [pivot, setPivot] = React.useState("Identity");
  const [filter, setFilter] = React.useState("all");
  const [selId, setSelId] = React.useState(ROSTER[0] ? ROSTER[0].id : null);

  const count = (key) => ROSTER.filter(FILTERS[key].test).length;
  const filtered = ROSTER.filter(FILTERS[filter].test);
  const row = filtered.find((r) => r.id === selId) || filtered[0];

  const pickFilter = (key) => {
    setFilter(key);
    const first = ROSTER.filter(FILTERS[key].test)[0];
    if (first) setSelId(first.id);
  };
  const pickIdentity = (rid) => { setFilter("all"); setSelId(rid); };

  const denyLegend = reva.denyDonut.legend;
  const highDeny = reva.highDeny;
  const usage = reva.usage;
  const maxUsage = Math.max(1, ...usage.map((u) => u.n));

  return (
    <div style={{ padding: 28 }}>
      {/* KPI / filter tiles */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 16, marginBottom: 16 }}>
        <KpiTile label="Agents" value={String(reva.kpis.agents)}
          foot={<span style={{ fontSize: 12, color: "var(--ink-4)", fontWeight: 600 }}>under governance</span>} active={filter === "agents"} onClick={() => pickFilter("agents")} />
        <KpiTile label="Prompts Blocked" tone="red" value={count("promptsBlocked")} foot={reva.kpis.promptsBlocked > 0 ? <Trend dir="up">{reva.kpis.promptsBlocked} blocked</Trend> : <span style={{ fontSize: 12, color: "var(--ink-4)", fontWeight: 600 }}>none</span>} active={filter === "promptsBlocked"} onClick={() => pickFilter("promptsBlocked")} />
        <KpiTile label="JIT (Just-in-Time Access)" tone="blue" value={String(reva.kpis.jit)} foot={<span style={{ fontSize: 12, color: "var(--ink-4)", fontWeight: 600 }}>{reva.kpis.jitActive} active · short-lived creds</span>} active={filter === "jit"} onClick={() => pickFilter("jit")} />
        <KpiTile label="Active Quarantines" tone="red" value={count("quarantined")} foot={reva.kpis.quarantines > 0 ? <Trend dir="up">{reva.kpis.newQuarantinesToday} new today</Trend> : null} active={filter === "quarantined"} onClick={() => pickFilter("quarantined")} />
        <KpiTile label="Low Trust (≤ 60)" tone="red" value={count("lowtrust")} foot={reva.kpis.lowtrust > 0 ? <Trend dir="up">below threshold</Trend> : null} active={filter === "lowtrust"} onClick={() => pickFilter("lowtrust")} />
      </div>

      {/* donut + high deny */}
      <div style={{ display: "grid", gridTemplateColumns: "1.15fr 1fr", gap: 16, marginBottom: 16 }}>
        <div className="card">
          <CardHead title="Permit / Deny Rate" right={<><Segmented options={["Session", "Identity"]} value={by} onChange={setBy} /><SelectChip>Last Week</SelectChip></>} />
          <div style={{ display: "flex", alignItems: "center", gap: 28, padding: "20px 22px" }}>
            <Donut size={172} thickness={24}
              segments={[{ value: reva.denyDonut.permitPct, color: "#16A34A" }, ...denyLegend]}
              center={{ value: reva.denyDonut.permitPct + "%", label: "Permit" }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--ink-3)", marginBottom: 10 }}>Deny by reason · {reva.denyDonut.denyPct}%</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 11 }}>
                {denyLegend.map((d) => (
                  <div key={d.label} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ width: 9, height: 9, borderRadius: 3, background: d.color, flex: "none" }} />
                    <span style={{ fontSize: 13, color: "var(--ink-2)" }}>{d.label}</span>
                    <span className="mono" style={{ marginLeft: "auto", fontSize: 12.5, color: "var(--ink-3)", fontWeight: 600 }}>{d.value}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <CardHead title="Identities with High Deny Rate" right={<button className="btn btn-text btn-sm" onClick={() => pickFilter("all")}>View all →</button>} />
          <div style={{ padding: "6px 8px" }}>
            {highDeny.map((h) => (
              <div key={h.id} className="hd-row" onClick={() => pickIdentity(h.rid)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 12px", borderRadius: 10, cursor: "pointer" }}>
                <div style={{ width: 30, height: 30, borderRadius: 8, display: "grid", placeItems: "center", flex: "none",
                  background: h.type === "dev" ? "var(--blue-tint)" : "var(--purple-tint)", color: h.type === "dev" ? "var(--blue-700)" : "var(--purple)" }}>
                  <Icon name={h.type === "dev" ? "user" : "bot"} size={17} />
                </div>
                <div style={{ minWidth: 0 }}>
                  <div className="mono" style={{ fontSize: 13, color: "var(--ink)", fontWeight: 600 }}>{h.id}</div>
                  <div className="mono" style={{ fontSize: 11.5, color: "var(--ink-4)" }}>{h.model}</div>
                </div>
                <div style={{ marginLeft: "auto", textAlign: "right" }}>
                  <Trend dir={h.dir}>{h.deny}%</Trend>
                  <div style={{ fontSize: 11, color: "var(--ink-4)" }}>deny rate</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* integrated roster */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14, flexWrap: "wrap" }}>
          <div className="section-title">Identities</div>
          {filter !== "all" && (
            <span className="pill pill-blue" style={{ height: 26 }}>
              {FILTERS[filter].label}
              <button onClick={() => setFilter("all")} style={{ border: 0, background: "transparent", padding: 0, marginLeft: 2, display: "grid", placeItems: "center", color: "var(--blue-700)", cursor: "pointer" }}><Icon name="x" size={13} /></button>
            </span>
          )}
          <span className="help">{filtered.length} of {ROSTER.length} principals</span>
          <div style={{ marginLeft: "auto", display: "flex", gap: 12 }}>
            <Search placeholder="Search identities…" width={240} />
            <Segmented options={["Identity", "Session"]} value={pivot} onChange={setPivot} />
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 16, alignItems: "start" }}>
          <RosterTable rows={filtered} selectedId={row ? row.id : null} onSelect={setSelId} />
          {row
            ? (pivot === "Session"
                ? <SessionsPanel row={row} terminated={reva.terminated} />
                : <AgentDetail row={row} />)
            : <div className="card" style={{ padding: 40, textAlign: "center", color: "var(--ink-4)" }}>No identity selected.</div>}
        </div>
      </div>

      {/* usage bars */}
      <div className="card">
        <CardHead title="Usage by Tool" right={<SelectChip>Last Week</SelectChip>} />
        <div style={{ padding: "18px 22px", display: "flex", flexDirection: "column", gap: 15 }}>
          {usage.map((u) => (
            <div key={u.tool} style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <div className="mono" style={{ width: 92, fontSize: 12.5, color: "var(--ink-2)", fontWeight: 600 }}>{u.tool}</div>
              <div style={{ flex: 1, height: 22, background: "var(--surface-3)", borderRadius: 6, overflow: "hidden", display: "flex" }}>
                <div style={{ width: `${(u.n / maxUsage) * 100}%`, background: u.permit < 80 ? "linear-gradient(90deg,#7C3AED,#9061f0)" : "linear-gradient(90deg,#2563EB,#4f80f0)", borderRadius: 6 }} />
              </div>
              <div className="mono" style={{ width: 64, textAlign: "right", fontSize: 12.5, color: "var(--ink)", fontWeight: 700 }}>{u.n.toLocaleString()}</div>
              <div style={{ width: 96, textAlign: "right" }}>
                <Pill tone={u.permit < 80 ? "amber" : "green"}>{u.permit}% permit</Pill>
              </div>
            </div>
          ))}
        </div>
      </div>

      <style>{`.hd-row:hover{background:var(--surface-2);} .kpi:hover{border-color:var(--border-strong);}`}</style>
    </div>
  );
}

window.Insights = Insights;

/* ===================== inventory.jsx ===================== */
/* global React, Icon, Pill, Search, Segmented, SelectChip, TrustMeter, Kebab */
/* Inventory — roster master/detail with Session/System/Identity pivots */

const ROSTER = [
  {
    id: 'Developer::"saisrungaram"', kind: "dev", email: "sai.s@acme.io", model: "claude-opus-4-8[1m]",
    os: "macOS 15.3", sessions: 3, trust: 58, state: "Quarantined", owner: "Patrick Fuller",
    svid: "spiffe://acme.io/dev/saisrungaram", svidFallback: false,
    budget: { used: 0, max: 5, note: "blocked — trust 58 ≤ 60" },
    tools: ["ReadFile", "EditFile", "RunBash (safe)", "WriteFile"],
    mcp: ["github-mcp", "jira-mcp"], gh: "ghs_••••••8f2a (brokered)",
    decisions: [
      { t: "2m", a: "RunBash", e: "Deny", r: "rm -rf flagged destructive" },
      { t: "9m", a: "ReadFile", e: "Deny", r: "secrets/** — Secret zone" },
      { t: "14m", a: "SpawnAgent", e: "Deny", r: "trust 58 ≤ 60" },
    ],
  },
  {
    id: 'Developer::"amartya.k"', kind: "dev", email: "amartya.k@acme.io", model: "claude-sonnet-4-6",
    os: "Ubuntu 24.04", sessions: 2, trust: 64, state: "Spawn-capped", owner: "Patrick Fuller",
    svid: "spiffe://acme.io/dev/amartya.k", svidFallback: false,
    budget: { used: 5, max: 5, note: "budget reached this session" },
    tools: ["ReadFile", "EditFile", "RunBash (safe)", "WriteFile", "SpawnAgent"],
    mcp: ["github-mcp"], gh: "ghs_••••••2b71 (brokered)",
    decisions: [
      { t: "5m", a: "SpawnAgent", e: "Deny", r: "spawn budget 5/5" },
      { t: "21m", a: "EditFile", e: "Permit", r: "Internal zone" },
    ],
  },
  {
    id: 'Agent::"saisrungaram:agent-9f2a…"', kind: "agent", email: "sai.s@acme.io", model: "claude-opus-4-8[1m]",
    os: "macOS 15.3", sessions: 1, trust: 72, state: "Active", owner: "saisrungaram",
    svid: "agent-hash:9f2a4c1e (fallback)", svidFallback: true,
    budget: { used: 0, max: 0, note: "ephemeral — not spawn-capable" },
    tools: ["ReadFile", "EditFile (scoped)"],
    mcp: ["github-mcp (read)"], gh: "inherited",
    decisions: [
      { t: "1m", a: "ReadFile", e: "Permit", r: "Internal zone" },
      { t: "3m", a: "EditFile", e: "Permit", r: "declared scope ok" },
    ],
  },
  {
    id: 'Developer::"d.okonkwo"', kind: "dev", email: "d.okonkwo@acme.io", model: "claude-sonnet-4-6",
    os: "Windows 11", sessions: 1, trust: 78, state: "Active", owner: "Patrick Fuller",
    svid: "spiffe://acme.io/dev/d.okonkwo", svidFallback: false,
    budget: { used: 2, max: 5, note: "" },
    tools: ["ReadFile", "EditFile", "RunBash (safe)", "WriteFile", "SpawnAgent"],
    mcp: ["github-mcp", "jira-mcp", "postgres-mcp"], gh: "ghs_••••••c4d0 (brokered)",
    decisions: [
      { t: "8m", a: "SpawnAgent", e: "Permit", r: "2/5 used" },
      { t: "12m", a: "MCPWrite", e: "HITL", r: "awaiting #ai-approvals" },
    ],
  },
  {
    id: 'Developer::"l.nakamura"', kind: "dev", email: "l.nakamura@acme.io", model: "claude-opus-4-8[1m]",
    os: "macOS 15.2", sessions: 4, trust: 85, state: "Active", owner: "Patrick Fuller",
    svid: "spiffe://acme.io/dev/l.nakamura", svidFallback: false,
    budget: { used: 1, max: 5, note: "" },
    tools: ["ReadFile", "EditFile", "RunBash (safe)", "WriteFile", "SpawnAgent"],
    mcp: ["github-mcp", "jira-mcp"], gh: "ghs_••••••a17e (brokered)",
    decisions: [
      { t: "4m", a: "WriteFile", e: "Permit", r: "Internal zone" },
      { t: "16m", a: "ReadFile", e: "Permit", r: "Public zone" },
    ],
  },
  {
    id: 'Agent::"d.okonkwo:agent-2b71…"', kind: "agent", email: "d.okonkwo@acme.io", model: "claude-haiku-4-3",
    os: "Windows 11", sessions: 1, trust: 69, state: "Active", owner: "d.okonkwo",
    svid: "agent-hash:2b71f8a3 (fallback)", svidFallback: true,
    budget: { used: 0, max: 0, note: "ephemeral — not spawn-capable" },
    tools: ["ReadFile"],
    mcp: ["github-mcp (read)"], gh: "inherited",
    decisions: [{ t: "6m", a: "ReadFile", e: "Permit", r: "Internal zone" }],
  },
  {
    id: 'Developer::"r.delgado"', kind: "dev", email: "r.delgado@acme.io", model: "claude-opus-4-8[1m]",
    os: "macOS 15.3", sessions: 1, trust: 52, state: "Quarantined", owner: "Patrick Fuller",
    svid: "spiffe://acme.io/dev/r.delgado", svidFallback: false,
    budget: { used: 0, max: 5, note: "blocked — trust 52 ≤ 60" },
    tools: ["ReadFile", "EditFile", "RunBash (safe)"],
    mcp: ["github-mcp"], gh: "ghs_••••••5a3d (brokered)",
    decisions: [
      { t: "3m", a: "RunBash", e: "Deny", r: "git reset --hard destructive" },
      { t: "7m", a: "RunBash", e: "Deny", r: "kubectl delete destructive" },
      { t: "11m", a: "SpawnAgent", e: "Deny", r: "trust 52 ≤ 60" },
    ],
  },
  {
    id: 'Developer::"k.lindqvist"', kind: "dev", email: "k.lindqvist@acme.io", model: "claude-sonnet-4-6",
    os: "Ubuntu 24.04", sessions: 2, trust: 55, state: "Quarantined", owner: "Patrick Fuller",
    svid: "spiffe://acme.io/dev/k.lindqvist", svidFallback: false,
    budget: { used: 0, max: 5, note: "blocked — trust 55 ≤ 60" },
    tools: ["ReadFile", "EditFile", "RunBash (safe)", "WriteFile"],
    mcp: ["github-mcp", "jira-mcp"], gh: "ghs_••••••e91c (brokered)",
    decisions: [
      { t: "1m", a: "ReadFile", e: "Deny", r: "prompt injection (score 74)" },
      { t: "6m", a: "EditFile", e: "Deny", r: "scope drift" },
    ],
  },
  {
    id: 'Developer::"j.park"', kind: "dev", email: "j.park@acme.io", model: "claude-sonnet-4-6",
    os: "macOS 15.2", sessions: 1, trust: 66, state: "Spawn-capped", owner: "Patrick Fuller",
    svid: "spiffe://acme.io/dev/j.park", svidFallback: false,
    budget: { used: 5, max: 5, note: "budget reached this session" },
    tools: ["ReadFile", "EditFile", "RunBash (safe)", "WriteFile", "SpawnAgent"],
    mcp: ["github-mcp"], gh: "ghs_••••••7d20 (brokered)",
    decisions: [
      { t: "4m", a: "SpawnAgent", e: "Deny", r: "spawn budget 5/5" },
      { t: "10m", a: "ReadFile", e: "Permit", r: "Internal zone" },
    ],
  },
  {
    id: 'Developer::"m.alvarez"', kind: "dev", email: "m.alvarez@acme.io", model: "claude-opus-4-8[1m]",
    os: "Windows 11", sessions: 3, trust: 81, state: "Active", owner: "Patrick Fuller",
    svid: "spiffe://acme.io/dev/m.alvarez", svidFallback: false,
    budget: { used: 2, max: 5, note: "" },
    tools: ["ReadFile", "EditFile", "RunBash (safe)", "WriteFile", "SpawnAgent"],
    mcp: ["github-mcp", "jira-mcp", "postgres-mcp"], gh: "ghs_••••••b8f4 (brokered)",
    decisions: [
      { t: "5m", a: "EditFile", e: "Permit", r: "Internal zone" },
      { t: "18m", a: "SpawnAgent", e: "Permit", r: "2/5 used" },
    ],
  },
  {
    id: 'Agent::"amartya.k:agent-7c10…"', kind: "agent", email: "amartya.k@acme.io", model: "claude-sonnet-4-6",
    os: "Ubuntu 24.04", sessions: 1, trust: 61, state: "Active", owner: "amartya.k",
    svid: "agent-hash:7c10ab93 (fallback)", svidFallback: true,
    budget: { used: 0, max: 0, note: "ephemeral — not spawn-capable" },
    tools: ["ReadFile", "EditFile (scoped)"],
    mcp: ["github-mcp (read)"], gh: "inherited",
    decisions: [
      { t: "2m", a: "EditFile", e: "Permit", r: "declared scope ok" },
      { t: "9m", a: "SpawnAgent", e: "Deny", r: "scope drift → review" },
    ],
  },
];

const STATE_TONE = { "Active": "green", "Spawn-capped": "amber", "Quarantined": "red" };

function RosterTable({ rows, selectedId, onSelect }) {
  return (
    <div className="card" style={{ overflow: "hidden" }}>
      <table className="tbl">
        <thead>
          <tr>
            <th>Identity</th><th>Authenticated As</th><th>Coding Agent</th><th>Model</th><th>OS</th>
            <th className="right">Sess.</th><th>Trust</th><th>State</th><th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className={`clickable ${r.id === selectedId ? "selected" : ""}`} onClick={() => onSelect(r.id)}>
              <td style={{ maxWidth: 230 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                  <span style={{ width: 26, height: 26, borderRadius: 7, flex: "none", display: "grid", placeItems: "center",
                    background: r.kind === "dev" ? "var(--blue-tint)" : "var(--purple-tint)", color: r.kind === "dev" ? "var(--blue-700)" : "var(--purple)" }}>
                    <Icon name={r.kind === "dev" ? "user" : "bot"} size={15} />
                  </span>
                  <span className="mono" style={{ fontSize: 12, color: "var(--ink)", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.principal || r.id}</span>
                </div>
              </td>
              <td className="sub">{r.email}</td>
              <td><span className="mono" style={{ fontSize: 11, padding: "2px 7px", borderRadius: 6, background: r.codingAgent === "codex" ? "var(--purple-tint)" : r.codingAgent === "kiro" ? "#FFF3E0" : "var(--blue-tint)", color: r.codingAgent === "codex" ? "var(--purple)" : r.codingAgent === "kiro" ? "#FF9900" : "var(--blue-700)" }}>{r.codingAgent === "codex" ? "Codex" : r.codingAgent === "kiro" ? "Kiro" : "Claude Code"}</span></td>
              <td><span className="mono" style={{ fontSize: 11.5, color: "var(--ink-3)" }}>{r.model}</span></td>
              <td className="sub">{r.os}</td>
              <td className="right mono" style={{ fontWeight: 600 }}>{r.sessions}</td>
              <td><TrustMeter value={r.trust} /></td>
              <td><Pill tone={STATE_TONE[r.state]} dot>{r.state}</Pill></td>
              <td className="right"><Kebab /></td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr><td colSpan={9} style={{ textAlign: "center", padding: "40px 0", color: "var(--ink-4)" }}>No identities match this filter.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function Inventory() {
  const [pivot, setPivot] = React.useState("Identity");
  const [selId, setSelId] = React.useState(ROSTER[0].id);
  const row = ROSTER.find((r) => r.id === selId) || ROSTER[0];
  return (
    <div style={{ padding: 28 }}>
      {/* toolbar */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
        <Search placeholder="Search identities, agents, emails…" width={320} />
        <Segmented options={["Session", "System", "Identity"]} value={pivot} onChange={setPivot} />
        <SelectChip>Type: All</SelectChip>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          <span className="help">{ROSTER.length} principals · grouped by {pivot}</span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 16, alignItems: "start" }}>
        <RosterTable rows={ROSTER} selectedId={selId} onSelect={setSelId} />
        <AgentDetail row={row} />
      </div>
    </div>
  );
}

function Field({ label, children, mono }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
      <span className="eyebrow" style={{ fontSize: 10.5 }}>{label}</span>
      <span className={mono ? "mono" : ""} style={{ fontSize: mono ? 12.5 : 13.5, color: "var(--ink)", fontWeight: mono ? 600 : 500, wordBreak: "break-all" }}>{children}</span>
    </div>
  );
}

function AgentDetail({ row }) {
  const quarantined = row.state === "Quarantined";
  const [appr, setAppr] = React.useState("idle"); // idle | sending | sent | noslack | error
  const osUserOfRow = () => (row.quarantine && row.quarantine.osUser) || (row.id.match(/"([^"]+)"/) || [])[1] || "";
  React.useEffect(() => { setAppr("idle"); }, [row.id]);
  const sendApproval = () => {
    const osUser = osUserOfRow();
    if (!osUser) return;
    setAppr("sending");
    fetch("/api/quarantine/request-approval", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ osUser }) })
      .then((r) => r.json())
      .then((d) => {
        if (d.ok) { setAppr("sent"); revaRefetch(); }
        else if (d.reason === "slack_not_configured") setAppr("noslack");
        else setAppr("error");
      })
      .catch(() => setAppr("error"));
  };
  return (
    <div className="card" style={{ overflow: "hidden", position: "sticky", top: 60 }}>
      <div style={{ padding: "16px 18px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 11 }}>
        <span style={{ width: 34, height: 34, borderRadius: 9, flex: "none", display: "grid", placeItems: "center",
          background: "var(--blue-tint)", color: "var(--blue-700)" }}>
          <Icon name="user" size={19} />
        </span>
        <div style={{ minWidth: 0 }}>
          <div className="section-title" style={{ fontSize: 14.5 }}>Developer Details</div>
          <div className="mono" style={{ fontSize: 11.5, color: "var(--ink-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.principal || row.id}</div>
        </div>
      </div>

      <div style={{ padding: 18, display: "flex", flexDirection: "column", gap: 16, maxHeight: "calc(100vh - 220px)", overflowY: "auto" }}>
        {quarantined && (
          <div style={{ background: "var(--red-tint)", border: "1px solid #F5C2C2", borderRadius: 10, padding: "12px 14px" }}>
            <div style={{ display: "flex", gap: 9 }}>
              <Icon name="lock" size={17} color="var(--red)" />
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: "var(--red)" }}>Access Quarantined</div>
                <div style={{ fontSize: 12.5, color: "#B42318", marginTop: 2 }}>
                  {(row.quarantine && row.quarantine.policyName) || "Isolation policy"}
                </div>
              </div>
            </div>
            {row.quarantine && row.quarantine.resolution === "Auto-Restore" ? (
              <div className="pill pill-amber" style={{ marginTop: 11, width: "100%", justifyContent: "center" }}><span className="status-pulse" style={{ marginRight: 4 }} />Auto-restoring…</div>
            ) : appr === "sent" || (row.quarantine && row.quarantine.status === "Approval sent") ? (
              <div className="pill pill-amber" style={{ marginTop: 11, width: "100%", justifyContent: "center" }}>Approval sent · awaiting resolution</div>
            ) : appr === "noslack" ? (
              <div style={{ marginTop: 11, fontSize: 12, color: "#B42318" }}>Slack isn't configured. Ask an admin to configure Slack under <b>Integrations</b> to send approval requests.</div>
            ) : (
              <button className="btn btn-danger btn-sm" style={{ marginTop: 11, width: "100%", background: "#fff", color: "var(--red)", border: "1px solid #F5C2C2" }} disabled={appr === "sending"} onClick={sendApproval}>
                <Icon name="send" size={13} /> {appr === "sending" ? "Sending…" : "Send Approval"}
              </button>
            )}
            {appr === "error" && <div style={{ fontSize: 12, color: "#B42318", marginTop: 6 }}>Couldn't send approval. Try again.</div>}
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <Field label="Authenticated As">{row.email}</Field>
          <Field label="Owner">{row.owner}</Field>
          <Field label="Active Sessions">{row.sessions}</Field>
        </div>

        <Field label={row.svidFallback ? "Agent ID (SVID fallback)" : "SPIFFE / SVID"} mono>{row.svid}</Field>
        {row.svidFallback && <div className="help" style={{ marginTop: -10, color: "var(--amber-ink)" }}>No SVID issued — using agent-hash fallback.</div>}

        <Field label="Coding Agent">{row.codingAgent === "codex" ? "Codex" : row.codingAgent === "kiro" ? "Kiro" : "Claude Code"}{row.surface ? " · " + row.surface : ""}</Field>
        <Field label="McpServers">
          {(row.mcp && row.mcp.length) ? (
            <span style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {row.mcp.map((m) => (
                <span key={m} className="mono" style={{ fontSize: 11.5, padding: "3px 9px", borderRadius: 6, background: "var(--blue-tint)", color: "var(--blue-700)", border: "1px solid var(--border)", fontWeight: 600 }}>{m}</span>
              ))}
            </span>
          ) : <span style={{ color: "var(--ink-3)" }}>—</span>}
        </Field>
        {row.codingAgent === "kiro" && (row.kiroAccountType || row.kiroEmail || row.kiroRegion || row.kiroStartUrl || row.kiroProfileArn) && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#FF9900", textTransform: "uppercase", letterSpacing: "0.4px", marginTop: 8 }}>Kiro Identity (AWS)</div>
            {row.kiroAccountType ? <Field label="Auth Method"><span className="mono" style={{ padding: "2px 7px", borderRadius: 6, background: "#FFF3E0", color: "#FF9900", fontSize: 11 }}>{row.kiroAccountType}</span></Field> : null}
            {row.kiroEmail ? <Field label="Kiro Email">{row.kiroEmail}</Field> : null}
            {row.kiroRegion ? <Field label="AWS Region" mono>{row.kiroRegion}</Field> : null}
            {row.kiroStartUrl ? <Field label="Identity Center URL" mono>{row.kiroStartUrl}</Field> : null}
            {row.kiroProfileArn ? <Field label="Profile ARN" mono>{row.kiroProfileArn}</Field> : null}
          </div>
        )}
        {row.codingAgent !== "kiro" && (row.accountUuid || row.orgUuid) && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {row.accountUuid ? <Field label={(row.codingAgent === "codex" ? "OpenAI" : "Anthropic") + " Account ID"} mono>{row.accountUuid}</Field> : null}
            {row.orgUuid ? <Field label={(row.codingAgent === "codex" ? "OpenAI" : "Anthropic") + " Org ID"} mono>{row.orgUuid}</Field> : null}
          </div>
        )}

        {row.jit && row.jit.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--blue-700)", textTransform: "uppercase", letterSpacing: "0.4px", marginTop: 8 }}>JIT — Short-Lived Credentials</div>
            {row.jit.map((j) => (
              <div key={j.id} style={{ border: "1px solid var(--border)", borderRadius: 10, padding: "11px 13px", background: "var(--surface-2)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span className="mono" style={{ fontSize: 12.5, fontWeight: 700, color: "var(--ink)" }}>{j.action || "privileged op"}</span>
                  <span className={"pill pill-" + (j.state === "active" ? "green" : j.state === "revoked" ? "red" : "amber")} style={{ marginLeft: "auto" }}><span className="dot" />{j.state}</span>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 12, marginTop: 8 }}>
                  <span className="help">approved by: <span className="mono" style={{ color: "var(--ink-2)" }}>{j.approver || "—"}</span></span>
                  {j.project ? <span className="help">project: <span className="mono" style={{ color: "var(--ink-2)" }}>{j.project}</span></span> : null}
                  <span className="help">issued: <span className="mono" style={{ color: "var(--ink-2)" }}>{relTime(j.issuedAt)}</span></span>
                  <span className="help">expires: <span className="mono" style={{ color: "var(--ink-2)" }}>{new Date(j.expiresAt).toLocaleTimeString()}</span></span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SessionsPanel({ row, terminated }) {
  const termSet = new Set(terminated || []);
  const sessions = row.sessionsList || [];
  const relTimeP = (iso) => {
    if (!iso) return "";
    const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
    if (m < 1) return "just now"; if (m < 60) return m + "m ago";
    const h = Math.floor(m / 60); if (h < 24) return h + "h ago"; return Math.floor(h / 24) + "d ago";
  };
  return (
    <div className="card" style={{ overflow: "hidden", position: "sticky", top: 60 }}>
      <div style={{ padding: "16px 18px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 11 }}>
        <span style={{ width: 34, height: 34, borderRadius: 9, flex: "none", display: "grid", placeItems: "center", background: "var(--blue-tint)", color: "var(--blue-700)" }}>
          <Icon name="list" size={19} />
        </span>
        <div style={{ minWidth: 0 }}>
          <div className="section-title" style={{ fontSize: 14.5 }}>Sessions</div>
          <div className="mono" style={{ fontSize: 11.5, color: "var(--ink-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.id}</div>
        </div>
      </div>
      <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10, maxHeight: "calc(100vh - 220px)", overflowY: "auto" }}>
        {sessions.length === 0 && <div className="help" style={{ textAlign: "center", padding: 20 }}>No active sessions.</div>}
        {sessions.map((sx) => {
          const isTerm = termSet.has(sx.session_id);
          const conn = sx.entrypoint === "remote" ? "Browser" : (sx.connection_type === "ssh" ? "SSH" : "Local");
          const os = sx.os_type || sx.remote_os || "";
          return (
            <div key={sx.session_id} style={{ border: "1px solid var(--border)", borderRadius: 10, padding: "12px 14px", background: "var(--surface-2)", opacity: isTerm ? 0.62 : 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span className="mono" style={{ fontSize: 12.5, fontWeight: 700, color: "var(--ink)" }}>{String(sx.session_id || "").slice(0, 14)}</span>
                {isTerm
                  ? <span className="pill pill-red" style={{ marginLeft: 4 }}><span className="dot" />Terminated</span>
                  : <span className="pill pill-green" style={{ marginLeft: 4 }}><span className="dot" />Active</span>}
                <span className="help" style={{ marginLeft: "auto" }}>{relTimeP(sx.enrolled_at)}</span>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 14, marginTop: 9 }}>
                {sx.entrypoint ? <span className="help">surface: <span className="mono" style={{ color: "var(--ink-2)" }}>{sx.entrypoint}</span></span> : null}
                <span className="help">connection: <span className="mono" style={{ color: "var(--ink-2)" }}>{conn}</span></span>
                {os ? <span className="help">os: <span className="mono" style={{ color: "var(--ink-2)" }}>{os}</span></span> : null}
                {sx.hostname ? <span className="help">host: <span className="mono" style={{ color: "var(--ink-2)" }}>{sx.hostname}</span></span> : null}
                {sx.model ? <span className="help">model: <span className="mono" style={{ color: "var(--ink-2)" }}>{sx.model}</span></span> : null}
                {sx.project_name ? <span className="help">project: <span className="mono" style={{ color: "var(--ink-2)" }}>{sx.project_name}</span></span> : null}
                {sx.git_branch ? <span className="help">branch: <span className="mono" style={{ color: "var(--ink-2)" }}>{sx.git_branch}</span></span> : null}
                {sx.git_remote_url ? <span className="help">remote: <span className="mono" style={{ color: "var(--ink-2)" }}>{sx.git_remote_url}</span></span> : null}
                {conn === "SSH" && sx.ssh_client_ip ? <span className="help">ssh ip: <span className="mono" style={{ color: "var(--ink-2)" }}>{sx.ssh_client_ip}</span></span> : null}
                {sx.jira_ticket_id ? <span className="help">jira: <span className="mono" style={{ color: "var(--ink-2)" }}>{sx.jira_ticket_id}</span></span> : null}
              </div>
              {isTerm
                ? <button className="btn btn-sm" disabled style={{ marginTop: 11, width: "100%", background: "var(--surface-2)", color: "var(--ink-3)", border: "1px solid var(--border)", cursor: "default" }}>Terminated</button>
                : <button className="btn btn-sm" style={{ marginTop: 11, width: "100%", background: "#fff", color: "var(--red)", border: "1px solid #F5C2C2" }} onClick={() => revaTerminateSession(sx.session_id, true)}>Terminate session</button>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

window.Inventory = Inventory;
Object.assign(window, { ROSTER, STATE_TONE, RosterTable, AgentDetail });

/* ===================== decisionlogs.jsx ===================== */
/* global React, Icon, Pill, Search, Segmented, SelectChip */
/* Decision Logs — forensic feed with inline expansion (delegation chain + JSON context) */

const LOGS = [
  {
    time: "14:32:09", trace: "trc_8f2a4c1e", count: 3, idShort: 'saisrungaram', kind: "dev",
    action: "RunBash", target: "rm -rf ./build/cache", effect: "Deny", reason: "Destructive command",
    chain: [
      { id: 'Developer::"saisrungaram"', task: "session root", dot: "denied" },
    ],
    ctx: {
      identity: 'Developer::"saisrungaram"', file_zone: "n/a", action: "RunBash",
      command_class: "Destructive", declared_scope: "refactor build pipeline",
      initial_scope: "refactor build pipeline", injection_score: 8, drift_score: 12,
      trust: 58, git_pip: { branch: "main", protected: true }, jira_pip: { ticket: "PLT-4471", status: "In Progress" },
      decision: "Deny",
    },
  },
  {
    time: "14:31:50", trace: "trc_8f2a4c1e", grouped: true, idShort: 'saisrungaram', kind: "dev",
    action: "ReadFile", target: "secrets/prod.env", effect: "Deny", reason: "Secret zone",
    ctx: { identity: 'Developer::"saisrungaram"', file_zone: "Secret", action: "ReadFile", glob: "secrets/**", trust: 58, decision: "Deny" },
  },
  {
    time: "14:29:12", trace: "trc_7c10ab93", count: 2, idShort: 'agent-7c10', kind: "agent",
    action: "SpawnAgent", target: "agent-7c10 · scope: deploy", effect: "Deny", reason: "Scope drift",
    chain: [
      { id: 'Developer::"amartya.k"', task: "session root", dot: "allowed" },
      { id: 'Agent::"agent-7c10"', task: "spawned: refactor api → attempted deploy", dot: "drifted" },
    ],
    ctx: {
      identity: 'Agent::"amartya.k:agent-7c10"', action: "SpawnAgent",
      declared_scope: "refactor api endpoints", initial_scope: "refactor api endpoints",
      observed_intent: "deploy to production", drift_score: 71, injection_score: 14, trust: 64,
      delegation_depth: 2, decision: "Deny",
    },
  },
  {
    time: "14:24:38", trace: "trc_5d91ff02", idShort: 'd.okonkwo', kind: "dev",
    action: "MCPWrite", target: "jira-mcp → PLT-4471", effect: "HITL", reason: "High-sensitivity action",
    ctx: { identity: 'Developer::"d.okonkwo"', action: "MCPWrite", mcp_server: "jira-mcp", hitl_channel: "#ai-approvals", trust: 78, decision: "HITL (awaiting)" },
  },
  {
    time: "14:20:01", trace: "trc_5d91ff02", grouped: true, idShort: 'd.okonkwo', kind: "dev",
    action: "EditFile", target: "src/api/routes.ts", effect: "Permit", reason: "Declared scope ok",
    ctx: { identity: 'Developer::"d.okonkwo"', file_zone: "Internal", action: "EditFile", declared_scope: "add rate limiting", drift_score: 4, trust: 78, decision: "Permit" },
  },
  {
    time: "14:12:47", trace: "trc_2b71f8a3", idShort: 'amartya.k', kind: "dev",
    action: "SpawnAgent", target: "agent-d4ee · scope: tests", effect: "Deny", reason: "Spawn budget 5/5",
    ctx: { identity: 'Developer::"amartya.k"', action: "SpawnAgent", spawn_used: 5, spawn_max: 5, trust: 64, decision: "Deny" },
  },
  {
    time: "14:05:33", trace: "trc_a17e0c44", idShort: 'l.nakamura', kind: "dev",
    action: "ReadFile", target: "README.md", effect: "Permit", reason: "Public zone",
    ctx: { identity: 'Developer::"l.nakamura"', file_zone: "Public", action: "ReadFile", trust: 85, decision: "Permit" },
  },
];

const EFF_TONE = { Permit: "green", Deny: "red", HITL: "amber" };

function JsonView({ obj, depth = 0 }) {
  const entries = Object.entries(obj);
  return (
    <div style={{ paddingLeft: depth ? 16 : 0 }}>
      {entries.map(([k, v], i) => {
        const isObj = v && typeof v === "object" && !Array.isArray(v);
        return (
          <div key={k} style={{ lineHeight: 1.8 }}>
            <span className="tok-key">"{k}"</span><span style={{ color: "#94A3B8" }}>: </span>
            {isObj ? <JsonView obj={v} depth={depth + 1} /> : (
              <span className={typeof v === "number" ? "tok-num" : typeof v === "boolean" ? "tok-num" : "tok-str"}>
                {typeof v === "string" ? `"${v.replace(/"/g, '\\"')}"` : String(v)}
              </span>
            )}
            {i < entries.length - 1 && !isObj && <span style={{ color: "#94A3B8" }}>,</span>}
          </div>
        );
      })}
    </div>
  );
}

function DelegationSpine({ chain }) {
  const dotColor = { allowed: "var(--green)", denied: "var(--red)", drifted: "var(--amber)" };
  return (
    <div style={{ position: "relative", paddingLeft: 4 }}>
      {chain.map((n, i) => (
        <div key={i} style={{ display: "flex", gap: 12, position: "relative", paddingBottom: i < chain.length - 1 ? 18 : 0 }}>
          {i < chain.length - 1 && <span style={{ position: "absolute", left: 6, top: 14, bottom: -4, width: 2, background: "var(--border-strong)" }} />}
          <span style={{ width: 14, height: 14, borderRadius: "50%", background: dotColor[n.dot], flex: "none", marginTop: 2, boxShadow: "0 0 0 3px #fff" }} />
          <div>
            <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: "var(--ink)" }}>{n.id}</div>
            <div className="help">{n.task}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function LogRow({ row, open, onToggle }) {
  return (
    <>
      <tr className="clickable" onClick={onToggle} style={row.grouped ? { background: "var(--surface-2)" } : null}>
        <td style={{ width: 28 }}>
          {!row.grouped && <Icon name={open ? "chevDown" : "chevRight"} size={16} color="var(--ink-4)" />}
        </td>
        <td className="mono" style={{ fontSize: 12, color: "var(--ink-3)" }}>{row.time}</td>
        <td>
          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <span className="mono" style={{ fontSize: 12, color: row.grouped ? "var(--ink-4)" : "var(--ink-2)", fontWeight: 600 }}>{row.trace}</span>
            {row.count && <span style={{ fontSize: 10.5, fontWeight: 700, padding: "1px 6px", borderRadius: 999, background: "var(--surface-3)", color: "var(--ink-3)" }}>{row.count}</span>}
          </div>
        </td>
        <td>
          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <Icon name={row.kind === "dev" ? "user" : "bot"} size={14} color={row.kind === "dev" ? "var(--blue)" : "var(--purple)"} />
            <span className="mono" style={{ fontSize: 12, color: "var(--ink)", fontWeight: 600 }}>{row.idShort}</span>
          </div>
        </td>
        <td><span className="mono" style={{ fontSize: 12, fontWeight: 600, color: "var(--ink-2)" }}>{row.action}</span></td>
        <td className="mono" style={{ fontSize: 11.5, color: "var(--ink-3)", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.target}</td>
        <td><Pill tone={EFF_TONE[row.effect]} dot>{row.effect}</Pill></td>
        <td className="sub" style={{ fontSize: 12.5 }}>{row.reason}</td>
      </tr>
      {open && !row.grouped && (
        <tr>
          <td colSpan={8} style={{ padding: 0, background: "var(--surface-2)" }}>
            <div style={{ display: "grid", gridTemplateColumns: row.chain ? "300px 1fr" : "1fr", gap: 0 }}>
              {row.chain && (
                <div style={{ padding: "18px 22px", borderRight: "1px solid var(--border)" }}>
                  <div className="eyebrow" style={{ fontSize: 10.5, marginBottom: 14 }}>Delegation chain · {row.trace}</div>
                  <DelegationSpine chain={row.chain} />
                </div>
              )}
              <div style={{ padding: "18px 22px" }}>
                <div className="eyebrow" style={{ fontSize: 10.5, marginBottom: 12 }}>Evaluated context (Cedar)</div>
                <div className="code" style={{ padding: "14px 16px" }}>
                  <span style={{ color: "#94A3B8" }}>{"{"}</span>
                  <JsonView obj={row.ctx} />
                  <span style={{ color: "#94A3B8" }}>{"}"}</span>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function DecisionLogs() {
  const reva = useReva();
  const LOGS = reva.logs;
  const [pivot, setPivot] = React.useState("Session");
  const [open, setOpen] = React.useState(0);
  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <Search placeholder="Search trace, identity, target…" width={300} />
        <Segmented options={["Session", "System", "Identity"]} value={pivot} onChange={setPivot} />
        <SelectChip>Deny reason</SelectChip>
        <SelectChip>Action</SelectChip>
        <SelectChip>Last 24h</SelectChip>
        <div style={{ marginLeft: "auto" }}><button className="btn btn-ghost btn-sm"><Icon name="ext" size={15} /> Export</button></div>
      </div>

      <div className="card" style={{ overflow: "hidden" }}>
        <table className="tbl">
          <thead>
            <tr>
              <th></th><th>Time</th><th>Trace / Session</th><th>Identity</th>
              <th>Action</th><th>Target</th><th>Effect</th><th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {LOGS.map((r, i) => (
              <LogRow key={i} row={r} open={open === i} onToggle={() => setOpen(open === i ? -1 : i)} />
            ))}
          </tbody>
        </table>
      </div>
      <div className="help" style={{ marginTop: 14, textAlign: "center" }}>Showing {LOGS.length} decisions · grouped by trace</div>
    </div>
  );
}

window.DecisionLogs = DecisionLogs;

/* ===================== devintegration.jsx ===================== */
/* global React, Icon, Toggle */
/* Developer Integration — exactly three accordions */

function Accordion({ title, subtitle, open, onToggle, children, saved }) {
  return (
    <div className="card" style={{ overflow: "hidden", marginBottom: 16 }}>
      <button onClick={onToggle} style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, padding: "18px 20px", background: "transparent", border: 0, textAlign: "left" }}>
        <Icon name={open ? "chevDown" : "chevRight"} size={18} color="var(--ink-3)" />
        <div style={{ flex: 1 }}>
          <div className="section-title">{title}</div>
          {subtitle && <div className="help" style={{ marginTop: 2 }}>{subtitle}</div>}
        </div>
        {saved && <span className="help" style={{ fontSize: 11.5 }}>Last saved {saved}</span>}
      </button>
      {open && <div style={{ borderTop: "1px solid var(--border)" }}>{children}</div>}
    </div>
  );
}

function ChipList({ tone, label, value, onChange }) {
  const chips = value || [];
  const [val, setVal] = React.useState("");
  const add = () => { if (val.trim()) { onChange([...chips, val.trim()]); setVal(""); } };
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 12, padding: 14, background: "var(--surface-2)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 11 }}>
        <span style={{ width: 8, height: 8, borderRadius: 3, background: `var(--${tone})` }} />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--ink)" }}>{label}</span>
        <span className="help" style={{ marginLeft: "auto" }}>{chips.length}</span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 7, marginBottom: 11 }}>
        {chips.map((c, i) => (
          <span key={c + i} className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11.5, fontWeight: 600, padding: "4px 8px", borderRadius: 7, background: "#fff", border: "1px solid var(--border)", color: "var(--ink-2)" }}>
            {c}
            <button onClick={() => onChange(chips.filter((_, j) => j !== i))} style={{ border: 0, background: "transparent", padding: 0, display: "grid", placeItems: "center", color: "var(--ink-4)", cursor: "pointer" }}><Icon name="x" size={12} /></button>
          </span>
        ))}
      </div>
      <div style={{ display: "flex", gap: 8 }}>
        <input value={val} onChange={(e) => setVal(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()}
          placeholder="+ Add command" className="mono"
          style={{ flex: 1, height: 32, border: "1px solid var(--border-strong)", borderRadius: 7, padding: "0 10px", fontSize: 12, outline: "none", background: "#fff" }} />
      </div>
    </div>
  );
}

const ZONES = [
  { zone: "Public", tone: "green", globs: ["README.md", "docs/**", "*.md"], desc: "Freely readable" },
  { zone: "Internal", tone: "blue", globs: ["src/**", "*.ts", "*.py"], desc: "Default working zone" },
  { zone: "Sensitive", tone: "amber", globs: ["config/**", "infra/**", "*.tfstate"], desc: "Drift-monitored" },
  { zone: "Secret", tone: "red", globs: [".env", "*.pem", "secrets/**", "*.key"], desc: "Read denied to agents" },
];

function SaveBar({ onSave }) {
  return (
    <div style={{ display: "flex", alignItems: "center", padding: "14px 20px", borderTop: "1px solid var(--border)", background: "var(--surface-2)" }}>
      <span className="help">Changes apply to all sessions on next prompt.</span>
      <button className="btn btn-primary btn-sm" style={{ marginLeft: "auto" }} onClick={onSave}>Save</button>
    </div>
  );
}

function DeveloperIntegration() {
  const reva = useReva();
  const [open, setOpen] = React.useState(0);
  const toggle = (i) => setOpen(open === i ? -1 : i);

  // Command chips — seeded from live config, edited locally, saved on demand.
  const [cmd, setCmd] = React.useState(reva.commands || { safe: [], restricted: [], destructive: [] });
  const [zones, setZones] = React.useState(reva.filezones || []);
  React.useEffect(() => { setCmd(reva.commands || { safe: [], restricted: [], destructive: [] }); }, [reva.commands]);
  React.useEffect(() => { setZones(reva.filezones || []); }, [reva.filezones]);

  const hitlCfg = reva.hitl || {};
  const slackConnected = !!hitlCfg.slack_connected;
  const hitlEnabled = hitlCfg.enabled !== false;
  const provider = hitlCfg.integration === "okta" ? "Okta Verify" : "Slack";

  const post = async (path, body) => {
    try { await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); await revaLoadConfigs(); } catch (e) {}
  };
  const saveCommands = () => post("/api/config/commands", cmd);
  const saveZones = () => post("/api/config/filezones", { zones });
  const setHitl = (on) => post("/api/config/hitl", { enabled: on });
  const setProvider = (p) => { if (p === "Slack" && !slackConnected) return; post("/api/config/hitl", { integration: p === "Okta Verify" ? "okta" : "slack" }); };
  const addGlob = (zi) => { const g = window.prompt("Add glob pattern (e.g. src/** or *.pem)"); if (g && g.trim()) setZones(zones.map((z, i) => i === zi ? { ...z, globs: [...z.globs, g.trim()] } : z)); };
  const removeGlob = (zi, gi) => setZones(zones.map((z, i) => i === zi ? { ...z, globs: z.globs.filter((_, j) => j !== gi) } : z));

  return (
    <div style={{ padding: 28, maxWidth: 1080 }}>
      {/* 1. Command Classification */}
      <Accordion title="Command Classification" subtitle="Feeds the destructive-command guardrail at RunBash." open={open === 0} onToggle={() => toggle(0)}>
        <div style={{ padding: 20 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 14 }}>
            <ChipList tone="green" label="Safe" value={cmd.safe} onChange={(v) => setCmd({ ...cmd, safe: v })} />
            <ChipList tone="amber" label="Restricted" value={cmd.restricted} onChange={(v) => setCmd({ ...cmd, restricted: v })} />
            <ChipList tone="red" label="Destructive" value={cmd.destructive} onChange={(v) => setCmd({ ...cmd, destructive: v })} />
          </div>
        </div>
        <SaveBar onSave={saveCommands} />
      </Accordion>

      {/* 2. File Sensitivity */}
      <Accordion title="File Sensitivity Classification" subtitle="Sets the file_zone attribute used in drift and injection evaluation." open={open === 1} onToggle={() => toggle(1)}>
        <table className="tbl">
          <thead><tr><th>Zone</th><th>Glob patterns</th><th>Behavior</th></tr></thead>
          <tbody>
            {zones.map((z, zi) => (
              <tr key={z.zone}>
                <td style={{ width: 140 }}><span className={`pill pill-${z.tone}`}><span className="dot" />{z.zone}</span></td>
                <td>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {z.globs.map((g, gi) => (
                      <span key={g + gi} className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11.5, padding: "3px 8px", borderRadius: 6, background: "var(--surface-3)", color: "var(--ink-2)", fontWeight: 600 }}>
                        {g}
                        <button onClick={() => removeGlob(zi, gi)} style={{ border: 0, background: "transparent", padding: 0, display: "grid", placeItems: "center", color: "var(--ink-4)", cursor: "pointer" }}><Icon name="x" size={11} /></button>
                      </span>
                    ))}
                    <button className="kebab" style={{ width: 26, height: 26 }} onClick={() => addGlob(zi)}><Icon name="plus" size={14} /></button>
                  </div>
                </td>
                <td className="sub" style={{ fontSize: 12.5 }}>{z.desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <SaveBar onSave={saveZones} />
      </Accordion>

      {/* 3. HITL */}
      <Accordion title="HITL" subtitle="Human-in-the-loop approvals for high-sensitivity actions." open={open === 2} onToggle={() => toggle(2)}>
        <div style={{ padding: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "14px 16px", border: "1px solid var(--border)", borderRadius: 12 }}>
            <Icon name="lock" size={20} color="var(--blue)" />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13.5, fontWeight: 700, color: "var(--ink)" }}>Require human approval for high-sensitivity actions</div>
              <div className="help" style={{ marginTop: 2 }}>Protected-branch writes, Secret-zone access, and MCP writes pause for approval.</div>
            </div>
            <Toggle on={hitlEnabled} onClick={() => setHitl(!hitlEnabled)} />
          </div>

          <div style={{ marginTop: 16, opacity: hitlEnabled ? 1 : 0.45, pointerEvents: hitlEnabled ? "auto" : "none", transition: "opacity .2s" }}>
            <div className="eyebrow" style={{ fontSize: 10.5, marginBottom: 10 }}>Approval provider</div>
            <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
              {["Slack", "Okta Verify"].map((p) => {
                const disabled = p === "Slack" && !slackConnected;
                return (
                  <button key={p} onClick={() => setProvider(p)} disabled={disabled} title={disabled ? "Connect Slack in Integrations first" : ""} style={{
                    flex: 1, display: "flex", alignItems: "center", gap: 11, padding: "14px 16px", textAlign: "left",
                    border: `1.5px solid ${provider === p ? "var(--blue)" : "var(--border-strong)"}`, borderRadius: 12,
                    background: provider === p ? "var(--blue-tint)" : "#fff", cursor: disabled ? "not-allowed" : "pointer",
                    opacity: disabled ? 0.5 : 1,
                  }}>
                    <span style={{ width: 18, height: 18, borderRadius: "50%", border: `2px solid ${provider === p ? "var(--blue)" : "var(--border-strong)"}`, display: "grid", placeItems: "center" }}>
                      {provider === p && <span style={{ width: 9, height: 9, borderRadius: "50%", background: "var(--blue)" }} />}
                    </span>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: "var(--ink)" }}>{p}</div>
                      <div className="help" style={{ fontSize: 11.5 }}>{p === "Slack" ? (slackConnected ? "Channel approval card" : "Not connected") : "Mobile push approval"}</div>
                    </div>
                  </button>
                );
              })}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "12px 14px", background: "var(--surface-2)", borderRadius: 10, border: "1px solid var(--border)" }}>
              {provider === "Slack"
                ? (slackConnected
                    ? <span className="pill pill-green"><span className="dot" />Slack {hitlCfg.slack_channel || "#approvals"} — connected</span>
                    : <span className="pill pill-amber"><span className="dot" />Slack — not connected</span>)
                : <span className="pill pill-green"><span className="dot" />Okta Verify — connected</span>}
              <a href="#" className="help" style={{ marginLeft: "auto", color: "var(--blue)", fontWeight: 600, textDecoration: "none" }}>Configure providers in Integrations → Approval Channel →</a>
            </div>
          </div>
        </div>
      </Accordion>
    </div>
  );
}

window.DeveloperIntegration = DeveloperIntegration;

/* ===================== settings.jsx ===================== */
/* global React, Icon, Pill, Toggle */
/* Settings — registration & risky-action detection */

function SettingsCard({ title, subtitle, children }) {
  return (
    <div className="card" style={{ marginBottom: 16, overflow: "hidden" }}>
      <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)" }}>
        <div className="section-title">{title}</div>
        {subtitle && <div className="help" style={{ marginTop: 2 }}>{subtitle}</div>}
      </div>
      {children}
    </div>
  );
}

function Row({ label, children, last }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "14px 20px", borderBottom: last ? 0 : "1px solid var(--border)" }}>
      <div style={{ flex: 1 }}>{label}</div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>{children}</div>
    </div>
  );
}

const DETECTORS = [
  { name: "Prompt Injection Detection", desc: "Score every prompt and tool result for injection.", key: "prompt_injection" },
  { name: "Intent Drift Attribution", desc: "Compare observed intent against declared scope and attribute drift.", key: "intent_drift" },
  { name: "Commands Classification", desc: "Classify RunBash commands as safe, restricted, or destructive.", key: "commands_classification", dev: true },
  { name: "File Sensitivity", desc: "Gate reads/writes by file_zone classification.", key: "file_sensitivity", dev: true },
  { name: "Quarantine Access", desc: "Quarantine developers on repeated authorization denials.", key: "quarantine_access" },
];

async function saveSecurity(patch) {
  try {
    const r = await fetch("/api/config/security", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(patch) });
    const cfg = await r.json();
    RevaStore.set({ security: cfg });
  } catch (e) { /* keep UI responsive */ }
}


function Detector({ d, on, onToggle }) {
  return (
    <Row label={
      <div>
        <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink)" }}>{d.name}</div>
        <div className="help" style={{ marginTop: 2 }}>{d.desc}</div>
      </div>
    }>
      {d.dev && (
        <span className="help" style={{ fontSize: 12, color: on ? "var(--ink-3)" : "var(--amber-ink)" }}>
          {on
            ? <>Configured in <a href="#" style={{ color: "var(--blue)", fontWeight: 600, textDecoration: "none" }}>Developer Integration</a></>
            : "Disables its config in Developer Integration"}
        </span>
      )}
      <Toggle on={on} onClick={onToggle} />
    </Row>
  );
}

const HITL_MAP = [
  { os: "saisrungaram", email: "sai.s@acme.io" },
  { os: "amartya.k", email: "amartya.k@acme.io" },
  { os: "d.okonkwo", email: "d.okonkwo@acme.io" },
  { os: "l.nakamura", email: "l.nakamura@acme.io" },
];

function SettingsTab() {
  const reva = useReva();
  const sec = reva.security || {};
  const [danger, setDanger] = React.useState(false);
  return (
    <div style={{ padding: 28, maxWidth: 980 }}>
      {/* Policy Store */}
      <SettingsCard title="Policy Store" subtitle="Where this workload's policies are authored and published.">
        <Row label={<span style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink)" }}>Policy Store Type</span>}>
          <Pill tone="purple">Cedar</Pill><span className="help">read-only</span>
        </Row>
        <Row label={<span style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink)" }}>Policy Publish Destination</span>}>
          <button className="selchip">Reva Managed</button>
        </Row>
        <Row last label={<span style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink)" }}>Schema Version</span>}>
          <Pill tone="blue">v7</Pill>
          <a href="#" className="help" style={{ color: "var(--blue)", fontWeight: 600, textDecoration: "none" }}>View schema →</a>
        </Row>
      </SettingsCard>

      {/* Security Settings */}
      <SettingsCard title="Security Settings" subtitle="Detection capabilities that feed Cedar evaluation. Enabled by default.">
        {DETECTORS.map((d) => {
          const on = sec[d.key] !== false;
          return <Detector key={d.name} d={d} on={on} onToggle={() => saveSecurity({ [d.key]: !on })} />;
        })}
      </SettingsCard>


      {/* Identity */}
      <SettingsCard title="Identity" subtitle="Agent identity attestation and approver mapping.">
        <Row label={<span style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink)" }}>SPIFFE / SPIRE Status</span>}>
          <Pill tone="green" dot>SVID active</Pill>
          <span className="help">hash fallback for unsigned agents</span>
        </Row>
        <div style={{ padding: "4px 20px 16px" }}>
          <div className="eyebrow" style={{ fontSize: 10.5, margin: "10px 0" }}>HITL email mapping</div>
          <div style={{ border: "1px solid var(--border)", borderRadius: 10, overflow: "hidden" }}>
            <table className="tbl">
              <thead><tr><th>osUser</th><th>Approver email</th><th className="right"></th></tr></thead>
              <tbody>
                {HITL_MAP.map((m, i) => (
                  <tr key={m.os}>
                    <td className="mono" style={{ fontSize: 12.5, fontWeight: 600, color: "var(--ink)" }}>{m.os}</td>
                    <td className="mono" style={{ fontSize: 12.5, color: "var(--ink-2)" }}>{m.email}</td>
                    <td className="right"><button className="btn btn-text btn-sm">Edit</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </SettingsCard>

      {/* Danger zone */}
      <div className="card" style={{ borderColor: "#F3C9C9", overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 10 }}>
          <Icon name="alert" size={18} color="var(--red)" />
          <div className="section-title" style={{ color: "var(--red)" }}>Danger Zone</div>
        </div>
        <Row last label={
          <div>
            <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink)" }}>Disable governance for this workload</div>
            <div className="help" style={{ marginTop: 2 }}>All Claude Code prompts and tool calls will bypass Cedar enforcement.</div>
          </div>
        }>
          <button className="btn btn-sm" style={{ background: "#fff", color: "var(--red)", border: "1px solid #F3C9C9" }} onClick={() => setDanger(true)}>Disable governance</button>
        </Row>
      </div>

      {danger && (
        <>
          <div onClick={() => setDanger(false)} style={{ position: "fixed", inset: 0, background: "rgba(11,18,32,.4)", zIndex: 40 }} />
          <div style={{ position: "fixed", top: "50%", left: "50%", transform: "translate(-50%,-50%)", width: 440, background: "#fff", borderRadius: 16, zIndex: 41, boxShadow: "var(--shadow-pop)", overflow: "hidden" }}>
            <div style={{ padding: "22px 24px" }}>
              <div style={{ display: "flex", gap: 12 }}>
                <span style={{ width: 38, height: 38, borderRadius: 10, background: "var(--red-tint)", color: "var(--red)", display: "grid", placeItems: "center", flex: "none" }}><Icon name="alert" size={20} /></span>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: "var(--ink)" }}>Disable governance?</div>
                  <div className="sub" style={{ marginTop: 6, fontSize: 13 }}>Cedar enforcement stops for all developers on this workload. Quarantines remain but new denials won't trigger. This is logged and notifies workload owners.</div>
                </div>
              </div>
            </div>
            <div style={{ padding: "14px 24px", borderTop: "1px solid var(--border)", display: "flex", justifyContent: "flex-end", gap: 10 }}>
              <button className="btn btn-text" onClick={() => setDanger(false)}>Cancel</button>
              <button className="btn btn-danger" onClick={() => setDanger(false)}>Disable governance</button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

window.SettingsTab = SettingsTab;

/* ===================== integrations.jsx ===================== */
/* global React, Icon, Pill, Toggle, Segmented, LogoTile, Mark */
/* Integrations directory + Create Integration wizard (Select Type → Configure → Instructions) */

const TYPE_TONE = {
  "Policy Store": "blue", "Identity Store": "purple", "Shared Signal": "amber",
  "AI Workload": "green", "AI Coding Agent": "green", "Approval Channel": "blue",
  "Analytics Source": "purple", "API Gateway": "gray", "CMDB": "gray", "Discovered": "gray",
};

const INTEGRATION_TYPES = ["Policy Store", "Identity Store", "Shared Signal", "AI Workload", "API Gateway", "CMDB", "Approval Channel", "Analytics Source"];

const CONNECTORS = [
  { name: "Claude Code", brand: "anthropic", types: ["AI Coding Agent"], featured: true, on: true,
    desc: "Cedar-enforced governance for every Claude Code prompt and tool call.", foot: "Patrick Fuller · 96 agents · last seen 4m ago" },
  { name: "AWS", brand: "aws", types: ["Policy Store"], on: true,
    desc: "Amazon Verified Permissions (AVP) policy store for account 732029699072.", foot: "Platform Sec · last sync 2m ago" },
  { name: "S3", brand: "s3", types: ["Policy Store"], on: true,
    desc: "Policy Store for Reva Trust Gateway — versioned Cedar bundles.", foot: "Platform Sec · last sync 5m ago" },
  { name: "AWS Cognito", brand: "cognito", types: ["Identity Store"], on: true,
    desc: "Cognito user pool for automated testing and integration validation.", foot: "IAM · 312 users" },
  { name: "Microsoft Entra ID", brand: "entra", types: ["Identity Store", "Shared Signal"], on: true,
    desc: "Entra ID (Azure AD) production user & group identity, plus access security signals.", foot: "IAM · 1,284 users" },
  { name: "Okta", brand: "okta", types: ["Identity Store", "Shared Signal"], on: true,
    desc: "Okta identity provider for enterprise SSO and access management signals.", foot: "IAM · 1,284 users" },
  { name: "CrowdStrike", brand: "crowdstrike", types: ["Shared Signal"], on: true,
    desc: "CrowdStrike Falcon endpoint detection and response signals.", foot: "SecOps · streaming" },
  { name: "GitHub AI Discovery", brand: "github", types: ["AI Workload"], on: true,
    desc: "Discover AI workloads and coding agents from GitHub repositories.", foot: "Platform Sec · 41 repos" },
  { name: "Amazon Bedrock AgentCore", brand: "bedrock", types: ["AI Workload"], on: true,
    desc: "Discover and govern AI agents running on AWS Bedrock.", foot: "Platform Sec · 12 agents" },
  { name: "n8n Production Discovery", brand: "n8n", types: ["AI Workload"], on: false,
    desc: "Automated discovery of AI workflows from an n8n production instance via webhook.", foot: "Automation · webhook" },
  { name: "Slack", brand: "slack", types: ["Approval Channel"], on: true,
    desc: "Route human-in-the-loop approvals to a Slack channel.", foot: "#ai-approvals · connected" },
  { name: "Okta Verify", brand: "oktaverify", types: ["Approval Channel"], on: false,
    desc: "Push approval requests to Okta Verify on mobile.", foot: "Not configured" },
  { name: "Anthropic Analytics", brand: "anthropic", types: ["Analytics Source"], on: true,
    desc: "Reconciles who is using Claude Code against governed sessions — powers Governance Coverage.", foot: "OTel · 48 users seen (7d)" },
];

const PROVIDERS = {
  "AI Workload": [
    { id: "claude", name: "Claude Code", brand: "anthropic", desc: "Govern every Claude Code prompt and tool call with Cedar." },
    { id: "n8n", name: "n8n", brand: "n8n", desc: "Discover AI workflows from n8n." },
    { id: "github", name: "GitHub", brand: "github", desc: "Discover AI workloads from GitHub repositories." },
    { id: "bedrock", name: "AWS Bedrock Agents", brand: "bedrock", desc: "Discover AI agents from AWS Bedrock." },
    { id: "crewai", name: "CrewAI", brand: "crewai", desc: "Discover AI agents from CrewAI projects." },
    { id: "langchain", name: "LangChain / LangGraph", brand: "langchain", desc: "Discover LangChain and LangGraph agents from GitHub repositories." },
    { id: "copilot", name: "Microsoft Copilot Studio", brand: "microsoft", desc: "Discover AI agents from Microsoft Copilot Studio across your Microsoft 365 tenant." },
    { id: "custom", name: "Custom", brand: "custom", desc: "Custom discovery source." },
  ],
  "Approval Channel": [
    { id: "slack", name: "Slack", brand: "slack", desc: "Route human approvals to a Slack channel." },
    { id: "oktaverify", name: "Okta Verify", brand: "oktaverify", desc: "Push approvals to Okta Verify." },
  ],
  "Analytics Source": [
    { id: "anthropic-api", name: "Anthropic Analytics API", brand: "anthropic", desc: "Pull Claude Code usage via the Admin Analytics API — for Console-billed orgs." },
    { id: "otel", name: "OpenTelemetry", brand: "otel", desc: "Ingest Claude Code OTel events — works for subscription and all plans." },
  ],
  "Policy Store": [
    { id: "avp", name: "AWS Verified Permissions", brand: "aws", desc: "Cedar policy store on Amazon Verified Permissions." },
    { id: "s3", name: "Amazon S3", brand: "s3", desc: "Versioned Cedar policy bundles in S3." },
    { id: "reva", name: "Reva Managed", brand: "custom", desc: "Reva-hosted Cedar policy store." },
  ],
  "Identity Store": [
    { id: "okta", name: "Okta", brand: "okta", desc: "Okta enterprise SSO and directory." },
    { id: "entra", name: "Microsoft Entra ID", brand: "entra", desc: "Entra ID users and groups." },
    { id: "cognito", name: "AWS Cognito", brand: "cognito", desc: "Cognito user pools." },
  ],
  "Shared Signal": [
    { id: "crowdstrike", name: "CrowdStrike", brand: "crowdstrike", desc: "Falcon endpoint risk signals." },
    { id: "okta", name: "Okta", brand: "okta", desc: "Okta access management signals." },
  ],
  "API Gateway": [
    { id: "kong", name: "Kong", brand: "custom", desc: "Enforce decisions at the Kong gateway." },
    { id: "awsapi", name: "AWS API Gateway", brand: "aws", desc: "Enforce at Amazon API Gateway." },
  ],
  "CMDB": [
    { id: "snow", name: "ServiceNow", brand: "custom", desc: "Sync configuration items from ServiceNow." },
  ],
};

/* ---------- small atoms ---------- */
function CopyBtn({ size = 30 }) {
  const [done, setDone] = React.useState(false);
  return (
    <button className="kebab" style={{ width: size, height: size }} onClick={() => { setDone(true); setTimeout(() => setDone(false), 1200); }}>
      <Icon name={done ? "check" : "copy"} size={15} color={done ? "var(--green)" : "var(--ink-4)"} />
    </button>
  );
}

const inputStyle = { width: "100%", height: 40, border: "1px solid var(--border-strong)", borderRadius: 9, padding: "0 12px", fontSize: 13.5, outline: "none", background: "#fff", color: "var(--ink)" };

function FieldGroup({ label, required, helper, children }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      {label && <label style={{ fontSize: 13, fontWeight: 600, color: "var(--ink)" }}>{label}{required && <span style={{ color: "var(--red)" }}> *</span>}</label>}
      {children}
      {helper && <div className="help" style={{ fontSize: 12 }}>{helper}</div>}
    </div>
  );
}

function MaskedField({ value = "••••••••••••••••", onApply = true, helper }) {
  return (
    <FieldGroup helper={helper}>
      <div style={{ display: "flex", gap: 8 }}>
        <div style={{ ...inputStyle, display: "flex", alignItems: "center", letterSpacing: 1 }} className="mono">{value}</div>
        <CopyBtn size={40} />
        <button className="btn btn-ghost" style={{ height: 40 }}>Apply</button>
      </div>
    </FieldGroup>
  );
}

function CodeBlock({ lines, label }) {
  return (
    <div>
      {label && <div className="help" style={{ marginBottom: 6 }}>{label}</div>}
      <div className="code" style={{ padding: "12px 14px", display: "flex", alignItems: "flex-start", gap: 10 }}>
        <pre style={{ margin: 0, flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{lines}</pre>
        <CopyBtn />
      </div>
    </div>
  );
}

function EmailMapTable() {
  const reva = useReva();
  const approvers = (reva.raw && reva.raw.approvers) || [];
  const selected = (reva.raw && reva.raw.approverSelected) || "";
  const [val, setVal] = React.useState(null);
  const [saved, setSaved] = React.useState(false);
  React.useEffect(() => { if (val === null && selected) setVal(selected); }, [selected]);
  const current = val !== null ? val : (selected || approvers[0] || "");
  const save = async () => {
    if (!current) return;
    try {
      await fetch("/api/config/approvers", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ selected: current }) });
      await revaLoadConfigs(); setSaved(true);
    } catch (e) {}
  };
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <select value={current} onChange={(e) => { setVal(e.target.value); setSaved(false); }}
          className="mono" style={{ flex: 1, height: 36, border: "1px solid var(--border-strong)", borderRadius: 8, padding: "0 10px", fontSize: 13, outline: "none", background: "#fff", color: "var(--ink)" }}>
          <option value="" disabled>Select approver…</option>
          {approvers.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <button className="btn btn-primary btn-sm" onClick={save}>Save</button>
        {saved && <span className="pill pill-green"><Icon name="check" size={13} /> Saved</span>}
      </div>
      <div className="help" style={{ marginTop: 8 }}>This approver receives all approval requests for now — quarantine reinstatement and short-lived SVID token requests.</div>
    </div>
  );
}

function TestButton({ label }) {
  const [state, setState] = React.useState("idle");
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <button className="btn btn-ghost" style={{ height: 38 }} onClick={() => { setState("sending"); setTimeout(() => setState("ok"), 700); }}>{label}</button>
      {state === "ok" && <span className="pill pill-green"><Icon name="check" size={13} /> Sent — check the channel</span>}
      {state === "sending" && <span className="help">Sending…</span>}
    </div>
  );
}

function LocalAccordion({ title, subtitle, open, onToggle, children }) {
  return (
    <div className="card" style={{ overflow: "hidden", marginBottom: 14 }}>
      <button onClick={onToggle} style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, padding: "16px 18px", background: "transparent", border: 0, textAlign: "left" }}>
        <Icon name={open ? "chevDown" : "chevRight"} size={18} color="var(--ink-3)" />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 14.5, fontWeight: 600, color: "var(--ink)" }}>{title}</div>
          {subtitle && <div className="help" style={{ marginTop: 2 }}>{subtitle}</div>}
        </div>
      </button>
      {open && <div style={{ borderTop: "1px solid var(--border)", padding: 18 }}>{children}</div>}
    </div>
  );
}

/* ---------- directory ---------- */
function ConnectorCard({ c, onClick }) {
  const [on, setOn] = React.useState(c.on);
  return (
    <div className="card conn" onClick={onClick} style={{ padding: 18, cursor: onClick ? "pointer" : "default", position: "relative",
      borderColor: c.featured ? "rgba(124,58,237,.35)" : "var(--border)", boxShadow: c.featured ? "0 0 0 3px rgba(124,58,237,.07), var(--shadow-card)" : "var(--shadow-card)" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
        <LogoTile brand={c.brand} />
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, flex: 1, paddingTop: 3 }}>
          {c.types.map((t) => <Pill key={t} tone={TYPE_TONE[t] || "gray"}>{t}</Pill>)}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 4 }} onClick={(e) => e.stopPropagation()}>
          <Toggle on={on} onClick={() => setOn(!on)} />
          <button className="kebab"><Icon name="kebab" size={18} /></button>
        </div>
      </div>
      <div style={{ marginTop: 14, fontSize: 15, fontWeight: 600, color: "var(--ink)" }}>{c.name}</div>
      <div className="sub" style={{ fontSize: 13, marginTop: 4, lineHeight: 1.5, minHeight: 38,
        display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{c.desc}</div>
      <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--border)", fontSize: 12, color: "var(--ink-4)" }}>{c.foot}</div>
    </div>
  );
}

function IntegrationsPage({ onOpenWorkload }) {
  const [grid, setGrid] = React.useState(true);
  const [menuOpen, setMenuOpen] = React.useState(false);
  const [wizard, setWizard] = React.useState(null); // category string

  const openWizard = (cat) => { setMenuOpen(false); setWizard(cat); };

  return (
    <div style={{ padding: 28 }}>
      <div style={{ marginBottom: 18 }}>
        <h1 style={{ margin: 0, fontSize: 23, fontWeight: 600, color: "var(--ink)", letterSpacing: "-0.01em" }}>Integrations</h1>
        <p style={{ margin: "8px 0 0", maxWidth: 980, color: "var(--ink-3)", fontSize: 13.5, lineHeight: 1.55 }}>
          Connect the policy stores, identity providers, CMDBs, agent registries, API gateways, approval channels, and analytics sources that authorization decisions depend on — bringing signals in and pushing enforcement out.
        </p>
      </div>

      {/* toolbar */}
      <div className="card" style={{ padding: 14, display: "flex", alignItems: "center", gap: 12, marginBottom: 18 }}>
        <div className="search" style={{ flex: 1, minWidth: 0 }}>
          <Icon name="search" size={16} color="var(--ink-4)" />
          <input placeholder="Search integrations…" />
          <Icon name="send" size={16} color="var(--ink-4)" />
        </div>
        <div className="seg" style={{ padding: 3 }}>
          <button className={grid ? "" : "active"} onClick={() => setGrid(false)} style={{ width: 34, padding: 0, display: "grid", placeItems: "center" }}><Icon name="list" size={17} /></button>
          <button className={grid ? "active" : ""} onClick={() => setGrid(true)} style={{ width: 34, padding: 0, display: "grid", placeItems: "center" }}><Icon name="grid" size={16} /></button>
        </div>
        <button className="selchip">Type: All <Icon name="chevDown" size={15} color="var(--ink-4)" /></button>
        <div style={{ position: "relative" }}>
          <button className="btn btn-primary" onClick={() => setMenuOpen(!menuOpen)}><Icon name="plus" size={16} /> Integration <Icon name="chevDown" size={15} color="#fff" /></button>
          {menuOpen && (
            <>
              <div onClick={() => setMenuOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 30 }} />
              <div className="card" style={{ position: "absolute", top: 46, right: 0, width: 220, padding: 6, zIndex: 31, boxShadow: "var(--shadow-pop)" }}>
                {INTEGRATION_TYPES.map((t) => (
                  <button key={t} onClick={() => openWizard(t)} style={{ width: "100%", textAlign: "left", padding: "10px 12px", border: 0, background: "transparent", borderRadius: 8, fontSize: 13.5, fontWeight: 500, color: "var(--ink-2)", cursor: "pointer" }}
                    onMouseEnter={(e) => e.currentTarget.style.background = "var(--surface-2)"} onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>{t}</button>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* grid */}
      <div style={{ display: "grid", gridTemplateColumns: grid ? "repeat(3, 1fr)" : "1fr", gap: 16 }}>
        {CONNECTORS.map((c) => (
          <ConnectorCard key={c.name} c={c} onClick={c.name === "Claude Code" ? onOpenWorkload : undefined} />
        ))}
        {/* ghost add card */}
        <button onClick={() => setWizard("AI Workload")} className="card" style={{ minHeight: 168, borderStyle: "dashed", background: "transparent", display: "grid", placeItems: "center", cursor: "pointer", color: "var(--ink-4)" }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, background: "var(--surface-3)", display: "grid", placeItems: "center", margin: "0 auto 8px" }}><Icon name="plus" size={20} color="var(--ink-3)" /></div>
            <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink-3)" }}>Add workload</div>
          </div>
        </button>
      </div>

      {wizard && <CreateWizard category={wizard} onClose={() => setWizard(null)} />}

      <style>{`.conn{transition:box-shadow .15s,border-color .15s,transform .15s;} .conn:hover{box-shadow:var(--shadow-pop);} `}</style>
    </div>
  );
}

/* ---------- wizard ---------- */
function Stepper({ step }) {
  const labels = ["Select Type", "Configure", "Instructions"];
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 0, padding: "16px 24px", borderBottom: "1px solid var(--border)" }}>
      {labels.map((l, i) => {
        const state = i < step ? "done" : i === step ? "current" : "future";
        const color = state === "done" ? "var(--green)" : state === "current" ? "var(--blue)" : "var(--border-strong)";
        return (
          <React.Fragment key={l}>
            <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
              <span style={{ width: 16, height: 16, borderRadius: "50%", background: color, display: "grid", placeItems: "center", flex: "none" }}>
                {state === "done" && <Icon name="check" size={11} color="#fff" />}
              </span>
              <span style={{ fontSize: 13.5, fontWeight: 600, color: state === "future" ? "var(--ink-4)" : state === "current" ? "var(--blue)" : "var(--ink-2)" }}>{l}</span>
            </div>
            {i < labels.length - 1 && <span style={{ width: 28, height: 1, background: "var(--border-strong)", margin: "0 14px" }} />}
          </React.Fragment>
        );
      })}
    </div>
  );
}

function ProviderCard({ p, selected, onClick }) {
  return (
    <button onClick={onClick} style={{
      textAlign: "left", padding: 18, borderRadius: 14, cursor: "pointer", position: "relative",
      border: `1.5px solid ${selected ? "var(--blue)" : "var(--border)"}`,
      background: selected ? "var(--blue-tint)" : "#fff",
      boxShadow: selected ? "0 0 0 3px rgba(37,99,235,.12)" : "none", transition: "all .15s",
    }}>
      {selected && <span style={{ position: "absolute", top: 14, right: 14, width: 20, height: 20, borderRadius: "50%", background: "var(--blue)", display: "grid", placeItems: "center" }}><Icon name="check" size={13} color="#fff" /></span>}
      <LogoTile brand={p.brand} size={40} mark={22} />
      <div style={{ marginTop: 12, fontSize: 14.5, fontWeight: 700, color: "var(--ink)" }}>{p.name}</div>
      <div className="sub" style={{ fontSize: 12.5, marginTop: 3, lineHeight: 1.45 }}>{p.desc}</div>
    </button>
  );
}

function SlackConnectionSettings() {
  const reva = useReva();
  const hitl = reva.hitl || {};
  const connected = !!hitl.slack_connected;
  const [token, setToken] = React.useState("");
  const [applying, setApplying] = React.useState(false);
  const [applyMsg, setApplyMsg] = React.useState(null);
  const [channels, setChannels] = React.useState([]);
  const [fetching, setFetching] = React.useState(false);
  const [testState, setTestState] = React.useState("idle");

  const apply = async () => {
    if (!token.trim()) return;
    setApplying(true); setApplyMsg(null);
    try {
      const r = await fetch("/api/hitl/slack/apply-token", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: token.trim() }) });
      const d = await r.json();
      if (d.ok) { setApplyMsg({ ok: true, team: d.team }); setToken(""); await revaLoadConfigs(); }
      else setApplyMsg({ ok: false, error: d.error || "Invalid token" });
    } catch (e) { setApplyMsg({ ok: false, error: "Network error" }); }
    setApplying(false);
  };
  const fetchChannels = async () => {
    setFetching(true);
    try { const r = await fetch("/api/hitl/slack/channels"); const d = await r.json(); if (d.ok) setChannels(d.channels || []); } catch (e) {}
    setFetching(false);
  };
  const selectChannel = async (e) => {
    const c = channels.find((x) => (x.id || x.name) === e.target.value);
    if (!c) return;
    await fetch("/api/config/hitl", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ slack_channel: "#" + String(c.name || "").replace(/^#/, ""), slack_channel_id: c.id || "" }) });
    await revaLoadConfigs();
  };
  const setExpiry = async (v) => { await fetch("/api/config/hitl", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ approval_expiry_minutes: parseInt(v, 10) || 60 }) }); };
  const test = async () => { setTestState("sending"); try { const r = await fetch("/api/hitl/slack/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) }); const d = await r.json(); setTestState(d.ok ? "ok" : "err"); } catch (e) { setTestState("err"); } };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <FieldGroup label="Bot Token" required helper={connected ? "A token is applied. Paste a new one to replace it." : "Starts with xoxb-. Stored encrypted."}>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <input value={token} onChange={(e) => setToken(e.target.value)} placeholder={connected ? "xoxb-•••••••• (applied)" : "xoxb-…"} className="mono" style={inputStyle} />
          <button className="btn btn-ghost" style={{ height: 40 }} onClick={apply} disabled={applying || !token.trim()}>{applying ? "Applying…" : "Apply"}</button>
        </div>
        {applyMsg && (applyMsg.ok
          ? <span className="pill pill-green" style={{ alignSelf: "flex-start" }}><Icon name="check" size={13} /> Connected — {applyMsg.team}</span>
          : <span className="pill pill-red" style={{ alignSelf: "flex-start" }}>{applyMsg.error}</span>)}
        {connected && !applyMsg && <span className="pill pill-green" style={{ alignSelf: "flex-start" }}><span className="dot" />Connected</span>}
      </FieldGroup>

      <FieldGroup label="Channel" helper="The bot must be invited to this channel.">
        <div style={{ display: "flex", gap: 8 }}>
          {channels.length
            ? <select onChange={selectChannel} defaultValue={hitl.slack_channel_id || ""} style={{ ...inputStyle, flex: 1 }}>
                <option value="" disabled>Select a channel…</option>
                {channels.map((c) => <option key={c.id || c.name} value={c.id || c.name}>#{String(c.name || "").replace(/^#/, "")}</option>)}
              </select>
            : <div className="selchip" style={{ flex: 1, justifyContent: "space-between", height: 40, display: "flex", alignItems: "center", padding: "0 12px" }}>{hitl.slack_channel || "No channel selected"}</div>}
          <button className="btn btn-ghost" style={{ height: 40 }} onClick={fetchChannels} disabled={fetching || !connected}><Icon name="rotate" size={15} /> {fetching ? "Fetching…" : "Fetch channels"}</button>
        </div>
      </FieldGroup>

      <FieldGroup label="Approval expiry (minutes)">
        <input style={{ ...inputStyle, width: 140 }} defaultValue={hitl.approval_expiry_minutes || 60} className="mono" onBlur={(e) => setExpiry(e.target.value)} />
      </FieldGroup>

      <FieldGroup label="Approver" helper="Approval requests are addressed to this approver."><EmailMapTable /></FieldGroup>

      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button className="btn btn-ghost" style={{ height: 38 }} onClick={test} disabled={!connected || testState === "sending"}>Send test message</button>
        {testState === "ok" && <span className="pill pill-green"><Icon name="check" size={13} /> Sent — check the channel</span>}
        {testState === "sending" && <span className="help">Sending…</span>}
        {testState === "err" && <span className="pill pill-red">Failed — check token/channel</span>}
      </div>
    </div>
  );
}

function ConnectionSettings({ provider, category }) {
  const id = provider ? provider.id : null;
  const helper = "Joined against Reva SessionStart events to compute Governance Coverage.";

  if (id === "slack") {
    return <SlackConnectionSettings />;
  }
  if (id === "oktaverify") {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
        <FieldGroup label="Okta domain" required><input style={inputStyle} placeholder="acme.okta.com" /></FieldGroup>
        <FieldGroup label="Authorization server id"><input style={inputStyle} className="mono" placeholder="aus1a2b3c4D5e6F7g8" /></FieldGroup>
        <FieldGroup label="Approver" helper="Approval requests are addressed to this approver."><EmailMapTable /></FieldGroup>
        <TestButton label="Send test push" />
      </div>
    );
  }
  if (category === "Analytics Source") {
    return <AnalyticsSettings defaultMode={id === "anthropic-api" ? "Admin Analytics API" : "OpenTelemetry"} helper={helper} />;
  }
  // generic / AI Workload
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      {id === "claude" && (
        <FieldGroup label="Plan" helper="Determines install path on the Instructions step.">
          <Segmented options={["Individual", "Enterprise"]} value={"Enterprise"} onChange={() => {}} />
        </FieldGroup>
      )}
      <FieldGroup label="Endpoint / Base URL" required><input style={inputStyle} className="mono" placeholder="https://api.example.com" /></FieldGroup>
      <FieldGroup label="Access Token" required helper="Scoped, read-only. Stored encrypted.">
        <div style={{ display: "flex", gap: 8 }}>
          <div style={{ ...inputStyle, display: "flex", alignItems: "center", letterSpacing: 1 }} className="mono">••••••••••••••••</div>
          <CopyBtn size={40} /><button className="btn btn-ghost" style={{ height: 40 }}>Apply</button>
        </div>
      </FieldGroup>
      <FieldGroup label="Sync schedule"><button className="selchip" style={{ justifyContent: "space-between", width: 220, height: 40 }}>Every 15 minutes <Icon name="chevDown" size={15} color="var(--ink-4)" /></button></FieldGroup>
    </div>
  );
}

function AnalyticsSettings({ defaultMode, helper }) {
  const [mode, setMode] = React.useState(defaultMode);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <Segmented options={["Admin Analytics API", "OpenTelemetry"]} value={mode} onChange={setMode} />
      {mode === "Admin Analytics API" ? (
        <>
          <FieldGroup label="Admin Key" required helper="Must start with sk-ant-admin…">
            <div style={{ display: "flex", gap: 8 }}>
              <div style={{ ...inputStyle, display: "flex", alignItems: "center", letterSpacing: 1 }} className="mono">sk-ant-admin-••••••••</div>
              <CopyBtn size={40} /><button className="btn btn-ghost" style={{ height: 40 }}>Apply</button>
            </div>
          </FieldGroup>
          <FieldGroup label="Org / workspace" required><input style={inputStyle} placeholder="acme-engineering" /></FieldGroup>
        </>
      ) : (
        <>
          <FieldGroup label="OTLP endpoint" required><input style={inputStyle} className="mono" placeholder="https://otel.acme.io:4317" /></FieldGroup>
          <CodeBlock label="Set these on each Claude Code host" lines={`CLAUDE_CODE_ENABLE_TELEMETRY=1\nOTEL_EXPORTER_OTLP_ENDPOINT=https://otel.acme.io:4317\nOTEL_EXPORTER_OTLP_PROTOCOL=grpc`} />
        </>
      )}
      <div className="help" style={{ display: "flex", gap: 7 }}><Icon name="info" size={15} color="var(--ink-4)" /> {helper}</div>
    </div>
  );
}

function NumberedStep({ n, title, children }) {
  return (
    <div style={{ display: "flex", gap: 14 }}>
      <span style={{ width: 26, height: 26, borderRadius: "50%", background: "var(--blue-tint)", color: "var(--blue-700)", display: "grid", placeItems: "center", fontSize: 13, fontWeight: 700, flex: "none" }}>{n}</span>
      <div style={{ flex: 1, paddingBottom: 18, minWidth: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--ink)", marginBottom: 8 }}>{title}</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>{children}</div>
      </div>
    </div>
  );
}

function Checklist({ items }) {
  return (
    <div style={{ background: "var(--green-tint)", border: "1px solid #BBE7CB", borderRadius: 12, padding: 16 }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: "var(--green)", marginBottom: 10 }}>Verify</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
        {items.map((it) => (
          <div key={it} style={{ display: "flex", alignItems: "center", gap: 9, fontSize: 13, color: "var(--ink-2)" }}>
            <span style={{ width: 18, height: 18, borderRadius: "50%", background: "var(--green)", display: "grid", placeItems: "center", flex: "none" }}><Icon name="check" size={12} color="#fff" /></span>
            {it}
          </div>
        ))}
      </div>
    </div>
  );
}

function StepLabel({ children }) {
  return <div style={{ fontSize: 13, fontWeight: 700, color: "var(--ink)" }}>{children}</div>;
}

function TokenField() {
  return (
    <div>
      <label style={{ fontSize: 13, fontWeight: 600, color: "var(--ink)" }}>Access Token</label>
      <div style={{ display: "flex", gap: 8, marginTop: 7 }}>
        <div style={{ ...inputStyle, display: "flex", alignItems: "center", letterSpacing: 2 }} className="mono">••••••••••••</div>
        <CopyBtn size={40} />
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 7 }}>
        <span className="help" style={{ fontSize: 12, flex: 1 }}>Fine-grained, read-only, scoped to the plugin repo. Expires; rotate from this screen.</span>
        <a href="#" style={{ fontSize: 12.5, fontWeight: 600, color: "var(--blue)", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 4 }}><Icon name="rotate" size={13} /> Rotate</a>
      </div>
    </div>
  );
}

function CollapsibleSub({ title, children }) {
  const [o, setO] = React.useState(false);
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 10, overflow: "hidden", background: "#fff" }}>
      <button onClick={() => setO(!o)} style={{ width: "100%", display: "flex", alignItems: "center", gap: 9, padding: "11px 14px", border: 0, background: "transparent", textAlign: "left", cursor: "pointer" }}>
        <Icon name={o ? "chevDown" : "chevRight"} size={15} color="var(--ink-3)" />
        <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--ink-2)" }}>{title}</span>
      </button>
      {o && <div style={{ padding: "0 14px 14px", display: "flex", flexDirection: "column", gap: 10 }}>{children}</div>}
    </div>
  );
}

const MANAGED_JSON = `{
  "extraKnownMarketplaces": {
    "reva-governance": {
      "source": { "source": "git", "url": "https://git.acme.internal/devtools/reva-governance.git" }
    }
  },
  "enabledPlugins": { "reva-governance@reva-governance": true },
  "strictKnownMarketplaces": true,
  "allowManagedHooksOnly": true,
  "allowedHttpHookUrls": ["https://reva-plugin.onrender.com/*"],
  "httpHookAllowedEnvVars": ["USER", "CLAUDE_PROJECT_DIR"]
}`;

const WHY_KEYS = [
  ["enabledPlugins", "force-enables Reva; its hooks load even under allowManagedHooksOnly."],
  ["allowManagedHooksOnly: true", "only managed + force-enabled-plugin hooks run; developers can't add bypass hooks."],
  ["allowedHttpHookUrls", "REQUIRED (Reva's hooks are HTTP); omit the URL and enforcement silently stops."],
  ["httpHookAllowedEnvVars", "keeps $USER / $CLAUDE_PROJECT_DIR from resolving empty (breaks identity attribution)."],
  ["strictKnownMarketplaces: true", "pins installs to the Reva source only."],
];

function ClaudeInstructions() {
  const [ind, setInd] = React.useState(true);
  const [ent, setEnt] = React.useState(false);
  return (
    <div>
      <LocalAccordion title="Individual Plan" subtitle="Private repo — authenticate git with the read-only token below, then register the marketplace." open={ind} onToggle={() => setInd(!ind)}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <StepLabel>Step 0 — Confirm git access</StepLabel>
          <CodeBlock lines={`git ls-remote https://github.com/saisrungaram-ai/reva-cowork-plugin.git`} />

          <TokenField />

          <StepLabel>Step 1 — Register the token with git</StepLabel>
          <CodeBlock lines={`gh auth login --hostname github.com --git-protocol https --with-token   # paste the token above\ngh auth setup-git`} />

          <StepLabel>Step 2 — Add the marketplace</StepLabel>
          <CodeBlock lines={`/plugin marketplace add https://github.com/saisrungaram-ai/reva-cowork-plugin.git`} />

          <CollapsibleSub title="Fallback — manual clone (if the credential helper isn't picked up)">
            <CodeBlock lines={`git clone https://x-access-token:<PASTE_TOKEN>@github.com/saisrungaram-ai/reva-cowork-plugin.git ~/.reva/reva-cowork-plugin\n/plugin marketplace add ~/.reva/reva-cowork-plugin`} />
            <div className="help" style={{ fontSize: 12 }}>Note: prefer Step 1 — the inline-token form persists the token in <span className="mono">.git/config</span>.</div>
          </CollapsibleSub>

          <StepLabel>Step 3 — Install + activate</StepLabel>
          <CodeBlock lines={`/plugin install reva-governance@reva-governance\n/reload-plugins`} />

          <Checklist items={["/plugin shows reva-governance enabled", "Errors tab is empty", "Trigger a governed action — a Reva Governance decision appears in the terminal"]} />

          <div className="help" style={{ fontSize: 12, display: "flex", gap: 7 }}>
            <Icon name="info" size={15} color="var(--ink-4)" />
            No local secrets — hooks call the hosted PDP at <span className="mono">reva-plugin.onrender.com</span>; ensure outbound HTTPS to that host is allowed.
          </div>
        </div>
      </LocalAccordion>

      <LocalAccordion title="Enterprise Plan" subtitle="Distributed centrally via managed settings — developers never access the plugin repo. One service credential mirrors the plugin into your own Git." open={ent} onToggle={() => setEnt(!ent)}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <StepLabel>Step 1 — Mirror (platform team, once)</StepLabel>
          <div style={{ fontSize: 13, color: "var(--ink-2)", lineHeight: 1.55 }}>Reva provides a read-only deploy token; set up a scheduled pull-mirror of the plugin into your internal Git, e.g. <span className="mono">git.acme.internal/devtools/reva-governance</span>.</div>

          <StepLabel>Step 2 — Managed settings (Admin Console → Claude Code → Managed settings)</StepLabel>
          <CodeBlock lines={MANAGED_JSON} />

          <div style={{ border: "1px solid var(--border)", borderRadius: 12, padding: 16, background: "var(--surface-2)" }}>
            <div style={{ fontSize: 12.5, fontWeight: 700, color: "var(--ink)", marginBottom: 10 }}>Why these keys</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
              {WHY_KEYS.map(([k, v]) => (
                <div key={k} style={{ display: "flex", gap: 9, fontSize: 12.5, color: "var(--ink-2)", lineHeight: 1.5 }}>
                  <span style={{ color: "var(--ink-4)" }}>•</span>
                  <span><span className="mono" style={{ fontWeight: 600, color: "var(--ink)" }}>{k}</span> — {v}</span>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: "flex", gap: 10, background: "var(--amber-tint)", border: "1px solid #F3D9A6", borderRadius: 10, padding: "12px 14px" }}>
            <Icon name="info" size={17} color="var(--amber-ink)" style={{ flex: "none", marginTop: 1 }} />
            <div style={{ fontSize: 12.5, color: "var(--amber-ink)", lineHeight: 1.5 }}><b>CLI users:</b> plugins from managed settings may not auto-install in the CLI — run Individual Plan Steps 2–3 once as a bootstrap.</div>
          </div>

          <div style={{ fontSize: 12, color: "var(--ink-3)", lineHeight: 1.5, background: "var(--surface-3)", borderRadius: 10, padding: "11px 14px" }}>
            CI / containers / ephemeral envs — bake the clone into the image and seed via <span className="mono">CLAUDE_CODE_PLUGIN_SEED_DIR</span> (no runtime auth).
          </div>
        </div>
      </LocalAccordion>
    </div>
  );
}

function InstructionsGuide({ provider, category }) {
  const id = provider ? provider.id : null;
  if (id === "claude") return <ClaudeInstructions />;
  if (id === "slack") {
    return (
      <div className="card" style={{ padding: 22 }}>
        <NumberedStep n="1" title="Create a Slack app">Visit api.slack.com/apps → Create New App → From scratch, in your workspace.</NumberedStep>
        <NumberedStep n="2" title="Add bot token scopes"><CodeBlock lines={`chat:write\nchannels:read`} /></NumberedStep>
        <NumberedStep n="3" title="Install to workspace">Install the app and copy the Bot User OAuth Token.</NumberedStep>
        <NumberedStep n="4" title="Paste the Bot Token">Return to Connection Settings and paste the token into the Bot Token field, then Apply.<CodeBlock lines={`xoxb-1234567890-XXXXXXXXXXXX`} /></NumberedStep>
        <NumberedStep n="5" title="Invite the bot">Invite it to your approvals channel.<CodeBlock lines={`/invite @reva-governance #ai-approvals`} /></NumberedStep>
      </div>
    );
  }
  if (id === "otel" || category === "Analytics Source") {
    return (
      <div className="card" style={{ padding: 22 }}>
        <NumberedStep n="1" title="Run an OpenTelemetry collector">Point it at your backend; expose an OTLP endpoint reachable by developer machines.</NumberedStep>
        <NumberedStep n="2" title="Set Claude Code environment variables">Distribute via managed settings or your dotfiles.<CodeBlock lines={`CLAUDE_CODE_ENABLE_TELEMETRY=1\nOTEL_EXPORTER_OTLP_ENDPOINT=https://otel.acme.io:4317\nOTEL_EXPORTER_OTLP_PROTOCOL=grpc`} /></NumberedStep>
        <NumberedStep n="3" title="Confirm events arrive"><Checklist items={["Collector receiving Claude Code spans", "Events include user.email attribute", "SessionStart events visible in Reva"]} /></NumberedStep>
      </div>
    );
  }
  if (id === "anthropic-api") {
    return (
      <div className="card" style={{ padding: 22 }}>
        <NumberedStep n="1" title="Create an Admin API key">In the Anthropic Console → Settings → Admin keys. Console-billed orgs only.</NumberedStep>
        <NumberedStep n="2" title="Paste the key">Add it to Connection Settings (must start with sk-ant-admin…).<CodeBlock lines={`sk-ant-admin-XXXXXXXXXXXXXXXX`} /></NumberedStep>
        <NumberedStep n="3" title="Confirm reconciliation"><Checklist items={["Admin Analytics API reachable", "Usage rows returned for the last 7d", "Joined to governed SessionStart events"]} /></NumberedStep>
      </div>
    );
  }
  // generic
  return (
    <div className="card" style={{ padding: 22 }}>
      <NumberedStep n="1" title="Authorize the connection">Generate a scoped, read-only credential in {provider ? provider.name : "the provider"} and paste it into Connection Settings.</NumberedStep>
      <NumberedStep n="2" title="Grant discovery access">Allow read access to the resources Reva should govern.<CodeBlock lines={`reva connect ${id || "provider"} --read-only`} /></NumberedStep>
      <NumberedStep n="3" title="Verify"><Checklist items={["Connection authenticated", "First sync completed", "Workloads appear in the directory"]} /></NumberedStep>
    </div>
  );
}

function CreateWizard({ category, onClose }) {
  const providers = PROVIDERS[category] || [];
  const [step, setStep] = React.useState(0);
  const [pid, setPid] = React.useState(null);
  const [open, setOpen] = React.useState({ basic: true, conn: true });
  const [lib, setLib] = React.useState(true);
  const [app, setApp] = React.useState(false);
  const provider = providers.find((p) => p.id === pid);
  const title = `Create ${category} Integration` + (provider && step > 0 ? ` — ${provider.name}` : "");

  return (
    <>
      <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(11,18,32,.34)", zIndex: 50 }} />
      <div style={{ position: "fixed", top: 0, right: 0, bottom: 0, width: "min(840px, 80vw)", background: "var(--bg)", zIndex: 51, boxShadow: "var(--shadow-drawer)", display: "flex", flexDirection: "column" }}>
        {/* header */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "16px 24px", background: "#fff", borderBottom: "1px solid var(--border)" }}>
          {step > 0 && <button className="kebab" onClick={() => setStep(step - 1)}><Icon name="chevRight" size={18} style={{ transform: "rotate(180deg)" }} /></button>}
          <div style={{ fontSize: 17, fontWeight: 700, color: "var(--ink)" }}>{title}</div>
          <button className="kebab" style={{ marginLeft: "auto", border: "1px solid var(--border-strong)" }} onClick={onClose}><Icon name="x" size={18} /></button>
        </div>
        <div style={{ background: "#fff" }}><Stepper step={step} /></div>

        {/* body */}
        <div style={{ flex: 1, overflowY: "auto", padding: 24 }}>
          {step === 0 && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {providers.map((p) => <ProviderCard key={p.id} p={p} selected={pid === p.id} onClick={() => setPid(p.id)} />)}
            </div>
          )}

          {step === 1 && (
            <div>
              <LocalAccordion title="Basic Information" open={open.basic} onToggle={() => setOpen({ ...open, basic: !open.basic })}>
                <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
                  <FieldGroup label="Integration Name" required><input style={inputStyle} defaultValue={provider ? `${provider.name} — Integration` : ""} placeholder="e.g. Slack — AI Approvals" /></FieldGroup>
                  <FieldGroup label="Description"><textarea style={{ ...inputStyle, height: 80, padding: 12, resize: "vertical" }} placeholder="Describe this integration…" /></FieldGroup>
                  <FieldGroup label="Choose Owner of This Connection"><button className="selchip" style={{ width: "100%", justifyContent: "space-between", height: 40 }}><span className="muted">Search &amp; select</span> <Icon name="chevDown" size={15} color="var(--ink-4)" /></button></FieldGroup>
                  <FieldGroup label="Applicable Entity Types" helper="Select entity types this integration applies to.">
                    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                      <EntityCheck on={lib} onToggle={() => setLib(!lib)} title="Library" sub="System Components" multiLabel="Library Entity Types" />
                      <EntityCheck on={app} onToggle={() => setApp(!app)} title="Application" sub="Application Specific" multiLabel="Application Entity Types" />
                    </div>
                  </FieldGroup>
                </div>
              </LocalAccordion>

              <LocalAccordion title="Connection Settings" subtitle={provider ? provider.name : ""} open={open.conn} onToggle={() => setOpen({ ...open, conn: !open.conn })}>
                <ConnectionSettings provider={provider} category={category} />
              </LocalAccordion>
            </div>
          )}

          {step === 2 && <InstructionsGuide provider={provider} category={category} />}
        </div>

        {/* footer */}
        <div style={{ display: "flex", alignItems: "center", padding: "14px 24px", background: "#fff", borderTop: "1px solid var(--border)" }}>
          {step > 0 && <button className="btn btn-ghost" onClick={() => setStep(step - 1)}>Back</button>}
          <div style={{ marginLeft: "auto", display: "flex", gap: 10 }}>
            <button className="btn btn-text" onClick={onClose}>Cancel</button>
            {step === 0 && <button className="btn btn-primary" disabled={!pid} style={!pid ? { opacity: 0.5, cursor: "not-allowed" } : null} onClick={() => pid && setStep(1)}>Next</button>}
            {step === 1 && <button className="btn btn-primary" onClick={() => setStep(2)}>Save &amp; Continue</button>}
            {step === 2 && <button className="btn btn-primary" onClick={onClose}>Done</button>}
          </div>
        </div>
      </div>
    </>
  );
}

function EntityCheck({ on, onToggle, title, sub, multiLabel }) {
  return (
    <div style={{ border: `1.5px solid ${on ? "var(--blue)" : "var(--border-strong)"}`, borderRadius: 12, padding: 14, background: on ? "var(--blue-tint)" : "#fff" }}>
      <button onClick={onToggle} style={{ display: "flex", alignItems: "center", gap: 11, border: 0, background: "transparent", width: "100%", textAlign: "left", cursor: "pointer", padding: 0 }}>
        <span style={{ width: 20, height: 20, borderRadius: 5, flex: "none", display: "grid", placeItems: "center", background: on ? "var(--blue)" : "#fff", border: on ? "0" : "1.5px solid var(--border-strong)" }}>{on && <Icon name="check" size={13} color="#fff" />}</span>
        <div>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: "var(--ink)" }}>{title}</div>
          <div className="help" style={{ fontSize: 12 }}>{sub}</div>
        </div>
      </button>
      {on && (
        <div style={{ marginTop: 12 }}>
          <label style={{ fontSize: 12.5, fontWeight: 600, color: "var(--ink)" }}>{multiLabel}<span style={{ color: "var(--red)" }}> *</span></label>
          <button className="selchip" style={{ width: "100%", justifyContent: "space-between", height: 40, marginTop: 7 }}><span className="muted">Search &amp; select</span> <Icon name="chevDown" size={15} color="var(--ink-4)" /></button>
        </div>
      )}
    </div>
  );
}

window.IntegrationsPage = IntegrationsPage;

/* ===================== aai-panel.jsx ===================== */
/* global React, Icon, Pill */
/* Toast + Confirm + Principal-review Side Panel */
const { createContext: aaiCreateContext, useContext: aaiUseContext, useCallback: aaiUseCallback } = React;

const ToastCtx = aaiCreateContext(null);
const useToast = () => aaiUseContext(ToastCtx);

function ToastProvider({ children }) {
  const [toasts, setToasts] = React.useState([]);
  const push = aaiUseCallback((msg) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((t) => [...t, { id, msg, leaving: false }]);
    setTimeout(() => setToasts((t) => t.map((x) => x.id === id ? { ...x, leaving: true } : x)), 2700);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toast-host">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.leaving ? "leaving" : ""}`}>
            <Icon name="checkCircle" size={16} color="#5eead4" /><span>{t.msg}</span>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

function ConfirmDialog({ open, title, body, confirmLabel, onConfirm, onCancel }) {
  if (!open) return null;
  return (
    <div className="cf-scrim" onClick={onCancel}>
      <div className="cf-box" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", gap: 12, alignItems: "flex-start", marginBottom: 16 }}>
          <div style={{ width: 36, height: 36, borderRadius: 8, background: "var(--red-tint)", color: "var(--red)", display: "grid", placeItems: "center", flexShrink: 0 }}>
            <Icon name="alert" size={18} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: "var(--ink)" }}>{title}</h3>
            <p style={{ margin: "6px 0 0", color: "var(--ink-3)", fontSize: 13.5, lineHeight: 1.55 }}>{body}</p>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button className="btn btn-ghost" onClick={onCancel}>Cancel</button>
          <button className="btn btn-danger" onClick={onConfirm}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

const STATUS_HEX = {
  "Quarantined": "#475569", "Awaiting resolution": "#d97706", "Approval sent": "#d97706", "In certification": "#7c3aed",
  "Auto-restoring": "#2563EB", "Resolved": "#059669", "Permanently revoked": "#dc2626",
};

function SidePanel({ policy, onClose, onUpdatePrincipal }) {
  const toast = useToast();
  const [closing, setClosing] = React.useState(false);
  const [confirmRevoke, setConfirmRevoke] = React.useState(null);

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") doClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const doClose = () => { setClosing(true); setTimeout(onClose, 200); };
  if (!policy) return null;

  const activeCount = policy.principals.filter((p) => !["Resolved", "Permanently revoked"].includes(p.status)).length;

  const handleAction = async (principal, kind) => {
    if (kind === "send-approval") {
      const osUser = principal.pid.includes(":") ? principal.pid.split(":").slice(1).join(":") : principal.pid;
      try {
        const r = await fetch("/api/quarantine/request-approval", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ osUser }) });
        const d = await r.json();
        if (d.ok) { onUpdatePrincipal(policy.id, principal.pid, { status: "Approval sent" }); toast("Approval request sent to Slack — awaiting reviewer authorization"); return; }
        if (d.reason === "slack_not_configured") { toast("Slack isn't configured — configure it in Integrations to send approvals"); return; }
      } catch (e) { /* fall through to optimistic for non-live (design) rows */ }
      onUpdatePrincipal(policy.id, principal.pid, { status: "Approval sent" });
      toast("Approval request sent — awaiting reviewer authorization");
      return;
    }
    let nextStatus, msg;
    switch (kind) {
      case "grant": nextStatus = "Resolved"; msg = "Access reinstated — principal restored to active state"; break;
      case "launch": nextStatus = "In certification"; msg = "Certification campaign launched — assigned to certifier"; break;
      case "revoke": nextStatus = "Permanently revoked"; msg = "Access permanently revoked — removed from access graph"; break;
    }
    onUpdatePrincipal(policy.id, principal.pid, { status: nextStatus });
    toast(msg);
  };

  return (
    <>
      <div className="sp-scrim" style={closing ? { opacity: 0, transition: "opacity .2s" } : null} onClick={doClose} />
      <div className="sp-panel" style={closing ? { transform: "translateX(100%)", transition: "transform .2s cubic-bezier(.7,0,.84,0)" } : null} onClick={(e) => e.stopPropagation()}>
        <div className="sp-head">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="sp-eyebrow">
              <span className="mono-id">{policy.id}</span>
              <span className="sp-dotsep" />
              <span>{activeCount} {activeCount === 1 ? "active principal" : "active principals"}</span>
            </div>
            <h2 className="sp-title">{policy.name}</h2>
          </div>
          <button className="kebab" onClick={doClose}><Icon name="x" size={18} /></button>
        </div>

        <div className="sp-meta">
          <div className="sp-meta-grp">
            <span className="sp-meta-lbl">Category</span>
            <span className="sp-meta-val">{CATEGORIES[policy.category].label} <span className="sp-meta-dim">({CATEGORIES[policy.category].short})</span></span>
          </div>
          <div className="sp-divider" />
          <div className="sp-meta-grp">
            <span className="sp-meta-lbl">Resolution</span>
            <Pill tone={RESOLUTION_PILL[policy.resolution]}>{policy.resolution}</Pill>
          </div>
          <div className="sp-divider" />
          <div className="sp-meta-grp">
            <span className="sp-meta-lbl">Status</span>
            <span className="sp-meta-val" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}><span className="live-dot" /> Monitoring</span>
          </div>
        </div>

        <div className="sp-body">
          {policy.principals.length === 0 ? <SpEmpty /> :
            activeCount === 0 ? <SpResolved principals={policy.principals} /> :
            <PrincipalTable principals={policy.principals} resolution={policy.resolution}
              onAction={handleAction} onRevoke={(p) => setConfirmRevoke(p)} />}
        </div>

        <div className="sp-foot">
          <span style={{ color: "var(--ink-3)", fontSize: 12.5, display: "inline-flex", alignItems: "center", gap: 5 }}>
            <Icon name="clock" size={12} /> Real-time updates · last sync just now
          </span>
          <button className="btn btn-ghost btn-sm"><Icon name="more" size={14} /> Audit log</button>
        </div>
      </div>

      <ConfirmDialog open={!!confirmRevoke}
        title={confirmRevoke ? `Revoke access for ${confirmRevoke.pid}?` : ""}
        body="This permanently removes the principal from the access graph. This cannot be undone."
        confirmLabel="Revoke access"
        onCancel={() => setConfirmRevoke(null)}
        onConfirm={() => { handleAction(confirmRevoke, "revoke"); setConfirmRevoke(null); }} />
    </>
  );
}

function SpEmpty() {
  return (
    <div className="sp-empty">
      <div className="sp-empty-ic"><Icon name="shield" size={28} /></div>
      <h3>No quarantined principals</h3>
      <p>This policy is actively monitoring. Principals will appear here when quarantine conditions are triggered.</p>
    </div>
  );
}
function SpResolved({ principals }) {
  return (
    <div className="sp-empty">
      <div className="sp-empty-ic" style={{ background: "var(--green-tint)", color: "var(--green)" }}><Icon name="checkCircle" size={28} /></div>
      <h3>All principals resolved</h3>
      <p>{principals.length} {principals.length === 1 ? "principal has" : "principals have"} been processed under this policy.</p>
    </div>
  );
}

function PrincipalTable({ principals, resolution, onAction, onRevoke }) {
  return (
    <table className="ptbl">
      <colgroup><col style={{ width: "22%" }} /><col style={{ width: "10%" }} /><col style={{ width: "36%" }} /><col style={{ width: "14%" }} /><col style={{ width: "18%" }} /></colgroup>
      <thead><tr><th>Principal</th><th>Identity</th><th>Clipped via</th><th>Status</th><th style={{ textAlign: "right" }}>Action</th></tr></thead>
      <tbody>
        {principals.map((p) => (
          <PrincipalRow key={p.pid} principal={p} resolution={resolution} onAction={(k) => onAction(p, k)} onRevoke={() => onRevoke(p)} />
        ))}
      </tbody>
    </table>
  );
}

function PrincipalRow({ principal: p, resolution, onAction, onRevoke }) {
  return (
    <tr>
      <td>
        <div className="pid">{p.pid}</div>
        <div className="pid-time"><Icon name="clock" size={11} /> {formatDuration(p.quarantineSec)} ago</div>
      </td>
      <td><Pill tone={IDENTITY_PILL[p.type]}>{p.type}</Pill></td>
      <td>
        <div style={{ marginBottom: 6 }}><Pill tone={TRIGGER_PILL[p.trigger]} dot>{p.trigger}</Pill></div>
        <div className="reason">{p.reason}</div>
      </td>
      <td>
        <Pill tone={STATUS_PILL[p.status]}>
          {p.status === "Auto-restoring" && <span className="status-pulse" style={{ marginRight: 4 }} />}{p.status}
        </Pill>
      </td>
      <td style={{ textAlign: "right" }}>
        <ActionCell status={p.status} resolution={resolution} onAction={onAction} onRevoke={onRevoke} />
      </td>
    </tr>
  );
}

function ActionCell({ status, resolution, onAction, onRevoke }) {
  if (status === "Resolved") return <span className="action-disabled">Access granted</span>;
  if (status === "Permanently revoked") return <span className="action-disabled">Revoked</span>;
  if (status === "Awaiting resolution") return <span className="action-disabled">Approval sent</span>;
  if (status === "Approval sent") return <span className="action-disabled">Approval sent</span>;
  if (status === "In certification") return <span className="action-disabled">Campaign launched</span>;
  if (status === "Auto-restoring") return <span className="action-disabled">Auto-restoring…</span>;

  switch (resolution) {
    case "Auto-Restore":
      return <span className="action-disabled">Auto-restore</span>;
    case "HITL":
      return (
        <div className="action-stack">
          <button className="btn-action btn-blue" onClick={() => onAction("send-approval")}><Icon name="send" size={11} /> Send approval</button>
          <button className="btn-action btn-revoke" onClick={onRevoke}>Revoke</button>
        </div>);
    case "Manual Admin Grant":
      return (
        <div className="action-stack">
          <button className="btn-action btn-teal" onClick={() => onAction("grant")}><Icon name="check" size={11} /> Grant access</button>
          <button className="btn-action btn-revoke" onClick={onRevoke}>Revoke</button>
        </div>);
    case "Launch Certification":
      return (
        <div className="action-stack">
          <button className="btn-action btn-purple" onClick={() => onAction("launch")}><Icon name="rocket" size={11} /> Launch campaign</button>
          <button className="btn-action btn-revoke" onClick={onRevoke}>Revoke</button>
        </div>);
    default: return null;
  }
}

Object.assign(window, { ToastProvider, useToast, ConfirmDialog, SidePanel });

/* ===================== aai-policies.jsx ===================== */
/* global React, Icon, Pill */
/* Isolation Policies page + 4-step Create Policy builder */
const { useMemo: ipUseMemo } = React;

function SortHeader({ col, label, sortBy, sortDir, toggle, style, alignRight }) {
  const active = sortBy === col;
  return (
    <th style={style}>
      <button className={`sort-head ${active ? "active" : ""}`} onClick={() => toggle(col)} style={{ marginLeft: alignRight ? "auto" : 0 }}>
        <span>{label}</span>
        {active ? <Icon name={sortDir === "asc" ? "arrowUp" : "arrowDown"} size={11} /> : <Icon name="sort" size={11} style={{ opacity: .4 }} />}
      </button>
    </th>
  );
}

function IsolationPolicies({ policies, openPanel, goCreate, goDashboard }) {
  const [filter, setFilter] = React.useState("all");
  const [sortBy, setSortBy] = React.useState("principals");
  const [sortDir, setSortDir] = React.useState("desc");
  const [page, setPage] = React.useState(1);
  const PER_PAGE = 15;

  const counts = ipUseMemo(() => {
    const c = { all: policies.length, rbp: 0, iaa: 0, mwb: 0, uap: 0, aig: 0 };
    policies.forEach((p) => { c[p.category]++; });
    return c;
  }, [policies]);

  const filtered = ipUseMemo(() => {
    const list = filter === "all" ? policies : policies.filter((p) => p.category === filter);
    const act = (p) => p.principals.filter((x) => !["Resolved", "Permanently revoked"].includes(x.status)).length;
    const sorted = [...list].sort((a, b) => {
      let av, bv;
      switch (sortBy) {
        case "id": av = a.id; bv = b.id; break;
        case "name": av = a.name; bv = b.name; break;
        case "category": av = a.category; bv = b.category; break;
        case "resolution": av = a.resolution; bv = b.resolution; break;
        default: av = act(a); bv = act(b);
      }
      const cmp = av < bv ? -1 : av > bv ? 1 : 0;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return sorted;
  }, [policies, filter, sortBy, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
  const paged = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE);
  const toggleSort = (col) => {
    if (sortBy === col) setSortDir((d) => d === "asc" ? "desc" : "asc");
    else { setSortBy(col); setSortDir(col === "principals" ? "desc" : "asc"); }
  };

  const tabs = [
    { id: "all", label: "All", count: counts.all },
    { id: "rbp", label: "Runtime behavioral", count: counts.rbp },
    { id: "iaa", label: "Identity-aware", count: counts.iaa },
    { id: "mwb", label: "Malicious blocking", count: counts.mwb },
    { id: "uap", label: "Unsafe action", count: counts.uap },
    { id: "aig", label: "Agent governance", count: counts.aig },
  ];

  return (
    <div className="hp-wrap">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 24 }}>
        <div>
          <a className="crumb" onClick={goDashboard}><Icon name="arrowLeft" size={12} /> Dashboard</a>
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 600, letterSpacing: "-.02em", color: "var(--ink)" }}>Isolation policies</h1>
          <p style={{ margin: "4px 0 0", color: "var(--ink-3)", fontSize: 13.5 }}>25 active policies governing access clipping for users, agents, NHIs, and MCP servers</p>
        </div>
        <button className="btn btn-primary" onClick={goCreate}><Icon name="plus" size={14} /> Create policy</button>
      </div>

      <div className="ip-tabs">
        {tabs.map((t) => (
          <button key={t.id} className={`ip-tab ${filter === t.id ? "on" : ""}`} onClick={() => { setFilter(t.id); setPage(1); }}>
            {t.label} <span className="ct">({t.count})</span>
          </button>
        ))}
      </div>

      <div className="card" style={{ overflow: "hidden" }} key={filter}>
        <table className="tbl">
          <thead>
            <tr>
              <SortHeader col="id" label="Policy ID" sortBy={sortBy} sortDir={sortDir} toggle={toggleSort} style={{ width: 140 }} />
              <SortHeader col="name" label="Policy name" sortBy={sortBy} sortDir={sortDir} toggle={toggleSort} />
              <SortHeader col="category" label="Category" sortBy={sortBy} sortDir={sortDir} toggle={toggleSort} style={{ width: 120 }} />
              <SortHeader col="resolution" label="Resolution" sortBy={sortBy} sortDir={sortDir} toggle={toggleSort} style={{ width: 200 }} />
              <SortHeader col="principals" label="Principals" sortBy={sortBy} sortDir={sortDir} toggle={toggleSort} style={{ width: 110 }} alignRight />
              <th style={{ width: 100, textAlign: "right" }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {paged.map((p) => {
              const active = p.principals.filter((x) => !["Resolved", "Permanently revoked"].includes(x.status)).length;
              return (
                <tr key={p.id} className="clickable" onClick={() => openPanel(p.id)}>
                  <td><span className="mono-id">{p.id}</span></td>
                  <td><span style={{ fontWeight: 600, color: "var(--ink)" }}>{p.name}</span></td>
                  <td><span className="cat-code">{CATEGORIES[p.category].short}</span></td>
                  <td><Pill tone={RESOLUTION_PILL[p.resolution]}>{p.resolution}</Pill></td>
                  <td style={{ textAlign: "right" }}><span className={active ? "pcount active" : "pcount zero"}>{active}</span></td>
                  <td style={{ textAlign: "right" }}><a className="hp-seelink" onClick={(e) => { e.stopPropagation(); openPanel(p.id); }}>Review</a></td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div className="tbl-foot">
          <span>Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, filtered.length)} of {filtered.length}</span>
          <div style={{ display: "flex", gap: 6 }}>
            <button className="btn btn-ghost btn-sm" disabled={page === 1} style={page === 1 ? { opacity: .5 } : null} onClick={() => setPage((p) => p - 1)}><Icon name="arrowLeft" size={12} /> Prev</button>
            <button className="btn btn-ghost btn-sm" disabled={page === totalPages} style={page === totalPages ? { opacity: .5 } : null} onClick={() => setPage((p) => p + 1)}>Next <Icon name="arrowRight" size={12} /></button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---------------- Create Policy ---------------- */
function CpField({ label, sublabel, required, error, children }) {
  return (
    <div className="cp-field">
      <label className="cp-flabel">
        <span>{label} {required && <span style={{ color: "var(--red)" }}>*</span>}</span>
        {sublabel && <span className="cp-fsub">{sublabel}</span>}
      </label>
      <div className="cp-finput">{children}</div>
      {error && <div className="cp-err"><Icon name="alert" size={11} /> {error}</div>}
    </div>
  );
}

function CreatePolicy({ goPolicies }) {
  const toast = useToast();
  const [step, setStep] = React.useState(1);
  const [completed, setCompleted] = React.useState(new Set());
  const [confirmCancel, setConfirmCancel] = React.useState(false);
  const [errors, setErrors] = React.useState({});
  const [form, setForm] = React.useState({
    name: "", category: "rbp", description: "", metric: "Policy denial count", operator: "Greater than",
    threshold: 5, windowVal: 60, windowUnit: "seconds", source: "Authorization engine",
    subjects: ["Agent"], targetScope: "full", targetType: "App", resolution: "HITL",
    ttl: 30, ttlUnit: "minutes", channels: ["Console", "Email"], certifier: "",
  });
  const policyId = `AAI-CUSTOM-${String(Date.now()).slice(-3).padStart(3, "0")}`;
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const validate = (s) => {
    const e = {};
    if (s === 1) { if (!form.name.trim()) e.name = "Policy name is required"; else if (form.name.length > 80) e.name = "Max 80 characters"; }
    if (s === 2) { if (!form.threshold || form.threshold <= 0) e.threshold = "Must be a positive integer"; if (!form.windowVal || form.windowVal <= 0) e.windowVal = "Required"; }
    if (s === 3) { if (form.subjects.length === 0) e.subjects = "Select at least one subject type"; }
    return e;
  };
  const next = () => { const e = validate(step); setErrors(e); if (Object.keys(e).length === 0) { setCompleted((c) => new Set([...c, step])); setStep((s) => Math.min(4, s + 1)); } };
  const goTo = (s) => { if (s < step || completed.has(s - 1) || s === step) setStep(s); };
  const cancel = () => { if (form.name || form.description) setConfirmCancel(true); else goPolicies(); };
  const activate = () => { toast(`Policy ${policyId} activated — monitoring is live`); setTimeout(goPolicies, 600); };

  const steps = [{ n: 1, label: "Define" }, { n: 2, label: "Trigger" }, { n: 3, label: "Enforcement" }, { n: 4, label: "Review" }];

  return (
    <div className="hp-wrap">
      <div style={{ marginBottom: 24 }}>
        <a className="crumb" onClick={goPolicies}><Icon name="arrowLeft" size={12} /> Isolation policies</a>
        <h1 style={{ margin: 0, fontSize: 24, fontWeight: 600, letterSpacing: "-.02em", color: "var(--ink)" }}>Create isolation policy</h1>
        <p style={{ margin: "4px 0 0", color: "var(--ink-3)", fontSize: 13.5 }}>Define when and how access should be clipped</p>
      </div>

      <div className="cp-stepper">
        {steps.map((s, i) => {
          const isDone = completed.has(s.n), isActive = step === s.n;
          const clickable = isDone || isActive || (i > 0 && completed.has(s.n - 1));
          return (
            <div key={s.n} className="cp-srow">
              <button className={`cp-step ${isActive ? "active" : ""} ${isDone ? "done" : ""}`} onClick={() => clickable && goTo(s.n)} style={{ cursor: clickable ? "pointer" : "default" }}>
                <span className="cp-sdot">{isDone ? <Icon name="check" size={11} /> : s.n}</span>
                <span className="cp-slabel">{s.label}</span>
              </button>
              {i < steps.length - 1 && <div className={`cp-line ${isDone ? "done" : ""}`} />}
            </div>
          );
        })}
      </div>

      <div className="cp-builder">
        {step === 1 && <CpStep1 form={form} set={set} errors={errors} policyId={policyId} />}
        {step === 2 && <CpStep2 form={form} set={set} errors={errors} />}
        {step === 3 && <CpStep3 form={form} set={set} errors={errors} />}
        {step === 4 && <CpStep4 form={form} policyId={policyId} />}

        <div className="cp-foot">
          <button className="btn btn-ghost" onClick={cancel}>Cancel</button>
          <div style={{ display: "flex", gap: 8 }}>
            {step > 1 && <button className="btn btn-ghost" onClick={() => setStep((s) => s - 1)}><Icon name="arrowLeft" size={12} /> Back</button>}
            {step < 4 ? <button className="btn btn-primary" onClick={next}>Continue <Icon name="arrowRight" size={12} /></button> : (
              <>
                <button className="btn btn-ghost">Save as draft</button>
                <button className="btn btn-primary" onClick={activate}><Icon name="zap" size={13} /> Activate policy</button>
              </>
            )}
          </div>
        </div>
      </div>

      <ConfirmDialog open={confirmCancel} title="Discard policy?" body="You have unsaved changes. Leaving now will discard your progress."
        confirmLabel="Discard" onCancel={() => setConfirmCancel(false)} onConfirm={() => { setConfirmCancel(false); goPolicies(); }} />
    </div>
  );
}

function CpStep1({ form, set, errors, policyId }) {
  return (
    <div className="cp-pane">
      <h2 className="cp-title">Define the policy</h2>
      <p className="cp-desc">Give it a clear name and choose where it lives in your governance taxonomy.</p>
      <CpField label="Policy name" required error={errors.name}>
        <input className={`cp-input ${errors.name ? "err" : ""}`} placeholder="e.g., Custom API rate limiting" value={form.name} maxLength={80} onChange={(e) => set("name", e.target.value)} />
        <span className="cp-cc">{form.name.length} / 80</span>
      </CpField>
      <CpField label="Category">
        <select className="cp-input" value={form.category} onChange={(e) => set("category", e.target.value)}>
          {Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
      </CpField>
      <CpField label="Description" sublabel="Optional. What problem does this policy address?">
        <textarea className="cp-input" rows={3} placeholder="Describe when and why this policy should trigger" value={form.description} maxLength={300} onChange={(e) => set("description", e.target.value)} />
        <span className="cp-cc">{form.description.length} / 300</span>
      </CpField>
      <CpField label="Policy ID" sublabel="Auto-generated">
        <span className="cp-readonly"><span className="mono-id">{policyId}</span></span>
      </CpField>
    </div>
  );
}

function CpStep2({ form, set, errors }) {
  const sentence = `Trigger when ${form.metric.toLowerCase()} is ${form.operator.toLowerCase()} ${form.threshold} within ${form.windowVal} ${form.windowUnit} from ${form.source.toLowerCase()}`;
  return (
    <div className="cp-pane">
      <h2 className="cp-title">Trigger condition</h2>
      <p className="cp-desc">Build the rule that determines when this policy fires.</p>
      <div className="cp-trigger">
        <span className="cp-tt">When</span>
        <select className="cp-input cp-tinput" value={form.metric} onChange={(e) => set("metric", e.target.value)}>
          {["Policy denial count", "Tool invocation frequency", "Error rate", "Data volume", "Session count", "Authentication failures", "Custom attribute"].map((o) => <option key={o}>{o}</option>)}
        </select>
        <span className="cp-tt">is</span>
        <select className="cp-input cp-tinput" value={form.operator} onChange={(e) => set("operator", e.target.value)}>
          {["Greater than", "Less than", "Equal to", "Spike over baseline"].map((o) => <option key={o}>{o}</option>)}
        </select>
        <input className={`cp-input cp-tinput cp-tnum ${errors.threshold ? "err" : ""}`} type="number" value={form.threshold} min={1} onChange={(e) => set("threshold", parseInt(e.target.value) || 0)} />
        <span className="cp-tt">within</span>
        <input className={`cp-input cp-tinput cp-tnum ${errors.windowVal ? "err" : ""}`} type="number" value={form.windowVal} min={1} onChange={(e) => set("windowVal", parseInt(e.target.value) || 0)} />
        <select className="cp-input cp-tinput" value={form.windowUnit} onChange={(e) => set("windowUnit", e.target.value)}>
          {["seconds", "minutes", "hours"].map((o) => <option key={o}>{o}</option>)}
        </select>
        <span className="cp-tt">from</span>
        <select className="cp-input cp-tinput" value={form.source} onChange={(e) => set("source", e.target.value)}>
          {["Authorization engine", "Identity provider", "Runtime monitor", "Threat intelligence", "MCP runtime"].map((o) => <option key={o}>{o}</option>)}
        </select>
      </div>
      <div className="cp-preview">
        <div className="cp-preview-lbl">Live preview</div>
        <div className="cp-preview-text">{sentence}</div>
      </div>
    </div>
  );
}

function CpStep3({ form, set, errors }) {
  const toggleSubject = (s) => { const has = form.subjects.includes(s); set("subjects", has ? form.subjects.filter((x) => x !== s) : [...form.subjects, s]); };
  const toggleChannel = (c) => { const has = form.channels.includes(c); set("channels", has ? form.channels.filter((x) => x !== c) : [...form.channels, c]); };
  const subjects = ["User", "Agent", "NHI", "MCP server"];
  const resolutions = [
    { id: "Auto-Restore", desc: "System automatically reinstates access after timer", icon: "shuffle" },
    { id: "HITL", desc: "Requires reviewer approval to reinstate", icon: "users" },
    { id: "Manual Admin Grant", desc: "Only security admin can reinstate", icon: "lock" },
    { id: "Launch Certification", desc: "Formal certification campaign to resolve", icon: "rocket" },
  ];
  const toneVar = { "Auto-Restore": "green", "HITL": "amber", "Manual Admin Grant": "red", "Launch Certification": "purple" };
  return (
    <div className="cp-pane">
      <h2 className="cp-title">Enforcement</h2>
      <p className="cp-desc">Choose who's affected and how access is restored.</p>
      <CpField label="Subject type" sublabel="Which identities does this policy clip?" error={errors.subjects}>
        <div className="cp-chips">
          {subjects.map((s) => (
            <button key={s} type="button" className={`cp-chip ${form.subjects.includes(s) ? "on" : ""}`} onClick={() => toggleSubject(s)}>
              {form.subjects.includes(s) && <Icon name="check" size={11} />} {s}
            </button>
          ))}
        </div>
      </CpField>
      <CpField label="Target scope">
        <div className="cp-radios">
          <label className={`cp-radio ${form.targetScope === "full" ? "on" : ""}`} onClick={() => set("targetScope", "full")}>
            <div><div className="cp-rt">Full</div><div className="cp-rs">Clip all access for matched principals</div></div>
          </label>
          <label className={`cp-radio ${form.targetScope === "targeted" ? "on" : ""}`} onClick={() => set("targetScope", "targeted")}>
            <div><div className="cp-rt">Targeted</div><div className="cp-rs">Clip only specific resource type</div></div>
          </label>
        </div>
        {form.targetScope === "targeted" && (
          <select className="cp-input" style={{ marginTop: 12, maxWidth: 240 }} value={form.targetType} onChange={(e) => set("targetType", e.target.value)}>
            {["App", "MCP server", "Tool", "Sub-agent"].map((o) => <option key={o}>{o}</option>)}
          </select>
        )}
      </CpField>
      <CpField label="Resolution path">
        <div className="cp-resgrid">
          {resolutions.map((r) => (
            <label key={r.id} className={`cp-res ${form.resolution === r.id ? "on" : ""}`} onClick={() => set("resolution", r.id)}>
              <div className="cp-res-ic" style={{ background: `var(--${toneVar[r.id]}-tint)`, color: `var(--${toneVar[r.id]}-ink, var(--${toneVar[r.id]}))` }}><Icon name={r.icon} size={16} /></div>
              <div style={{ flex: 1 }}>
                <div style={{ marginBottom: 4 }}><Pill tone={RESOLUTION_PILL[r.id]}>{r.id}</Pill></div>
                <div className="cp-rs">{r.desc}</div>
              </div>
            </label>
          ))}
        </div>
      </CpField>
      {(form.resolution === "Auto-Restore" || form.resolution === "HITL") && (
        <CpField label="Time-to-live" sublabel="How long before access is automatically reinstated">
          <div style={{ display: "flex", gap: 8, maxWidth: 320 }}>
            <input className="cp-input" type="number" value={form.ttl} min={1} style={{ flex: 1 }} onChange={(e) => set("ttl", parseInt(e.target.value) || 0)} />
            <select className="cp-input" value={form.ttlUnit} onChange={(e) => set("ttlUnit", e.target.value)} style={{ flex: 1 }}>
              {["minutes", "hours", "days"].map((o) => <option key={o}>{o}</option>)}
            </select>
          </div>
        </CpField>
      )}
      {(form.resolution === "HITL" || form.resolution === "Manual Admin Grant") && (
        <CpField label="Notification channels">
          <div className="cp-chips">
            {["Console", "Email", "Slack", "Push notification"].map((c) => (
              <button key={c} type="button" className={`cp-chip ${form.channels.includes(c) ? "on" : ""}`} onClick={() => toggleChannel(c)}>
                {form.channels.includes(c) && <Icon name="check" size={11} />} {c}
              </button>
            ))}
          </div>
        </CpField>
      )}
      {form.resolution === "Launch Certification" && (
        <CpField label="Default certifier" sublabel="Who reviews the campaign?">
          <input className="cp-input" placeholder="Search by name or team…" value={form.certifier} onChange={(e) => set("certifier", e.target.value)} style={{ maxWidth: 320 }} />
        </CpField>
      )}
    </div>
  );
}

function CpSumRow({ label, value }) { return <div className="cp-sumrow"><span className="cp-sumlbl">{label}</span><span className="cp-sumval">{value}</span></div>; }

function CpStep4({ form, policyId }) {
  return (
    <div className="cp-pane">
      <h2 className="cp-title">Review and activate</h2>
      <p className="cp-desc">Confirm settings. Once activated, this policy begins monitoring immediately.</p>
      <div className="cp-summary">
        <CpSumRow label="Policy ID" value={<span className="mono-id">{policyId}</span>} />
        <CpSumRow label="Name" value={form.name || <em style={{ color: "var(--ink-4)" }}>Unnamed</em>} />
        <CpSumRow label="Category" value={CATEGORIES[form.category].label} />
        <CpSumRow label="Description" value={form.description || <em style={{ color: "var(--ink-4)" }}>—</em>} />
        <div className="cp-sumdiv" />
        <CpSumRow label="Trigger" value={<span style={{ color: "var(--ink-2)" }}>When <b>{form.metric.toLowerCase()}</b> is <b>{form.operator.toLowerCase()}</b> <b>{form.threshold}</b> within <b>{form.windowVal} {form.windowUnit}</b> from <b>{form.source.toLowerCase()}</b></span>} />
        <div className="cp-sumdiv" />
        <CpSumRow label="Subjects" value={<div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>{form.subjects.map((s) => <Pill key={s} tone={IDENTITY_PILL[s.replace(" server", "")] || "gray"}>{s}</Pill>)}</div>} />
        <CpSumRow label="Scope" value={form.targetScope === "full" ? "Full — all targets" : `Targeted — ${form.targetType}`} />
        <CpSumRow label="Resolution" value={<Pill tone={RESOLUTION_PILL[form.resolution]}>{form.resolution}</Pill>} />
        {(form.resolution === "Auto-Restore" || form.resolution === "HITL") && <CpSumRow label="TTL" value={`${form.ttl} ${form.ttlUnit}`} />}
        {(form.resolution === "HITL" || form.resolution === "Manual Admin Grant") && <CpSumRow label="Notify via" value={form.channels.join(", ") || "—"} />}
      </div>
      <div className="cp-preview" style={{ marginTop: 24 }}>
        <div className="cp-preview-lbl">Appears in policies table as</div>
        <div className="cp-table-preview">
          <span className="mono-id">{policyId}</span>
          <span style={{ flex: 1, fontWeight: 600, color: "var(--ink)" }}>{form.name || "Unnamed policy"}</span>
          <span className="cat-code">{CATEGORIES[form.category].short}</span>
          <Pill tone={RESOLUTION_PILL[form.resolution]}>{form.resolution}</Pill>
          <span className="pcount zero">0</span>
        </div>
      </div>
      <div className="cp-warn"><Icon name="alert" size={14} /><span>Once activated, this policy begins monitoring immediately. Policies cannot be deleted — only deprecated.</span></div>
    </div>
  );
}

Object.assign(window, { IsolationPolicies, CreatePolicy });

/* ===================== home.jsx ===================== */
/* global React, Icon, Pill, Mark */
/* Home Dashboard (greeting, KPIs, violations, AAI card, agent inventory) + HomeApp container */

const KPIS = [
  { icon: "box", bg: "var(--blue-tint)", fg: "var(--blue-700)", num: "17", delta: "12%", dir: "up", label: "Ungoverned Agents",
    sub: "17 agents across 5 sources have no policies assigned. GitHub has the highest concentration with 6 ungoverned agents." },
  { icon: "flag", bg: "var(--coral-tint)", fg: "var(--coral)", num: "18", delta: "8%", dir: "down", label: "Active Violations",
    sub: "12 deny and 6 conditional-allow decisions in the last 7 days. 4 goal-hijack violations unresolved, directly impacting OWASP ASI compliance." },
  { icon: "umbrella", bg: "var(--amber-tint)", fg: "var(--amber)", num: "34%", delta: "6%", dir: "down", label: "Enforce Coverage Gap",
    sub: "34% of agent-to-resource edges have no enforcement policy. Underwriter platform and fraud-models are the largest uncovered surfaces." },
  { icon: "heartShield", bg: "var(--green-tint)", fg: "var(--green)", num: "82%", delta: "4%", dir: "up", label: "Access Policy Health",
    sub: "82% of policies pass all design guardrails. 3 policies flagged for missing mandatory conditions, 2 for conflicting permit/forbid effects." },
];

const COMPLIANCE_DOT = {
  "OWASP ASI": "#16A34A", "NIST AI-RMF": "#2563EB", "MAESTRO": "#7C3AED", "HIPAA": "#EA580C", "SOX": "#D97706",
  "NIST 800-53": "#0D9488", "EU AI Act": "#7C3AED",
};

const RUNTIME = {
  filters: ["All", "OWASP ASI", "NIST AI-RMF", "MAESTRO", "HIPAA", "SOX"],
  rows: [
    { name: "Global Baseline (All) : Minimum Trust Score", tags: ["OWASP ASI", "NIST AI-RMF", "MAESTRO"], n: 2 },
    { name: "Global Baseline (Agent) : Threat Protection", tags: ["OWASP ASI", "MAESTRO"], n: 1 },
    { name: "Behavioral Monitoring (Agent) : Drift & Anomaly", tags: ["OWASP ASI", "MAESTRO"], n: 2 },
    { name: "Data Protection (All) : PII & Sensitive Data", tags: ["HIPAA", "OWASP ASI"], n: 1 },
    { name: "Identity & Trust (All) : Session Decay", tags: ["NIST AI-RMF", "MAESTRO"], n: 2 },
  ],
};
const DESIGN = {
  filters: ["All", "NIST 800-53", "SOX", "NIST AI-RMF", "EU AI Act"],
  rows: [
    { name: "Enforce Mandatory Policy Conditions", tags: ["NIST 800-53:AC-16"], n: 3 },
    { name: "Prevent Overly Permissive Policies", tags: ["NIST 800-53:AC-6"], n: 0 },
    { name: "Use Specific Resources Instead of Wildcard", tags: ["SOX"], n: 0 },
    { name: "Prevent Conflicting Policy Effects", tags: ["NIST 800-53:AC-4"], n: 2 },
    { name: "Prevent Create And Approve Permission (SOD)", tags: ["NIST 800-53:AC-5", "SOX"], n: 0 },
  ],
};

const INVENTORY = [
  { name: "Commercial Credit Memo Copilot (Microsoft Copilot Studio)", conn: [["box", 1, "var(--blue)"], ["shuffle", 2, "var(--amber)"], ["server", 1, "var(--teal)"]], type: "SaaS", typeTone: "blue", users: 18, app: "Microsoft Copilot Studio", owner: "Lisa Hoffman", brand: "microsoft", status: "Governed" },
  { name: "ReAct Agent", conn: [["shuffle", 1, "var(--amber)"], ["server", 1, "var(--teal)"]], type: "Custom", typeTone: "coral", users: 4, app: "React Agent", owner: "Alex Turner", brand: "langchain", status: "Governed" },
  { name: "underwriting-agent-01", conn: [["box", 2, "var(--blue)"], ["shuffle", 2, "var(--amber)"], ["server", 1, "var(--teal)"]], type: "Custom", typeTone: "coral", users: 5, app: null, owner: "David Wilson", brand: "github", status: "Discovered" },
  { name: "FinBot", conn: [["box", 5, "var(--blue)"], ["shuffle", 3, "var(--amber)"], ["server", 1, "var(--teal)"]], type: "Custom", typeTone: "coral", users: 22, app: null, owner: "Alexis Turner", brand: "github", status: "Discovered" },
  { name: "shipment_supervisor", conn: [["box", 1, "var(--blue)"], ["shuffle", 12, "var(--amber)"], ["server", 1, "var(--teal)"]], type: "Custom", typeTone: "coral", users: 3, app: null, owner: "Laura Garcia", brand: "github", status: "Discovered" },
  { name: "FraudTriageAgent", conn: [["box", 1, "var(--blue)"], ["shuffle", 2, "var(--amber)"], ["server", 1, "var(--teal)"]], type: "Enterprise", typeTone: "purple", users: 14, app: null, owner: "Laura Garcia", brand: "crewai", status: "Discovered" },
  { name: "RelationshipBankerAgent", conn: [["shuffle", 2, "var(--amber)"], ["server", 1, "var(--teal)"]], type: "SaaS", typeTone: "blue", users: 45, app: null, owner: "Emily Johnson", brand: "cloud", status: "Discovered" },
  { name: "Claude Code (Engineering)", conn: [["server", 1, "var(--teal)"]], type: "Coding Agent", typeTone: "amber", users: 85, app: null, owner: "Michael Brown", brand: "anthropic", status: "Discovered" },
];

function KpiCard({ k }) {
  return (
    <div className="card hp-stat">
      <div className="hp-stat-head">
        <div className="hp-stat-ic" style={{ background: k.bg, color: k.fg }}><Icon name={k.icon} size={18} /></div>
        <a className="hp-seelink">See all <Icon name="arrowRight" size={12} /></a>
      </div>
      <div className="hp-stat-num">{k.num}
        <span className={`hp-delta ${k.dir}`}><Icon name={k.dir === "up" ? "arrowUp" : "arrowDown"} size={11} />{k.delta}</span>
      </div>
      <div className="hp-stat-lbl">{k.label}</div>
      <div className="hp-stat-sub">{k.sub}</div>
    </div>
  );
}

function ViolationCard({ title, data }) {
  const [filter, setFilter] = React.useState("All");
  const [scope, setScope] = React.useState("agent");
  const rows = filter === "All" ? data.rows : data.rows.filter((r) => r.tags.some((t) => t.startsWith(filter)));
  return (
    <div className="card" style={{ overflow: "hidden" }}>
      <div className="hp-card-head">
        <h3>{title}</h3>
        <div className="hp-runtog">
          <button className={scope === "all" ? "on" : ""} onClick={() => setScope("all")} title="All"><Icon name="shield" size={14} /></button>
          <button className={scope === "agent" ? "on" : ""} onClick={() => setScope("agent")} title="Agent"><Icon name="shieldAlert" size={14} /></button>
        </div>
        <a className="hp-seelink">See all</a>
      </div>
      <div className="hp-fpills">
        {data.filters.map((f) => (
          <button key={f} className={`hp-fpill ${filter === f ? "on" : ""}`} onClick={() => setFilter(f)}>
            {f !== "All" && <span className="cdot" style={{ background: COMPLIANCE_DOT[f] || "var(--ink-4)" }} />}{f}
          </button>
        ))}
      </div>
      <div>
        {rows.map((r) => (
          <div className="hp-vrow" key={r.name}>
            <div className="hp-vrow-main">
              <div className="hp-vrow-name">{r.name}</div>
              <div className="hp-vrow-tags">
                {r.tags.map((t) => {
                  const base = t.split(":")[0];
                  return <span className="hp-vtag" key={t}><span className="cdot" style={{ background: COMPLIANCE_DOT[base] || "var(--ink-4)" }} />{t}</span>;
                })}
              </div>
            </div>
            <span className={`hp-vcount ${r.n > 0 ? "warn" : "ok"}`}><Icon name="alert" size={12} />{r.n}</span>
            <Icon name="chevRight" size={16} color="var(--ink-4)" />
          </div>
        ))}
      </div>
    </div>
  );
}

function AaiDashCard({ openPanel, goPolicies }) {
  const reva = useReva();
  const liveCount = (id) => (reva.quarantine.quarantined || []).filter((q) => q.policyId === id).length;
  const rows = [
    { policyId: "AAI-RBP-002", name: "High Denial Rate", trigger: "Runtime", count: liveCount("AAI-RBP-002"), age: 47 * 60, just: "Repeated authorization denials in a short window" },
    { policyId: "AAI-UAP-001", name: "Prompt Injection Detection", trigger: "Runtime", count: liveCount("AAI-UAP-001"), age: 2 * 3600, just: "Injection payload detected in agent input — system prompt override attempt" },
    { policyId: "AAI-RBP-003", name: "Ephemeral Agent Surge", trigger: "Runtime", count: liveCount("AAI-RBP-003"), age: 12 * 60, just: "Parallel agent spawns exceeded the per-session budget" },
    { policyId: "AAI-AIG-003", name: "Incident blast radius", trigger: "Manual", count: liveCount("AAI-AIG-003"), age: 86400, just: "Manual containment clip including access graph" },
  ];
  return (
    <div className="card" style={{ overflow: "hidden", marginBottom: 20 }}>
      <div className="aai-card-head">
        <div className="t"><Icon name="shieldAlert" size={16} color="var(--amber)" /><span>Adaptive access isolation</span></div>
        <a className="hp-seelink" style={{ marginLeft: "auto" }} onClick={goPolicies}>See all <Icon name="arrowRight" size={12} /></a>
      </div>
      <div className="aai-rows">
        {rows.map((r) => (
          <div className="aai-row" key={r.policyId}>
            <div className="aai-row-l1">
              <span className="aai-row-name" title={r.name}>{r.name}</span>
              <a className="hp-seelink" onClick={() => openPanel(r.policyId)}>Review</a>
            </div>
            <div className="aai-row-pills">
              <Pill tone={TRIGGER_PILL[r.trigger]} dot>{r.trigger}</Pill>
              <Pill tone="gray">{r.count} {r.count === 1 ? "principal" : "principals"}</Pill>
              <Pill tone={timeBadgeTone(r.age)}><Icon name="clock" size={10} /> {formatDuration(r.age)}</Pill>
            </div>
            <div className="aai-row-just">{r.just}</div>
          </div>
        ))}
      </div>
      <div className="aai-foot">
        <div className="aai-foot-grp"><span className="aai-foot-dot" style={{ background: "var(--amber)" }} /><span className="aai-foot-num">24</span><span className="aai-foot-lbl">quarantined</span>
          <span style={{ width: 18, height: 18, borderRadius: 4, display: "grid", placeItems: "center", background: "var(--red-tint)", color: "var(--red)", marginLeft: 2 }}><Icon name="arrowUp" size={11} /></span>
        </div>
        <div className="aai-foot-grp"><span className="aai-foot-dot" style={{ background: "var(--red)" }} /><span className="aai-foot-num">15</span><span className="aai-foot-lbl">awaiting resolution</span></div>
      </div>
    </div>
  );
}

function AgentInventory() {
  return (
    <div className="card" style={{ overflow: "hidden" }}>
      <div className="hp-card-head">
        <h3>Agent Inventory</h3>
        <a className="hp-seelink" style={{ marginLeft: "auto" }}>See all <Icon name="arrowRight" size={12} /></a>
      </div>
      <table className="tbl">
        <thead>
          <tr><th>Name</th><th>Connections</th><th>Agent Type</th><th className="right">Users</th><th>Apps</th><th>Owner</th><th>Source</th><th>Status</th><th></th></tr>
        </thead>
        <tbody>
          {INVENTORY.map((a) => (
            <tr key={a.name} className="clickable">
              <td style={{ maxWidth: 280 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                  <span style={{ fontWeight: 600, color: "var(--ink)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name}</span>
                  <Icon name="chevRight" size={13} color="var(--ink-4)" />
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 4, marginTop: 4, fontSize: 11.5, color: "var(--ink-3)" }}><Icon name="box" size={11} /> Agent</div>
              </td>
              <td>
                <div className="hp-conn-wrap">
                  {a.conn.map(([ic, n, col], i) => (
                    <span key={i} className="hp-inv-conn" style={{ background: "var(--surface-3)", color: col }}><Icon name={ic} size={12} />{n}</span>
                  ))}
                </div>
              </td>
              <td><span className={`hp-agent-type`} style={{ color: `var(--${a.typeTone}-ink, var(--${a.typeTone}))` }}>{a.type}</span></td>
              <td className="right" style={{ fontVariantNumeric: "tabular-nums", fontWeight: 600 }}>{a.users}</td>
              <td>{a.app ? <Pill tone="blue">{a.app}</Pill> : <span style={{ color: "var(--ink-4)" }}>—</span>}</td>
              <td className="sub">{a.owner}</td>
              <td><span style={{ display: "inline-grid", placeItems: "center", width: 26, height: 26 }}><Mark brand={a.brand} size={20} /></span></td>
              <td>
                {a.status === "Governed"
                  ? <span className="hp-status gov"><Icon name="check" size={12} /> Governed</span>
                  : <span className="hp-status disc"><Icon name="search" size={11} /> Discovered</span>}
              </td>
              <td className="right"><button className="hp-manage">{a.status === "Governed" ? "Manage" : "Assign"}</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HomeDashboard({ openPanel, goPolicies }) {
  const [mode, setMode] = React.useState("AI");
  return (
    <div className="hp-wrap">
      <div className="hp-greet-row">
        <div className="hp-greet" style={{ flex: 1 }}>
          <h1>Hey, Patrick Fuller!</h1>
          <p>Real-time insights and key performance indicators across all your applications.</p>
        </div>
        <div className="hp-mode">
          <button className={mode === "AI" ? "on" : ""} onClick={() => setMode("AI")}>AI</button>
          <button className={mode === "Application" ? "on" : ""} onClick={() => setMode("Application")}>Application</button>
        </div>
      </div>

      <div className="hp-stats">
        {KPIS.map((k) => <KpiCard key={k.label} k={k} />)}
      </div>

      <AaiDashCard openPanel={openPanel} goPolicies={goPolicies} />

      <div className="hp-cols">
        <ViolationCard title="Runtime Violations" data={RUNTIME} />
        <ViolationCard title="Design Violations" data={DESIGN} />
      </div>

      <AgentInventory />
    </div>
  );
}

/* ---------------- HomeApp container ---------------- */
function HomeApp({ initialView }) {
  const reva = useReva();
  const [view, setView] = React.useState(initialView || "dashboard"); // dashboard | policies | create
  const [policies, setPolicies] = React.useState(reva.aaiPolicies && reva.aaiPolicies.length ? reva.aaiPolicies : window.POLICIES);
  const [openPolicyId, setOpenPolicyId] = React.useState(null);
  React.useEffect(() => { if (reva.aaiPolicies && reva.aaiPolicies.length) setPolicies(reva.aaiPolicies); }, [reva.aaiPolicies]);

  const openPanel = (id) => {
    if (view !== "policies" && view !== "dashboard") setView("policies");
    setOpenPolicyId(id);
  };
  const updatePrincipal = (policyId, pid, patch) => {
    // Live reinstate — granting access or completing approval lifts the quarantine.
    if (patch.status === "Resolved") {
      const osUser = (pid || "").replace(/^(user:|agent:|dev:)/, "");
      fetch("/api/quarantine/reinstate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ osUser }) })
        .then(() => revaRefetch()).catch(() => {});
    }
    setPolicies((ps) => ps.map((p) => p.id !== policyId ? p : { ...p, principals: p.principals.map((pr) => pr.pid === pid ? { ...pr, ...patch } : pr) }));
  };
  const activePolicy = openPolicyId ? policies.find((p) => p.id === openPolicyId) : null;

  return (
    <window.ToastProvider>
      {view === "dashboard" && <HomeDashboard openPanel={openPanel} goPolicies={() => setView("policies")} />}
      {view === "policies" && <window.IsolationPolicies policies={policies} openPanel={openPanel} goCreate={() => setView("create")} goDashboard={() => setView("dashboard")} />}
      {view === "create" && <window.CreatePolicy goPolicies={() => setView("policies")} />}
      {activePolicy && <window.SidePanel policy={activePolicy} onClose={() => setOpenPolicyId(null)} onUpdatePrincipal={updatePrincipal} />}
    </window.ToastProvider>
  );
}

Object.assign(window, { HomeDashboard, HomeApp });

/* ===================== app.jsx ===================== */
/* global React, Icon, Pill */
/* Main app shell: slim left rail + top bar + page header + pill tab bar + content router */

const TABS = [
  "Insights", "Policies", "Guardrails", "Data", "Schema", "Version History",
  "Decision Logs", "Developer Integration", "Settings",
];

/* Policies tab — policy sets with risk level + enable toggle */
const RISK_TONE = { Critical: "red", High: "amber", Medium: "blue", Low: "gray" };

async function savePolicySet(id, enabled) {
  try {
    const r = await fetch("/api/config/policy-sets", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, enabled }),
    });
    const data = await r.json();
    RevaStore.set({ policySets: data.sets || [] });
  } catch (e) { /* keep UI responsive */ }
}

function GuardrailsTab() {
  const reva = useReva();
  const sets = reva.policySets || [];
  const [q, setQ] = React.useState("");
  const shown = sets.filter((s) => !q || s.name.toLowerCase().includes(q.toLowerCase()) || (s.description || "").toLowerCase().includes(q.toLowerCase()));
  const onCount = sets.filter((s) => s.enabled !== false).length;
  return (
    <div style={{ padding: 28 }}>
      <div className="card" style={{ overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "18px 20px", borderBottom: "1px solid var(--border)" }}>
          <div>
            <div className="section-title">Guardrails</div>
            <div className="help" style={{ marginTop: 2 }}>High-level protections evaluated before policies. Toggle to enable or suspend a guardrail across all sessions.</div>
          </div>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
            <div className="search" style={{ minWidth: 240 }}><Icon name="search" size={16} color="var(--ink-4)" /><input placeholder="Search guardrails…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
            <button className="btn btn-primary btn-sm" onClick={() => {}}><Icon name="plus" size={15} /> Create</button>
          </div>
        </div>
        <table className="tbl">
          <thead>
            <tr><th>Name</th><th>Description</th><th>Risk Level</th><th className="right">Enabled</th></tr>
          </thead>
          <tbody>
            {shown.map((s) => {
              const on = s.enabled !== false;
              return (
                <tr key={s.id} style={{ opacity: on ? 1 : 0.6, transition: "opacity .15s" }}>
                  <td style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink)", whiteSpace: "nowrap" }}>{s.name}</td>
                  <td><span className="sub" style={{ fontSize: 13 }}>{s.description}</span></td>
                  <td><Pill tone={RISK_TONE[s.risk] || "gray"}>{s.risk}</Pill></td>
                  <td className="right"><Toggle on={on} onClick={() => savePolicySet(s.id, !on)} /></td>
                </tr>
              );
            })}
            {shown.length === 0 && (
              <tr><td colSpan={4} style={{ textAlign: "center", color: "var(--ink-4)", padding: 32 }}>No guardrails match.</td></tr>
            )}
          </tbody>
        </table>
        <div className="tbl-foot">{sets.length} guardrails · {onCount === sets.length ? "all enabled" : `${onCount} of ${sets.length} enabled`}</div>
      </div>
    </div>
  );
}
window.GuardrailsTab = GuardrailsTab;

const RAIL = [
  { id: "home", name: "Home", icon: "home" },
  { id: "workloads", name: "AI Workloads", icon: "layers" },
  { id: "integrations", name: "Integrations", icon: "plug" },
  { id: "identities", name: "Identities", icon: "user" },
  { id: "logs", name: "Decision Logs", icon: "list" },
  { id: "isolation", name: "Access Isolation", icon: "shield" },
];

function LeftRail({ activeId, onNavigate }) {
  return (
    <aside style={{
      width: 64, background: "#fff", borderRight: "1px solid var(--border)",
      display: "flex", flexDirection: "column", alignItems: "center",
      paddingTop: 16, paddingBottom: 16, flex: "none", zIndex: 5,
    }}>
      {/* Reva shield logo */}
      <div style={{ width: 38, height: 38, borderRadius: 11, display: "grid", placeItems: "center",
        background: "linear-gradient(150deg, #2563EB, #7C3AED)", boxShadow: "0 4px 12px rgba(124,58,237,.28)" }}>
        <Icon name="shield" size={21} color="#fff" />
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 22 }}>
        {RAIL.map((r) => {
          const on = r.id === activeId;
          return (
            <button key={r.id} title={r.name} onClick={() => onNavigate(r.id)} style={{
              width: 44, height: 44, borderRadius: 11, border: 0, cursor: "pointer",
              background: on ? "var(--blue-tint)" : "transparent",
              color: on ? "var(--blue-700)" : "var(--ink-4)",
              display: "grid", placeItems: "center", transition: "all .15s",
            }}><Icon name={r.icon} size={20} /></button>
          );
        })}
      </div>
      <div style={{ marginTop: "auto", width: 36, height: 36, borderRadius: "50%",
        background: "#E8EDF5", color: "var(--ink-2)", display: "grid", placeItems: "center",
        fontSize: 13, fontWeight: 700 }}>PF</div>
    </aside>
  );
}

function TopBar({ crumbs }) {
  return (
    <div style={{
      height: 56, background: "#fff", borderBottom: "1px solid var(--border)",
      display: "flex", alignItems: "center", gap: 14, padding: "0 24px", flex: "none",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13.5 }}>
        {crumbs.map((c, i) => (
          <React.Fragment key={c}>
            {i > 0 && <Icon name="chevRight" size={14} color="var(--ink-4)" />}
            <span style={{ color: i === crumbs.length - 1 ? "var(--ink)" : "var(--ink-3)", fontWeight: i === crumbs.length - 1 ? 600 : 400 }}>{c}</span>
          </React.Fragment>
        ))}
      </div>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
        <div className="search" style={{ minWidth: 240, height: 34 }}>
          <Icon name="search" size={15} color="var(--ink-4)" />
          <input placeholder="Search Reva…" />
        </div>
        <button className="kebab"><Icon name="bell" size={19} /></button>
      </div>
    </div>
  );
}

function PageHeader() {
  return (
    <div style={{ padding: "22px 32px 0" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 16 }}>
        <div style={{ width: 46, height: 46, borderRadius: 12, background: "#fff", border: "1px solid var(--border)",
          display: "grid", placeItems: "center", flex: "none", boxShadow: "var(--shadow-card)" }}>
          <ClaudeBurst size={26} />
        </div>
        <div style={{ flex: 1 }}>
          <h1 style={{ margin: 0, fontSize: 23, fontWeight: 600, color: "var(--ink)", letterSpacing: "-0.01em" }}>AI Coding Agents</h1>
          <div style={{ display: "flex", gap: 8, marginTop: 9 }}>
            <Pill tone="blue">Owner: Patrick Fuller</Pill>
            <Pill tone="green" dot>Status: Online</Pill>
            <Pill tone="purple">Cedar-enforced</Pill>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button className="btn btn-ghost btn-sm">View schema</button>
          <button className="kebab" style={{ border: "1px solid var(--border-strong)" }}><Icon name="kebab" size={18} /></button>
        </div>
      </div>
    </div>
  );
}

function TabBar({ active, onChange }) {
  const ref = React.useRef(null);
  return (
    <div style={{ padding: "0 32px", marginTop: 18, background: "#fff", borderBottom: "1px solid var(--border)",
      position: "sticky", top: 0, zIndex: 4 }}>
      <div ref={ref} style={{ display: "flex", gap: 4, overflowX: "auto", scrollbarWidth: "none" }}>
        {TABS.map((t) => {
          const on = t === active;
          return (
            <button key={t} onClick={() => onChange(t)} style={{
              position: "relative", border: 0, background: "transparent",
              padding: "14px 14px 15px", fontSize: 13.5, fontWeight: 600, whiteSpace: "nowrap",
              color: on ? "var(--ink)" : "var(--ink-3)", transition: "color .15s",
            }}>
              {t}
              {on && <span style={{ position: "absolute", left: 8, right: 8, bottom: -1, height: 2.5,
                background: "var(--blue)", borderRadius: 2 }} />}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function Placeholder({ name }) {
  return (
    <div style={{ padding: 32 }}>
      <div className="card" style={{ height: 420, display: "grid", placeItems: "center", borderStyle: "dashed", background: "transparent" }}>
        <div style={{ textAlign: "center", color: "var(--ink-4)" }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "var(--ink-3)" }}>{name}</div>
          <div style={{ fontSize: 13, marginTop: 6 }}>Tab content not part of this design pass.</div>
        </div>
      </div>
    </div>
  );
}

function App() {
  const [nav, setNav] = React.useState("home");
  const [tab, setTab] = React.useState("Insights");
  const scrollRef = React.useRef(null);
  const isIntegrations = nav === "integrations";
  const isHome = nav === "home";
  const isIsolation = nav === "isolation";

  const navigate = (id) => {
    setNav(id);
    if (id === "logs") setTab("Decision Logs");
    else if (id === "identities" || id === "workloads") setTab("Insights");
  };

  const map = {
    "Insights": window.Insights,
    "Policies": window.PoliciesTab,
    "Guardrails": window.GuardrailsTab,
    "Decision Logs": window.DecisionLogs,
    "Developer Integration": window.DeveloperIntegration,
    "Settings": window.SettingsTab,
  };
  const Active = map[tab];
  const Integrations = window.IntegrationsPage;
  const HomeApp = window.HomeApp;
  React.useEffect(() => { if (scrollRef.current) scrollRef.current.scrollTop = 0; }, [tab, nav]);

  let crumbs;
  if (isHome) crumbs = ["Home"];
  else if (isIsolation) crumbs = ["Home", "Adaptive Access Isolation"];
  else if (isIntegrations) crumbs = ["Integrations"];
  else crumbs = ["AI Workloads", "AI Coding Agents"];

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
      <LeftRail activeId={nav} onNavigate={navigate} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <TopBar crumbs={crumbs} />
        <div ref={scrollRef} style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column" }}>
          {isHome ? (
            <HomeApp key="home" initialView="dashboard" />
          ) : isIsolation ? (
            <HomeApp key="iso" initialView="policies" />
          ) : isIntegrations ? (
            Integrations ? <Integrations onOpenWorkload={() => navigate("workloads")} /> : <Placeholder name="Integrations" />
          ) : (
            <>
              <PageHeader />
              <TabBar active={tab} onChange={setTab} />
              <div style={{ flex: 1 }}>
                {Active ? <Active /> : <Placeholder name={tab} />}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}


/* ===== injected: real policy data ===== */
const PO_DATA = [{"id": 1,"name": "Block Subagent File Edits","desc": "Spawned subagents cannot edit files.","principal": "ALL","resource": "ALL","action": "EditFile","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource\n) \n when { context has agent_type && context.agent_type == \"subagent\"};"},{"id": 2,"name": "Ticket Status Validation","desc": "Blocks edits when the linked Jira ticket exists but is not In Progress.","principal": "ALL","resource": "ALL","action": "EditFile","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_status && context.jira_status != \"\" && context.jira_status != \"In Progress\"};"},{"id": 3,"name": "Committer Identity Match","desc": "Blocks edits when the git committer email does not match the authenticated user.","principal": "ALL","resource": "ALL","action": "EditFile","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource\n) \n when { context has git_email && context.git_email != \"\" && context has oauth_email && context.oauth_email != \"\" && context.git_email != context.oauth_email};"},{"id": 4,"name": "Protected Branch Edit Guard","desc": "Blocks edits on protected branches without approver consent.","principal": "ALL","resource": "ALL","action": "EditFile","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource\n) \n when { context has github_branch_protected && context.github_branch_protected == true && context has approver_consent && context.approver_consent == false};"},{"id": 5,"name": "Subagent Command Execution","desc": "Allows spawned subagents to run Bash commands.","principal": "ALL","resource": "ALL","action": "RunBash","access": "Permit","code": "permit (\n    principal,\n    action == ClaudeCode::Action::\"RunBash\",\n    resource\n) \n when { context has agent_type && context.agent_type == \"subagent\"};"},{"id": 6,"name": "Forbid Destructive Bash Commands","desc": "Blocks shell commands classified as destructive.","principal": "ALL","resource": "ALL","action": "RunBash","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"RunBash\",\n    resource\n) \n when { context.command_risk == \"destructive\"};"},{"id": 7,"name": "Intent-Matched File Edit","desc": "Allows edits over SSH when an assigned Jira ticket is In Progress and trust is sufficient.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · File","action": "EditFile","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource is ClaudeCode::File\n) \n when { context has connection_type && context.connection_type == \"ssh\" && context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_assignee_email && context has oauth_email && context.jira_assignee_email == context.oauth_email && context has jira_status && context.jira_status == \"In Progress\" && context has trust_score && context.trust_score > 30};"},{"id": 8,"name": "Block Prompt Injection","desc": "Blocks prompt submission when injection content is detected.","principal": "ALL","resource": "ALL","action": "SubmitPrompt","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"SubmitPrompt\",\n    resource\n) \n when { context has is_injection && context.is_injection};"},{"id": 9,"name": "Auth-Service Scoped Edit","desc": "Allows edits to reva-auth-service over SSH with an assigned in-progress ticket and sufficient trust.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · File","action": "EditFile","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource is ClaudeCode::File\n) \n when { context has project_name && context.project_name == \"reva-auth-service\" && context has connection_type && context.connection_type == \"ssh\" && context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_assignee_email && context has oauth_email && context.jira_assignee_email == context.oauth_email && context has jira_status && context.jira_status == \"In Progress\" && context has trust_score && context.trust_score > 30};"},{"id": 10,"name": "Just-in-Time Access Validation","desc": "Allows commands when the SVID is active, the branch is protected, and trust exceeds 30.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · Command","action": "RunBash","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"RunBash\",\n    resource is ClaudeCode::Command\n) \n when { context has svid_active && context.svid_active == true && context has github_branch_protected && context.github_branch_protected == true && context has trust_score && context.trust_score > 30};"},{"id": 11,"name": "Approved Protected-Branch Edit","desc": "Allows edits on a protected branch with approver consent and trust above 40.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · File","action": "EditFile","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource is ClaudeCode::File\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_assignee_email && context has oauth_email && context.jira_assignee_email == context.oauth_email && context has jira_status && context.jira_status == \"In Progress\" && context has github_branch_protected && context.github_branch_protected == true && context has approver_consent && context.approver_consent == true && context has trust_score && context.trust_score > 40};"},{"id": 12,"name": "Read Files (Active Session)","desc": "Allows reading files while the session is active.","principal": "ClaudeCode · Developer","resource": "ALL","action": "ReadFile","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"ReadFile\",\n    resource\n) \n when { context has access_state && context.access_state == \"Active\"};"},{"id": 13,"name": "Sensitive File Operations – AppSec","desc": "Allows edits to secret or config files only with AppSec review and an active ticket.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · File","action": "EditFile","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource is ClaudeCode::File\n) \n when { context has file_zone && (context.file_zone == \"secrets\" || context.file_zone == \"config\") && context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_assignee_email && context has oauth_email && context.jira_assignee_email == context.oauth_email && context has jira_status && context.jira_status == \"In Progress\" && context has jira_appsec_review && context.jira_appsec_review == true && context has trust_score && context.trust_score > 30};"},{"id": 14,"name": "MCP Read (Active Session)","desc": "Allows MCP tool reads while the session is active.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · MCPTool","action": "MCPRead","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"MCPRead\",\n    resource is ClaudeCode::MCPTool\n) \n when { context has access_state && context.access_state == \"Active\"};"},{"id": 15,"name": "Restricted Project Write Operations","desc": "Blocks writes to reva-auth-service from non-SSH connections.","principal": "ALL","resource": "ClaudeCode · File","action": "WriteFile","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"WriteFile\",\n    resource is ClaudeCode::File\n) \n when { context has project_name && context.project_name == \"reva-auth-service\" && context has connection_type && context.connection_type != \"ssh\"};"},{"id": 16,"name": "Block Subagent File Writes","desc": "Spawned subagents cannot write files.","principal": "ALL","resource": "ALL","action": "WriteFile","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"WriteFile\",\n    resource\n) \n when { context has agent_type && context.agent_type == \"subagent\"};"},{"id": 17,"name": "Read Access — Unrestricted","desc": "Allows developers to read files.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · File","action": "ReadFile","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"ReadFile\",\n    resource is ClaudeCode::File\n);"},{"id": 18,"name": "Sensitive MCP Operations","desc": "Allows MCP writes with an active ticket, trust above 30, and low injection risk.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · MCPTool","action": "MCPWrite","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"MCPWrite\",\n    resource is ClaudeCode::MCPTool\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == true && context has trust_score && context.trust_score > 30 && context has injection_score && context.injection_score < 30};"},{"id": 19,"name": "Shell Commands – Intent Match","desc": "Allows commands on an unprotected branch with an assigned in-progress ticket and high trust.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · Command","action": "RunBash","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"RunBash\",\n    resource is ClaudeCode::Command\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_assignee_email && context has oauth_email && context.jira_assignee_email == context.oauth_email && context has jira_status && context.jira_status == \"In Progress\" && context has github_branch_protected && context.github_branch_protected == false && context has trust_score && context.trust_score > 40 && context has escalation_score && context.escalation_score < 30};"},{"id": 20,"name": "Agent Spawn Grant","desc": "Allows spawning subagents when trust exceeds 30.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · Session","action": "SpawnAgent","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"SpawnAgent\",\n    resource is ClaudeCode::Session\n) \n when { context has trust_score && context.trust_score > 30};"},{"id": 21,"name": "Intent-Matched File Write","desc": "Allows writes on an unprotected branch with an assigned in-progress ticket and sufficient trust.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · File","action": "WriteFile","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"WriteFile\",\n    resource is ClaudeCode::File\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_assignee_email && context has oauth_email && context.jira_assignee_email == context.oauth_email && context has jira_status && context.jira_status == \"In Progress\" && context has github_branch_protected && context.github_branch_protected == false && context has trust_score && context.trust_score > 30};"},{"id": 22,"name": "Auth-Service SSH-Only Edit","desc": "Blocks edits to reva-auth-service from non-SSH connections.","principal": "ALL","resource": "ClaudeCode · File","action": "EditFile","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource is ClaudeCode::File\n) \n when { context has project_name && context.project_name == \"reva-auth-service\" && context has connection_type && context.connection_type != \"ssh\"};"},{"id": 23,"name": "Require Linked Ticket","desc": "Blocks edits when no Jira ticket is linked.","principal": "ALL","resource": "ALL","action": "EditFile","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == false};"},{"id": 24,"name": "Detect Intent Drift","desc": "Blocks command execution when intent drift is detected.","principal": "ALL","resource": "ALL","action": "RunBash","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"RunBash\",\n    resource\n) \n when { context has is_intent_drift && context.is_intent_drift == true};"},{"id": 25,"name": "PM Safe Command Access","desc": "Allows product management to run safe commands while active.","principal": "ClaudeCode · Department","resource": "ClaudeCode · Command","action": "RunBash","access": "Permit","code": "permit (\n    principal in ClaudeCode::Department::\"productmanagement\",\n    action == ClaudeCode::Action::\"RunBash\",\n    resource is ClaudeCode::Command\n) \nwhen\n{\n  resource has command_risk &&\n  resource.command_risk == \"safe\" &&\n  context has access_state &&\n  context.access_state == \"Active\"\n};"},{"id": 26,"name": "Auth-Service SSH-Only Command","desc": "Blocks commands in reva-auth-service from non-SSH connections.","principal": "ALL","resource": "ClaudeCode · Command","action": "RunBash","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"RunBash\",\n    resource is ClaudeCode::Command\n) \n when { context has project_name && context.project_name == \"reva-auth-service\" && context has connection_type && context.connection_type != \"ssh\"};"},{"id": 27,"name": "Governed MCP Execute","desc": "Allows MCP execution with high trust, low injection risk, and approver consent.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · MCPTool","action": "MCPExecute","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"MCPExecute\",\n    resource is ClaudeCode::MCPTool\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == true && context has trust_score && context.trust_score > 40 && context has injection_score && context.injection_score < 20 && context has approver_consent && context.approver_consent == true};"},{"id": 28,"name": "Baseline Safety Floor – Injection","desc": "Blocks all actions when the injection score is 50 or higher.","principal": "ALL","resource": "ALL","action": "ALL","access": "Forbid","code": "forbid (\n    principal,\n    action,\n    resource\n) \n when { context has injection_score && context.injection_score >= 50};"},{"id": 29,"name": "Baseline Safety Floor – Trust","desc": "Blocks all actions when trust falls below 15.","principal": "ALL","resource": "ALL","action": "ALL","access": "Forbid","code": "forbid (\n    principal,\n    action,\n    resource\n) \n when { context has trust_score && context.trust_score < 15};"},{"id": 30,"name": "Block Jailbreak Prompts","desc": "Blocks prompt submission when jailbreak content is detected.","principal": "ALL","resource": "ALL","action": "SubmitPrompt","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"SubmitPrompt\",\n    resource\n) \n when { context has is_jailbreak && context.is_jailbreak};"},{"id": 31,"name": "Approved Protected-Branch Edit (Trust 30)","desc": "Allows edits on a protected branch with approver consent and trust above 30.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · File","action": "EditFile","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource is ClaudeCode::File\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_assignee_email && context has oauth_email && context.jira_assignee_email == context.oauth_email && context has jira_status && context.jira_status == \"In Progress\" && context has github_branch_protected && context.github_branch_protected == true && context has approver_consent && context.approver_consent == true && context has trust_score && context.trust_score > 30};"},{"id": 32,"name": "Unprotected-Branch Edit (Trust 40)","desc": "Allows edits on an unprotected branch with an assigned in-progress ticket and trust above 40.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · File","action": "EditFile","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource is ClaudeCode::File\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_assignee_email && context has oauth_email && context.jira_assignee_email == context.oauth_email && context has jira_status && context.jira_status == \"In Progress\" && context has github_branch_protected && context.github_branch_protected == false && context has trust_score && context.trust_score > 40};"},{"id": 33,"name": "MCP Write — Atlassian Rovo","desc": "Allows MCP writes to Atlassian Rovo with approver consent while active.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · MCPTool","action": "MCPWrite","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"MCPWrite\",\n    resource is ClaudeCode::MCPTool\n) \n when { context has server_name && context.server_name == \"claude_ai_Atlassian_Rovo\" && context has approver_consent && context.approver_consent == true && context has access_state && context.access_state == \"Active\"};"},{"id": 34,"name": "Assignee Identity Match","desc": "Blocks edits when the Jira assignee email does not match the authenticated user.","principal": "ALL","resource": "ALL","action": "EditFile","access": "Forbid","code": "forbid (\n    principal,\n    action == ClaudeCode::Action::\"EditFile\",\n    resource\n) \n when { context has jira_ticket_exists && context.jira_ticket_exists == true && context has jira_assignee_email && context.jira_assignee_email != \"\" && context has oauth_email && context.oauth_email != \"\" && context.jira_assignee_email != context.oauth_email};"},{"id": 35,"name": "PM MCP Write — Atlassian Rovo","desc": "Allows product managers to write to Atlassian Rovo with approver consent while active.","principal": "ClaudeCode · Department","resource": "ALL","action": "MCPWrite","access": "Permit","code": "permit (\n    principal in ClaudeCode::Department::\"productmanagement\",\n    action == ClaudeCode::Action::\"MCPWrite\",\n    resource in ClaudeCode::MCPServer::\"claude_ai_Atlassian_Rovo\"\n) \nwhen\n{\n  principal has user_role &&\n  principal.user_role == \"product_manager\" &&\n  context.approver_consent == true &&\n  context.access_state == \"Active\"\n};"},{"id": 36,"name": "Run Safe Bash Commands","desc": "Allows developers to run safe commands while the session is active.","principal": "ClaudeCode · Developer","resource": "ClaudeCode · Command","action": "RunBash","access": "Permit","code": "permit (\n    principal is ClaudeCode::Developer,\n    action == ClaudeCode::Action::\"RunBash\",\n    resource is ClaudeCode::Command\n) \n when { context has command_risk && context.command_risk == \"safe\" && context has access_state && context.access_state == \"Active\"};"}];
/* ============================================================= */
/* ===============  PIVOT: Policies / DecisionLogs / Intent  ==== */
/* ============================================================= */
const { useState: poUseState, useMemo: dlUseMemo } = React;

/* ---------- Cedar syntax highlight ---------- */
function poHighlight(code) {
  const re = /(\/\/[^\n]*)|("(?:[^"\\]|\\.)*")|\b(permit|forbid|when|unless|principal|action|resource|is|has|in|like|true|false|context)\b|\b(\d+)\b|(==|!=|>=|<=|&&|\|\||>|<)/g;
  return code.split("\n").map((line, li) => {
    const parts = []; let last = 0, m; re.lastIndex = 0;
    while ((m = re.exec(line))) {
      if (m.index > last) parts.push({ c: "var(--ink-2)", v: line.slice(last, m.index) });
      if (m[1]) parts.push({ c: "var(--ink-4)", v: m[1] });
      else if (m[2]) parts.push({ c: "#15803D", v: m[2] });
      else if (m[3]) parts.push({ c: "var(--blue)", v: m[3], b: 1 });
      else if (m[4]) parts.push({ c: "var(--purple)", v: m[4] });
      else if (m[5]) parts.push({ c: "var(--teal)", v: m[5] });
      last = re.lastIndex;
    }
    if (last < line.length) parts.push({ c: "var(--ink-2)", v: line.slice(last) });
    return (
      <div key={li} style={{ display: "flex", minHeight: 22 }}>
        <span style={{ width: 40, flex: "none", textAlign: "right", paddingRight: 14, color: "var(--ink-4)", userSelect: "none" }}>{li + 1}</span>
        <span style={{ flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
          {parts.map((p, i) => <span key={i} style={{ color: p.c, fontWeight: p.b ? 600 : 400 }}>{p.v}</span>)}
        </span>
      </div>
    );
  });
}

const PO_ACTION_TONE = { ReadFile: "#3258d6", RunBash: "#7c3aed", EditFile: "#0d9488", WriteFile: "#b45309", MCPWrite: "#c026d3" };
function PoActionChip({ action }) {
  return <span className="mono" style={{ display: "inline-flex", fontSize: 11, fontWeight: 600, padding: "3px 8px", borderRadius: 6, background: "var(--surface-3)", color: PO_ACTION_TONE[action] || "var(--ink-3)" }}>{action}</span>;
}
function PoPrincipalCell({ p }) {
  return (
    <div>
      <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--ink-2)", lineHeight: 1.6 }}>
        <span style={{ whiteSpace: "nowrap" }}>{p.principal}</span>
        <span style={{ color: "var(--ink-4)", margin: "0 7px" }}>→</span>
        <span style={{ whiteSpace: "nowrap" }}>{p.resource}</span>
      </div>
      <div style={{ marginTop: 7 }}><PoActionChip action={p.action} /></div>
    </div>
  );
}
const PO_UPDATED = "3 Jun 2026, 15:11";
function PoTBtn({ name, active, onClick, title }) {
  return <button className="kebab" title={title} onClick={onClick} style={{ width: 34, height: 34, color: active ? "var(--red)" : "var(--ink-4)" }}><Icon name={name} size={18} /></button>;
}
function PoMiniToast({ msg }) {
  if (!msg) return null;
  return <div className="toast-host"><div className="toast"><Icon name="checkCircle" size={16} color="#5eead4" />{msg}</div></div>;
}
const PO_BLANK = "permit (\n    principal,\n    action,\n    resource\n)\nwhen {\n    \n};";

function PoEditor({ policy, onBack, onDelete }) {
  const isNew = !policy;
  const [draft, setDraft] = poUseState(isNew ? PO_BLANK : policy.code);
  return (
    <div className="card" style={{ overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 14, padding: "18px 22px", borderBottom: "1px solid var(--border)", background: "var(--surface-2)" }}>
        <button className="kebab" onClick={onBack} style={{ marginTop: 2 }}><Icon name="arrowLeft" size={18} /></button>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 16, fontWeight: 600, color: "var(--ink)" }}>{isNew ? "New policy" : policy.name}</span>
            <Icon name="sparkles" size={16} color="var(--purple)" />
          </div>
          <div className="help" style={{ marginTop: 3 }}>{isNew ? "Write a Cedar policy below, then publish." : policy.desc}</div>
        </div>
        {!isNew && <button className="kebab" onClick={onDelete}><Icon name="trash" size={17} color="var(--ink-4)" /></button>}
      </div>
      <div style={{ padding: 22 }}>
        {isNew ? (
          <div style={{ display: "flex", border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden", background: "#fff", fontFamily: "var(--mono)", fontSize: 12.5, lineHeight: "22px" }}>
            <div style={{ width: 40, flex: "none", background: "var(--surface-2)", borderRight: "1px solid var(--border)", padding: "14px 0", textAlign: "right" }}>
              {draft.split("\n").map((_, i) => <div key={i} style={{ paddingRight: 12, color: "var(--ink-4)" }}>{i + 1}</div>)}
            </div>
            <textarea value={draft} onChange={(e) => setDraft(e.target.value)} spellCheck={false}
              style={{ flex: 1, border: 0, outline: 0, resize: "vertical", minHeight: 240, padding: "14px 16px", fontFamily: "var(--mono)", fontSize: 12.5, lineHeight: "22px", color: "var(--ink-2)", background: "#fff" }} />
          </div>
        ) : (
          <div style={{ border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden", background: "#fff" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 14px", borderBottom: "1px solid var(--border)", background: "var(--surface-2)" }}>
              <Icon name="fileCode" size={14} color="var(--ink-4)" />
              <span className="mono" style={{ fontSize: 11.5, color: "var(--ink-3)" }}>policy.cedar</span>
              <span className="pill pill-gray" style={{ marginLeft: "auto", height: 20, fontSize: 10.5 }}>Cedar</span>
            </div>
            <div style={{ padding: "14px 16px", fontFamily: "var(--mono)", fontSize: 12.5, lineHeight: "22px" }}>{poHighlight(draft)}</div>
          </div>
        )}
      </div>
    </div>
  );
}

function PoPager({ page, pages, total, onPage }) {
  if (pages <= 1) return <div className="tbl-foot">{total} policies</div>;
  return (
    <div className="tbl-foot" style={{ display: "flex", alignItems: "center" }}>
      <span>{total} policies</span>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
        <button className="kebab" onClick={() => onPage(page - 1)} disabled={page === 0} style={{ width: 30, height: 30, opacity: page === 0 ? 0.4 : 1 }}><Icon name="arrowLeft" size={15} /></button>
        <span className="help">Page {page + 1} of {pages}</span>
        <button className="kebab" onClick={() => onPage(page + 1)} disabled={page >= pages - 1} style={{ width: 30, height: 30, opacity: page >= pages - 1 ? 0.4 : 1 }}><Icon name="arrowRight" size={15} /></button>
      </div>
    </div>
  );
}

function PoTable({ rows, startIndex, numbered, editable, onRowClick, onDelete }) {
  return (
    <table className="tbl">
      <thead>
        <tr>
          {numbered && <th style={{ width: 44 }}></th>}
          <th style={{ width: 220 }}>Name</th>
          <th>Description</th>
          <th style={{ width: 300 }}>Principal → Resource [Action]</th>
          <th style={{ width: 100 }}>Access</th>
          <th style={{ width: 140 }}>Last Updated</th>
          {editable && <th style={{ width: 48 }}></th>}
        </tr>
      </thead>
      <tbody>
        {rows.map((p, i) => (
          <tr key={p.id} className={onRowClick ? "clickable" : ""} onClick={onRowClick ? () => onRowClick(p) : undefined}>
            {numbered && <td><span style={{ display: "grid", placeItems: "center", width: 26, height: 26, borderRadius: "50%", background: "var(--surface-3)", color: "var(--ink-3)", fontSize: 11.5, fontWeight: 700 }}>{(startIndex || 0) + i + 1}</span></td>}
            <td><span style={{ fontWeight: 600, color: "var(--ink)", fontSize: 13.5 }}>{p.name}</span></td>
            <td className="sub" style={{ fontSize: 12.5, maxWidth: 280 }}><span style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{p.desc}</span></td>
            <td><PoPrincipalCell p={p} /></td>
            <td><Pill tone={p.access === "Permit" ? "green" : "red"}>{p.access}</Pill></td>
            <td className="sub mono" style={{ fontSize: 12 }}>{PO_UPDATED}</td>
            {editable && <td className="right"><button className="kebab" onClick={(e) => { e.stopPropagation(); onDelete(p.id); }}><Icon name="trash" size={16} color="var(--ink-4)" /></button></td>}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function PoEditModal({ selected, onSelect, onClose, onCreateDraft, onEdit }) {
  return (
    <div className="cf-scrim" onClick={onClose}>
      <div className="cf-box" style={{ width: 460 }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <h3 style={{ margin: 0, fontSize: 17, fontWeight: 600, color: "var(--ink)" }}>Edit Policy</h3>
          <Icon name="info" size={15} color="var(--ink-4)" />
          <button className="kebab" style={{ marginLeft: "auto", border: "1px solid var(--border-strong)" }} onClick={onClose}><Icon name="x" size={17} /></button>
        </div>
        <p className="help" style={{ margin: "0 0 16px" }}>Select to edit an existing draft or create a new one.</p>
        <button onClick={() => onSelect("draft1")} style={{ width: "100%", display: "flex", alignItems: "flex-start", gap: 11, padding: "14px 16px", textAlign: "left", borderRadius: 12, cursor: "pointer", background: selected === "draft1" ? "var(--blue-tint)" : "#fff", border: "1.5px solid " + (selected === "draft1" ? "var(--blue)" : "var(--border-strong)") }}>
          <span style={{ width: 18, height: 18, borderRadius: "50%", marginTop: 1, flex: "none", display: "grid", placeItems: "center", border: "2px solid " + (selected === "draft1" ? "var(--blue)" : "var(--border-strong)") }}>
            {selected === "draft1" && <span style={{ width: 9, height: 9, borderRadius: "50%", background: "var(--blue)" }} />}
          </span>
          <span>
            <span style={{ display: "block", fontSize: 13.5, fontWeight: 700, color: "var(--ink)" }}>Draft 1</span>
            <span className="help" style={{ fontSize: 12 }}>Created by Patrick Fuller on 28 May, 26 · 21:02</span>
          </span>
        </button>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 20 }}>
          <button className="btn btn-ghost" onClick={onCreateDraft}>Create New Draft</button>
          <button className="btn btn-primary" disabled={!selected} style={!selected ? { opacity: .5, cursor: "not-allowed" } : null} onClick={onEdit}>Edit</button>
        </div>
      </div>
    </div>
  );
}

const PO_PER = 10;
function PoliciesTab() {
  const [mode, setMode] = poUseState("view");
  const [showModal, setShowModal] = poUseState(false);
  const [selectedDraft, setSelectedDraft] = poUseState(null);
  const [editingPolicy, setEditingPolicy] = poUseState(undefined);
  const [policies, setPolicies] = poUseState(PO_DATA);
  const [page, setPage] = poUseState(0);
  const [toast, setToast] = poUseState(null);
  const fireToast = (m) => { setToast(m); setTimeout(() => setToast(null), 2600); };

  const pages = Math.max(1, Math.ceil(policies.length / PO_PER));
  const pg = Math.min(page, pages - 1);
  const rows = policies.slice(pg * PO_PER, pg * PO_PER + PO_PER);
  const goEditor = (p) => { setEditingPolicy(p); setMode("editor"); };
  const publish = () => { setMode("view"); setEditingPolicy(undefined); fireToast("Draft published — policies are now live"); };
  const removePolicy = (id) => setPolicies((ps) => ps.filter((p) => p.id !== id));

  if (mode === "editor") {
    return (
      <div style={{ padding: 28 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 16 }}>
          <span className="pill pill-amber">Draft 1 · unpublished</span>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 4 }}>
            <PoTBtn name="filter" title="Filter" /><PoTBtn name="flag" active title="Flags" /><PoTBtn name="download" title="Export" /><PoTBtn name="columns" title="Columns" /><PoTBtn name="sitemap" title="Graph view" />
            <button className="btn btn-primary btn-sm" style={{ marginLeft: 6 }} onClick={publish}>Publish</button>
            <button className="kebab" style={{ border: "1px solid var(--border-strong)" }} onClick={() => setMode("edit")}><Icon name="x" size={18} /></button>
          </div>
        </div>
        <PoEditor policy={editingPolicy} onBack={() => setMode("edit")}
          onDelete={() => { if (editingPolicy) removePolicy(editingPolicy.id); setMode("edit"); fireToast("Policy deleted from draft"); }} />
        <PoMiniToast msg={toast} />
      </div>
    );
  }

  const editing = mode === "edit";
  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16 }}>
        {editing ? <span className="pill pill-amber">Editing · Draft 1</span> : <span className="help">{policies.length} policies · published</span>}
        {editing && <span className="help" style={{ marginLeft: 4 }}>click a row to open the editor</span>}
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 4 }}>
          <PoTBtn name="filter" title="Filter" /><PoTBtn name="download" title="Export" /><PoTBtn name="flag" active={editing} title="Flags" /><PoTBtn name="columns" title="Columns" /><PoTBtn name="sitemap" title="Graph view" />
          {editing ? (
            <>
              <button className="btn btn-ghost btn-sm" style={{ marginLeft: 6, color: "var(--blue)", borderColor: "rgba(37,99,235,.4)" }} onClick={() => goEditor(null)}><Icon name="plus" size={15} /> Policy</button>
              <button className="btn btn-primary btn-sm" onClick={publish}>Publish</button>
              <button className="kebab" style={{ border: "1px solid var(--border-strong)" }} onClick={() => setMode("view")}><Icon name="x" size={18} /></button>
            </>
          ) : (
            <button className="btn btn-primary btn-sm" style={{ marginLeft: 6 }} onClick={() => { setShowModal(true); setSelectedDraft("draft1"); }}>Edit</button>
          )}
        </div>
      </div>
      <div className="card" style={{ overflow: "hidden" }}>
        <PoTable rows={rows} startIndex={pg * PO_PER} numbered editable={editing} onRowClick={editing ? goEditor : null} onDelete={removePolicy} />
        <PoPager page={pg} pages={pages} total={policies.length} onPage={setPage} />
      </div>
      {showModal && (
        <PoEditModal selected={selectedDraft} onSelect={setSelectedDraft}
          onClose={() => setShowModal(false)}
          onCreateDraft={() => { setShowModal(false); setMode("edit"); fireToast("New draft created"); }}
          onEdit={() => { setShowModal(false); setMode("edit"); }} />
      )}
      <PoMiniToast msg={toast} />
    </div>
  );
}
window.PoliciesTab = PoliciesTab;

/* ===================== DECISION LOGS (real data) ===================== */
function dlIsReal(email) {
  if (!email) return false;
  const e = String(email).toLowerCase().trim();
  if (!e || e === "unknown" || e === "developer" || e === "$user") return false;
  if (e.includes("$") || e.includes("hook") || e === "*") return false;
  return true;
}
const DL_DEC_TONE = { Deny: "red", Allow: "green" };

const DL_KIND = { Command: "Command", File: "File", Prompt: "Prompt", Session: "Session", MCPTool: "MCP Tool" };
function dlMap(d, i) {
  const ctx = d.cedar_context || {};
  const osUser = ctx.os_user || ((d.user_email || "").includes("@") ? d.user_email.split("@")[0] : (d.user_email || d.oauth_email || ""));
  const isAgent = (ctx.agent_type || d.agent_type) === "subagent";
  const agentId = ctx.agent_id || d.agent_id || "";
  const principal = isAgent ? (osUser + (agentId ? ":" + agentId : "")) : osUser;
  const decision = d.effect === "Permit" ? "Allow" : "Deny";
  const tnum = d.timestamp ? new Date(d.timestamp) : null;
  const action = d.cedar_action || d.tool || "—";
  const rtype = d.cedar_resource_type || "";
  const resource = String(d.cedar_resource || ctx.command || ctx.file_path || d.reason || d.prompt || "—");
  const sc = d.scores || {};
  const drift = ctx.intent_drift_score != null ? ctx.intent_drift_score : (sc.intent_drift_score != null ? sc.intent_drift_score : (sc.intent_mismatch_score || 0));
  const hasIntent = !!(ctx.declared_scope || ctx.initial_scope || ctx.is_intent_drift || drift > 0);
  return {
    id: i, time: tnum ? tnum.toLocaleString("en-GB", { day: "2-digit", month: "short", year: "2-digit", hour: "2-digit", minute: "2-digit" }).replace(",", " |") : "—",
    principal: principal || "—", principalType: isAgent ? "Agent" : "Developer",
    action,
    resource, resourceKind: DL_KIND[rtype] || rtype || "—",
    decision,
    decisionId: d.cedar_decision_id || d.decision_id || "—",
    traceId: ctx.session_trace_id || d.trace_id || ("trc-" + (String(d.session_id || "").replace(/[^a-z0-9]/gi, "").slice(0, 24) || "—")),
    spanId: d.span_id || "—", parentSpanId: ctx.parent_session_id || d.parent_span_id || "—",
    policyStoreId: d.policy_store_id || "—",
    policyName: d.cedar_policy_name || "",
    hasCedar: !!d.cedar_action,
    drift, hasIntent, ctx, _d: d,
  };
}

function DlField({ label, children, mono }) {
  return (
    <div>
      <div style={{ fontSize: 12, color: "var(--ink-3)", marginBottom: 5 }}>{label}</div>
      <div className={mono ? "mono" : ""} style={{ fontSize: 13.5, color: "var(--ink)", fontWeight: 500, wordBreak: "break-all" }}>{children}</div>
    </div>
  );
}
function DlKvRow({ k, v, last }) {
  let color = "var(--ink-2)";
  if (typeof v === "number") color = "var(--blue)";
  else if (typeof v === "boolean") color = "var(--teal)";
  return (
    <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: 16, padding: "11px 0", borderBottom: last ? 0 : "1px solid var(--border)", alignItems: "center" }}>
      <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--blue)" }}>{k}</span>
      <span className="mono" style={{ fontSize: 12.5, color, wordBreak: "break-all" }}>{v === "" || v == null ? "—" : (typeof v === "object" ? JSON.stringify(v) : String(v))}</span>
    </div>
  );
}

function DlDetail({ log, onClose, onTraceFilter, onIntent }) {
  const d = log._d || {};
  const body = {
    decision_id: log.decisionId, policy_store_id: log.policyStoreId,
    subject: log.principalType + "::" + log.principal, action: log.action,
    resource: log.resourceKind + "::" + (log.resource.length > 30 ? log.resource.slice(0, 30) + "…" : log.resource),
    decision: log.decision.toLowerCase(), reason: d.reason || "", latency_ms: d.latency_ms != null ? d.latency_ms : 0, source: "pdp",
    trace_id: log.traceId, parent_span_id: log.parentSpanId,
  };
  const ctx = log.ctx || {};
  const evaluated = [{
    name: log.policyName || (log.decision === "Deny" ? "Cedar forbid policy matched" : "Cedar permit policy matched"),
    d: log.decision,
  }];
  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "20px 24px" }}>
      <div style={{ position: "relative" }}>
        <button className="kebab" onClick={onClose} style={{ position: "absolute", top: 0, right: 0, width: 32, height: 32, borderRadius: "50%", background: "var(--blue-tint)", color: "var(--blue)" }}><Icon name="x" size={17} /></button>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "18px 40px", paddingRight: 40 }}>
          <DlField label="Source"><Pill tone="blue">PDP</Pill></DlField>
          <DlField label="Decision"><Pill tone={DL_DEC_TONE[log.decision]}>{log.decision}</Pill></DlField>
          <DlField label="Decision ID" mono>{log.decisionId}</DlField>
          <DlField label="Timestamp">{log.time}</DlField>
          <DlField label="Principal" mono>{log.principal}</DlField>
          <DlField label="Action">{log.action}</DlField>
          <DlField label="Resource" mono>{log.resource.length > 40 ? log.resource.slice(0, 40) + "…" : log.resource}</DlField>
          <DlField label="Trace ID">
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="mono" style={{ fontSize: 12.5 }}>{log.traceId}</span>
              <button className="kebab" title="Filter with TraceID" onClick={onTraceFilter} style={{ width: 26, height: 26 }}><Icon name="filter" size={14} color="var(--blue)" /></button>
            </div>
            {log.hasIntent && (
              <button onClick={onIntent} style={{ marginTop: 10, display: "inline-flex", alignItems: "center", gap: 7, height: 32, padding: "0 12px", borderRadius: 8, border: "1px solid rgba(234,88,12,.3)", background: "var(--coral-tint)", color: "var(--coral-ink)", fontSize: 12.5, fontWeight: 600, cursor: "pointer", whiteSpace: "nowrap" }}>
                <Icon name="flame" size={14} color="var(--coral)" /> View Intent Profile <Icon name="arrowRight" size={13} />
              </button>
            )}
          </DlField>
        </div>
      </div>

      <div style={{ marginTop: 26 }}>
        <div className="section-title" style={{ fontSize: 16, marginBottom: 12 }}>Evaluated Policies</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {evaluated.map((p, i) => (
            <div key={i} className="card" style={{ padding: "14px 18px", display: "flex", alignItems: "center", gap: 12 }}>
              <span style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink)" }}>{p.name}</span>
              <div style={{ marginLeft: "auto" }}><Pill tone={DL_DEC_TONE[p.d]}>{p.d}</Pill></div>
            </div>
          ))}
        </div>
      </div>

      <div className="card" style={{ marginTop: 22, padding: 18, borderLeft: "3px solid var(--blue)" }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--ink)", marginBottom: 14 }}>Decision Context</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "14px 24px" }}>
          <DlField label="Trace ID" mono>{log.traceId}</DlField>
          <DlField label="Span ID" mono>{log.spanId}</DlField>
          <DlField label="Parent Span ID" mono>{log.parentSpanId}</DlField>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16, padding: 18 }}>
        <div style={{ display: "flex", alignItems: "center", marginBottom: 6 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: "var(--ink)" }}>Body</span>
          <span className="pill pill-blue" style={{ marginLeft: "auto", height: 22 }}>{Object.keys(body).length}</span>
        </div>
        <div>{Object.entries(body).map(([k, v], i, a) => <DlKvRow key={k} k={k} v={v} last={i === a.length - 1} />)}</div>
      </div>

      <div className="card" style={{ marginTop: 16, padding: 18 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 12 }}>
          <span style={{ fontSize: 13.5, fontWeight: 600, color: "var(--blue)" }}>context</span>
          <span className="pill pill-amber" style={{ height: 20, fontSize: 10.5 }}>JSON</span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
          {Object.entries(ctx).map(([k, v]) => {
            let color = "var(--ink-2)";
            if (typeof v === "number") color = "var(--blue)";
            else if (typeof v === "boolean") color = "var(--teal)";
            return (
              <div key={k} style={{ display: "flex", gap: 8, fontSize: 12.5 }}>
                <span style={{ fontWeight: 600, color: "var(--blue)", whiteSpace: "nowrap" }}>{k}:</span>
                <span className="mono" style={{ color, wordBreak: "break-all" }}>{v == null ? "—" : (typeof v === "object" ? JSON.stringify(v) : String(v))}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function DlRailCard({ log, active, onClick }) {
  const ok = log.decision === "Allow";
  return (
    <button onClick={onClick} style={{ width: "100%", textAlign: "left", padding: "12px 14px", borderRadius: 12, cursor: "pointer", marginBottom: 10, background: active ? "var(--blue-tint)" : "#fff", border: "1.5px solid " + (active ? "var(--blue)" : "var(--border)") }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: "var(--ink-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 84 }}>{log.principal.split(":")[0]}</span>
        <Icon name="arrowRight" size={12} color="var(--ink-4)" />
        <span className="mono" style={{ fontSize: 12, color: "var(--ink-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{log.resource.length > 16 ? log.resource.slice(0, 16) + "…" : log.resource}</span>
        <span className="pill pill-gray" style={{ height: 22, fontSize: 11, fontFamily: "var(--mono)" }}>{log.action}</span>
        <span style={{ width: 18, height: 18, borderRadius: "50%", flex: "none", display: "grid", placeItems: "center", background: ok ? "var(--green)" : "var(--red)" }}><Icon name={ok ? "check" : "x"} size={11} color="#fff" /></span>
      </div>
      <div className="help" style={{ fontSize: 11.5, marginTop: 6 }}>{log.time}</div>
    </button>
  );
}

function DlReplaceModal({ onCancel, onConfirm }) {
  return (
    <div className="cf-scrim" onClick={onCancel}>
      <div className="cf-box" style={{ width: 420 }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", alignItems: "center", marginBottom: 8 }}>
          <h3 style={{ margin: 0, fontSize: 17, fontWeight: 600, color: "var(--ink)" }}>Replace filters?</h3>
          <button className="kebab" style={{ marginLeft: "auto", border: "1px solid var(--border-strong)" }} onClick={onCancel}><Icon name="x" size={17} /></button>
        </div>
        <p className="sub" style={{ margin: "0 0 20px", fontSize: 13.5 }}>This will clear all current filters and apply the Trace ID filter instead.</p>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
          <button className="btn btn-ghost" onClick={onCancel}>Cancel</button>
          <button className="btn btn-primary" onClick={onConfirm}>Replace Filters</button>
        </div>
      </div>
    </div>
  );
}

function DecisionLogsV2() {
  const reva = useReva();
  const raw = (reva.raw && reva.raw.decisions) || [];
  const LOGS = dlUseMemo(() => raw
    .filter((d) => !!d.cedar_action || d.effect === "Deny" || d.effect === "HITL")
    .filter((d) => dlIsReal((d.cedar_context && d.cedar_context.os_user) || d.user_email || d.oauth_email))
    .map((d, i) => dlMap(d, i)), [raw]);
  const [openId, setOpenId] = React.useState(null);
  const [traceFilter, setTraceFilter] = React.useState(null);
  const [confirmTrace, setConfirmTrace] = React.useState(null);
  const [intentLog, setIntentLog] = React.useState(null);
  const [q, setQ] = React.useState("");

  const visible = dlUseMemo(() => {
    let v = LOGS;
    if (traceFilter) v = v.filter((l) => l.traceId === traceFilter);
    if (q) { const s = q.toLowerCase(); v = v.filter((l) => (l.principal + l.action + l.resource + l.traceId).toLowerCase().includes(s)); }
    return v;
  }, [LOGS, traceFilter, q]);
  const openLog = openId != null ? LOGS.find((l) => l.id === openId) : null;

  if (intentLog) return <window.IntentProfile log={intentLog} onBack={() => setIntentLog(null)} />;

  return (
    <div style={{ padding: "24px 28px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 18 }}>
        <div className="search" style={{ flex: 1, minWidth: 0, height: 44, borderRadius: 999 }}>
          {traceFilter && (
            <span className="pill pill-blue" style={{ height: 28, flex: "none" }}>
              Trace ID is {traceFilter.slice(0, 22)}…
              <button onClick={() => setTraceFilter(null)} style={{ border: 0, background: "transparent", padding: 0, marginLeft: 4, display: "grid", placeItems: "center", color: "var(--blue-700)", cursor: "pointer" }}><Icon name="x" size={13} /></button>
            </span>
          )}
          <input placeholder="Filter by principal, action, resource…" value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1 }} />
          <Icon name="search" size={17} color="var(--ink-4)" />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <button className="kebab" title="Export"><Icon name="download" size={18} /></button>
          <button className="kebab" title="Date range"><Icon name="calendar" size={18} /></button>
          <button className="kebab" title="Refresh"><Icon name="rotate" size={18} /></button>
        </div>
      </div>

      {openLog ? (
        <div style={{ display: "flex", gap: 16, minHeight: 0 }}>
          <div style={{ width: 360, flex: "none", maxHeight: "calc(100vh - 240px)", overflowY: "auto", paddingRight: 4 }}>
            {visible.map((l) => <DlRailCard key={l.id} log={l} active={l.id === openId} onClick={() => setOpenId(l.id)} />)}
          </div>
          <div className="card" style={{ flex: 1, minWidth: 0, display: "flex", overflow: "hidden", maxHeight: "calc(100vh - 240px)" }}>
            <DlDetail log={openLog} onClose={() => setOpenId(null)}
              onTraceFilter={() => setConfirmTrace(openLog.traceId)}
              onIntent={() => setIntentLog(openLog)} />
          </div>
        </div>
      ) : (
        <div className="card" style={{ overflow: "hidden" }}>
          <table className="tbl" style={{ tableLayout: "fixed", width: "100%" }}>
            <thead>
              <tr>
                <th style={{ width: 170 }}>Timestamp</th>
                <th style={{ width: 260 }}>Principal</th>
                <th style={{ width: 150 }}>Action</th>
                <th>Resource</th>
                <th style={{ width: 110, textAlign: "right" }}>Decision</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((l) => (
                <tr key={l.id} className="clickable" onClick={() => setOpenId(l.id)}>
                  <td className="sub" style={{ fontSize: 12.5 }}>{l.time}</td>
                  <td>
                    <div className="mono" style={{ fontSize: 12.5, color: "var(--ink)", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{l.principal}</div>
                    <div className="help" style={{ fontSize: 11.5, marginTop: 2 }}>{l.principalType}</div>
                  </td>
                  <td><span className="pill pill-gray" style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{l.action}</span></td>
                  <td>
                    <div className="mono" style={{ fontSize: 12.5, color: "var(--ink-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{l.resource}</div>
                    <div className="help" style={{ fontSize: 11.5, marginTop: 2 }}>{l.resourceKind}</div>
                  </td>
                  <td style={{ textAlign: "right" }}><Pill tone={DL_DEC_TONE[l.decision]}>{l.decision}</Pill></td>
                </tr>
              ))}
              {visible.length === 0 && <tr><td colSpan={5} style={{ textAlign: "center", color: "var(--ink-4)", padding: 36 }}>No decisions yet.</td></tr>}
            </tbody>
          </table>
          {visible.length > 0 && <div className="tbl-foot">Showing {visible.length} decision{visible.length === 1 ? "" : "s"}</div>}
        </div>
      )}

      {confirmTrace && <DlReplaceModal onCancel={() => setConfirmTrace(null)} onConfirm={() => { setTraceFilter(confirmTrace); setConfirmTrace(null); setOpenId(null); }} />}
    </div>
  );
}
window.DecisionLogs = DecisionLogsV2;

/* ===================== INTENT PROFILE (coding scenario) ===================== */
const IP_SEV_TONE = { Low: "green", Medium: "amber", High: "coral", Critical: "red" };
function IpSevBadge({ level }) {
  return <span className={"pill pill-" + (IP_SEV_TONE[level] || "gray")} style={{ gap: 5 }}><Icon name="bars" size={11} /> {level}</span>;
}
function ipSev(v) { return v >= 0.85 ? "Critical" : v >= 0.6 ? "High" : v >= 0.4 ? "Medium" : "Low"; }
function ipClamp(v) { return Math.max(0, Math.min(1, v)); }

const IP_MUT_CMD = /\b(rm|rmdir|mv|cp|mkdir|touch|truncate|dd|tee|chmod|chown|ln|shred)\b|\bsed\s+-i\b|\bgit\s+(commit|push|merge|rebase|reset|stash|tag|cherry-pick)\b|\b(npm|yarn|pnpm|pip|pip3|gem|cargo|go|apt|brew)\s+(install|add|remove|uninstall)\b/i;
const IP_READ_CMD = /\b(cat|head|tail|less|more|nl|strings|cut|sed|awk|od|xxd|grep|egrep|fgrep|rg)\b|\bgit\s+(show|diff|log|blame)\b/i;
const IP_ASKED_MUTATE = /\b(edit|update|modify|change|remove|delete|drop|write|creat|add|fix|refactor|renam|install|deploy|push|commit|merge|rewrite|patch|append)/i;
const IP_STOP = new Set(["the","all","files","file","review","summarize","summary","directory","directories","folder","folders","and","for","a","an","to","me","list","please","this","that","its","their","code","project","contents","what","how","each","relate","overall","key","tech","stack","note","obvious","issues","concerns","concise","complete","provide","users"]);
function ipTokensOf(text) { return (String(text || "").toLowerCase().match(/[a-z0-9._-]+/g) || []).map((t) => t.replace(/^[._-]+|[._-]+$/g, "")).filter((t) => t.length > 2 && !IP_STOP.has(t)); }
function ipPathTail(p) {
  // Use only the last two segments of each path, mirroring the server — the
  // home/project prefix (…/saisrungaram/claude-demo-project/…) is shared by every
  // file and must not count as scope overlap.
  return String(p || "").split(/\s+/).filter((a) => a.includes("/")).map((seg) => {
    const s = seg.replace(/^[a-z]+:\/\//i, "").split("/").filter(Boolean);
    return s.slice(-2).join(" ");
  }).join(" ").toLowerCase();
}
function ipOutOfScope(pathOrCmd, declared) {
  const ask = ipTokensOf(declared); if (!ask.length) return false;
  const tail = ipPathTail(pathOrCmd); if (!tail) return false;
  return !ask.some((t) => tail.includes(t));
}

function ipCompute(d) {
  d = d || {};
  const ctx = d.cedar_context || {};
  const sc = d.scores || {};
  const oauth = ctx.oauth_email || d.oauth_email || ctx.os_user || d.user_email || "";
  const git = ctx.git_email || d.git_email || "";
  const assignee = ctx.jira_assignee_email || d.jira_assignee_email || "";
  const action = d.cedar_action || d.tool || "—";
  const cr = ctx.command_risk || "";
  const declared = ctx.declared_scope || ctx.initial_scope || d.declared_scope || "the requested task";
  const resource = d.cedar_resource || ctx.command || ctx.file_path || "";
  const cmd = ctx.command || (action === "RunBash" ? resource : "");
  const zone = ctx.file_zone || "";
  const trust = ctx.trust_score != null ? ctx.trust_score : (d.trust_score != null ? d.trust_score : 70);
  const driftScore = ctx.intent_drift_score != null ? ctx.intent_drift_score : (sc.intent_drift_score || 0);
  const drifted = !!ctx.is_intent_drift || driftScore > 0;

  // Mirror the server's classification of the action shape.
  const askedMutate = IP_ASKED_MUTATE.test(declared);
  const actionMutates = (action === "EditFile" || action === "WriteFile" || action === "MCPWrite") || cr === "destructive" || cr === "restricted" || (action === "RunBash" && IP_MUT_CMD.test(cmd));
  const isContentRead = action === "ReadFile" || action === "MCPRead" || (action === "RunBash" && IP_READ_CMD.test(cmd) && !IP_MUT_CMD.test(cmd));
  const isFileOp = isContentRead || action === "EditFile" || action === "WriteFile";

  // Actor — identity divergence (continuous).
  let actor = 0.05;
  if (git && oauth && git !== oauth) actor += 0.6;
  if (assignee && oauth && assignee !== oauth) actor += 0.3;
  if (trust < 50) actor += 0.1; if (trust < 20) actor += 0.15;
  actor = ipClamp(actor);

  // Value — operation risk (continuous).
  let value = cr === "destructive" ? 0.85 : cr === "restricted" ? 0.5 : 0.12;
  if (action === "EditFile" || action === "WriteFile") value = Math.max(value, 0.6);
  if (action === "MCPWrite" || action === "MCPExecute") value = Math.max(value, 0.5);
  value += (ctx.escalation_score || 0) / 100 * 0.2 + (ctx.exfiltration_score || 0) / 100 * 0.2;
  value = ipClamp(value);

  // Action — did the action TYPE exceed the declared (read/review) intent? Safe
  // listing/read is NOT a mutating action — this is the fix for `ls -la`.
  let actionV;
  if (!askedMutate && actionMutates) actionV = cr === "destructive" ? 0.85 : 0.6;
  else if (actionMutates) actionV = 0.35;
  else actionV = 0.1;
  actionV = ipClamp(actionV);

  // Target — resource-scope distance, only for actions that touch a file.
  let target = 0.08, outScope = false;
  if (isFileOp) {
    const z = zone === "secrets" ? 0.9 : zone === "config" ? 0.6 : zone === "src" ? 0.3 : zone === "docs" ? 0.22 : 0.16;
    outScope = ipOutOfScope(resource, declared);
    target = ipClamp(outScope ? 0.6 + z * 0.4 : z * 0.5);
  }

  // Scope — boundary: blend of server drift verdict, target distance, breadth.
  const priors = String(ctx.prior_intents || "").split(/[,|]/).filter(Boolean).length;
  const scope = ipClamp(Math.max(driftScore / 100, target * 0.7, 0.08 + priors * 0.03));

  const axes = { Actor: actor, Target: target, Value: value, Action: actionV, Scope: scope };
  const arr = [actor, target, value, actionV, scope];
  const mx = Math.max(...arr), mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  const agg = ipClamp(0.62 * mx + 0.38 * mean);

  return {
    axes, agg, drifted, driftScore, oauth, git, assignee, action, cr, declared, resource, zone,
    askedMutate, actionMutates, isContentRead, isFileOp, outScope,
    idMismatch: (!!git && !!oauth && git !== oauth) || (!!assignee && !!oauth && assignee !== oauth),
  };
}

function IpRadar({ axes }) {
  const order = ["Actor", "Target", "Value", "Action", "Scope"];
  const size = 300, cx = size / 2, cy = size / 2 + 4, maxR = 96;
  const pt = (i, r) => { const a = (-90 + i * 72) * Math.PI / 180; return [cx + Math.cos(a) * r * maxR, cy + Math.sin(a) * r * maxR]; };
  const rings = [0.25, 0.5, 0.75, 1];
  const actual = order.map((k) => axes[k]);
  const baseline = [0.4, 0.4, 0.4, 0.4, 0.4];
  const poly = (vals) => vals.map((v, i) => pt(i, v).join(",")).join(" ");
  return (
    <svg width="100%" viewBox={"0 0 " + size + " " + size} style={{ maxHeight: 300 }}>
      {rings.map((r, i) => <polygon key={i} points={order.map((_, j) => pt(j, r).join(",")).join(" ")} fill="none" stroke="var(--border)" strokeWidth="1" />)}
      {order.map((_, i) => { const [x, y] = pt(i, 1); return <line key={i} x1={cx} y1={cy} x2={x} y2={y} stroke="var(--border)" strokeWidth="1" />; })}
      <polygon points={poly(baseline)} fill="rgba(124,58,237,.06)" stroke="var(--purple)" strokeWidth="1.4" strokeDasharray="4 4" opacity=".7" />
      <polygon points={poly(actual)} fill="rgba(220,38,38,.13)" stroke="var(--red)" strokeWidth="2" />
      {actual.map((v, i) => { const [x, y] = pt(i, v); return <circle key={i} cx={x} cy={y} r="3.2" fill="var(--red)" />; })}
      {order.map((k, i) => { const [x, y] = pt(i, 1.16); return (
        <g key={k}>
          <text x={x} y={y - 3} textAnchor="middle" style={{ fontSize: 11, fontWeight: 600, fill: "var(--ink-3)" }}>{k}</text>
          <text x={x} y={y + 10} textAnchor="middle" style={{ fontSize: 11, fontWeight: 700, fill: "var(--ink)" }}>{axes[k].toFixed(2)}</text>
        </g>); })}
    </svg>
  );
}

function IpScoreBar({ score }) {
  return (
    <div>
      <div style={{ position: "relative", height: 12, borderRadius: 999, display: "flex" }}>
        <span style={{ flex: 0.4, background: "var(--green)", borderRadius: "999px 0 0 999px" }} />
        <span style={{ flex: 0.2, background: "var(--amber)" }} />
        <span style={{ flex: 0.4, background: "var(--red)", borderRadius: "0 999px 999px 0" }} />
        <span style={{ position: "absolute", top: "50%", left: (score * 100) + "%", transform: "translate(-50%,-50%)", width: 18, height: 18, borderRadius: "50%", background: "#fff", border: "3px solid var(--red)", boxShadow: "0 1px 4px rgba(16,24,40,.2)" }} />
      </div>
      <div style={{ display: "flex", marginTop: 6, fontSize: 11.5, color: "var(--ink-3)", fontWeight: 500 }}>
        <span style={{ flex: 0.4, textAlign: "center" }}>Aligned</span>
        <span style={{ flex: 0.2, textAlign: "center" }}>Misaligned</span>
        <span style={{ flex: 0.4, textAlign: "center" }}>Drifted</span>
      </div>
    </div>
  );
}

function IpTransition({ from, to, drift }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", fontSize: 12.5, fontWeight: 600, marginBottom: 8 }}>
      <span style={{ color: "var(--blue)" }}>{from}</span>
      <Icon name="arrowRight" size={13} color="var(--ink-4)" />
      <span style={{ color: drift ? "var(--red)" : "var(--blue)" }}>{to}</span>
    </div>
  );
}
function IpCard({ c }) {
  return (
    <div className="card" style={{ padding: 18 }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12, marginBottom: 12 }}>
        <span style={{ width: 40, height: 40, borderRadius: 11, flex: "none", display: "grid", placeItems: "center", background: "var(--" + c.tint + "-tint)", color: "var(--" + c.tint + ")" }}><Icon name={c.icon} size={20} /></span>
        <div>
          <div style={{ fontSize: 24, fontWeight: 700, color: "var(--ink)", letterSpacing: "-.02em", lineHeight: 1 }}>{c.score.toFixed(2)}</div>
          <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--ink)", marginTop: 4 }}>{c.label} <span style={{ color: "var(--ink-3)", fontWeight: 500 }}>({c.sub})</span></div>
        </div>
        <div style={{ marginLeft: "auto" }}><IpSevBadge level={c.sev} /></div>
      </div>
      <IpTransition from={c.from} to={c.to} drift={c.drift} />
      <div style={{ fontSize: 12.5, color: "var(--ink-3)", lineHeight: 1.55 }}>{c.note}</div>
    </div>
  );
}

function IntentProfile({ log, onBack }) {
  const d = (log && log._d) || {};
  const traceId = (log && log.traceId) || "—";
  const r = ipCompute(d);
  const drifted = r.drifted;
  // Display verdict (render-only, additive): derive the headline / colour / badge
  // from the computed aggregate so the words match the radar and the marker's band.
  // Uses the same 0.4 / 0.6 thresholds the score bar already draws. The backend
  // is_intent_drift / intent_drift_score flag (`drifted`) is kept as an elevator,
  // not the sole driver — read alone it is unpopulated and always rendered "Aligned".
  // No change to ipCompute scoring or to the backend signal.
  const band = (drifted || r.agg >= 0.6) ? "drifted" : r.agg >= 0.4 ? "misaligned" : "aligned";
  const bandColor = band === "drifted" ? "var(--red)" : band === "misaligned" ? "var(--amber)" : "var(--teal)";
  // Scope card mirrors its own axis (as the other four cards already mirror theirs),
  // validated: assert scope drift only when the declared scope is evaluable (has
  // scope tokens) — otherwise the boundary can't be judged and we stay aligned.
  const scopeEvaluable = ipTokensOf(r.declared).length > 0;
  const scopeDrift = drifted || (scopeEvaluable && r.axes.Scope >= 0.4);
  const behavior = r.action + (r.resource ? " · " + r.resource : "");
  const sev = (v) => ipSev(v);
  const cards = [
    { icon: "user", tint: r.idMismatch ? "red" : "blue", score: r.axes.Actor, label: "Actor", sub: "Identity", elevated: r.idMismatch,
      from: r.oauth || "authenticated user", to: r.idMismatch ? (r.git || r.assignee || "different identity") : (r.oauth || "authenticated user"),
      note: r.idMismatch ? "Acting identity diverged from the authenticated user — the committer/assignee email does not match the OAuth identity (Identity Integrity)." : "Acting identity matches the authenticated developer throughout — no identity drift." },
    { icon: "target", tint: r.outScope ? "red" : "blue", score: r.axes.Target, label: "Target", sub: "Resource", elevated: r.outScope,
      from: r.isFileOp ? "asked folders" : "no file read", to: r.isFileOp ? (r.resource || "—") : "listing / metadata only",
      note: !r.isFileOp ? "No file contents were read — a listing or metadata action, which is never out of scope." : r.outScope ? "Read a file outside the asked folders — a path that was never part of the request." : "File access stayed within the asked folders." },
    { icon: "coin", tint: r.axes.Value >= 0.5 ? "coral" : "green", score: r.axes.Value, label: "Value", sub: "Operation", elevated: r.axes.Value >= 0.5,
      from: "declared intent", to: (r.cr ? r.cr + " " : "") + r.action,
      note: r.axes.Value >= 0.5 ? "Operation carries elevated risk — a mutating or higher-risk command class." : "Operation remained low-risk and consistent with the declared intent." },
    { icon: "play", tint: (!r.askedMutate && r.actionMutates) ? "coral" : "green", score: r.axes.Action, label: "Action", sub: "Intent Type", elevated: (!r.askedMutate && r.actionMutates),
      from: r.askedMutate ? "declared change" : "review / read", to: r.action,
      note: (!r.askedMutate && r.actionMutates) ? "Action type exceeded the declared intent — a mutating action when only a read or review was asked." : "Action type is consistent with the declared intent." },
    { icon: "pin", tint: scopeDrift ? "red" : "purple", score: r.axes.Scope, label: "Scope", sub: "Boundary", elevated: scopeDrift,
      from: r.declared, to: scopeDrift ? "drifted beyond the asked scope" : "within the asked scope",
      note: scopeDrift ? "Execution moved beyond the declared task boundary — work the developer did not ask for." : "Execution stayed within the declared task boundary." },
  ].map((c) => ({ ...c, sev: sev(c.score), drift: c.elevated }));

  const scoreColor = bandColor;
  const statusText = band === "drifted" ? (r.agg >= 0.85 ? "High / drifted" : "Drifted") : band === "misaligned" ? "Misaligned" : "Aligned";

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 22 }}>
        <button className="kebab" onClick={onBack} style={{ width: 38, height: 38, border: "1px solid var(--border-strong)" }}><Icon name="arrowLeft" size={18} /></button>
        <div>
          <h1 style={{ margin: 0, fontSize: 21, fontWeight: 600, letterSpacing: "-.02em", color: "var(--ink)" }}>Intent Drift Attribution</h1>
          <div className="mono" style={{ fontSize: 12, color: "var(--ink-3)", marginTop: 3 }}>TraceID: {traceId}</div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "340px 1fr", gap: 16, marginBottom: 16 }}>
        <div className="card" style={{ padding: 18 }}>
          <div className="section-title" style={{ fontSize: 15, marginBottom: 6 }}>Drift Attribution</div>
          <IpRadar axes={r.axes} />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="card" style={{ padding: 20 }}>
            <div className="section-title" style={{ fontSize: 15, marginBottom: 14 }}>Intent Comparison</div>
            <div style={{ display: "flex", alignItems: "stretch", gap: 14 }}>
              <div style={{ flex: 1, minWidth: 0, background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 12, padding: "14px 16px" }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--blue)", marginBottom: 6 }}>Declared Scope</div>
                <div style={{ fontSize: 13.5, color: "var(--ink)", fontStyle: "italic", whiteSpace: "normal", wordBreak: "break-word" }}>"{r.declared}"</div>
              </div>
              <div style={{ display: "grid", placeItems: "center" }}><Icon name="arrowRight" size={20} color="var(--ink-4)" /></div>
              {(() => {
                const bg = band === "drifted" ? "var(--red-tint)" : band === "misaligned" ? "var(--amber-tint)" : "var(--green-tint)";
                const bd = band === "drifted" ? "#F5C2C2" : band === "misaligned" ? "#F3D9A6" : "#BFE3D2";
                const fg = band === "drifted" ? "var(--red)" : band === "misaligned" ? "var(--amber-ink)" : "var(--teal)";
                const ic = band === "aligned" ? "checkCircle" : "flame";
                const tx = band === "drifted" ? "Drifted Behavior" : band === "misaligned" ? "Scope Misaligned" : "Scope Aligned";
                const tc = band === "aligned" ? "var(--ink)" : "var(--coral-ink)";
                return (
                  <div style={{ flex: "0 0 42%", minWidth: 0, background: bg, border: "1px solid " + bd, borderRadius: 12, padding: "14px 16px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, color: fg, marginBottom: 6 }}>
                      <Icon name={ic} size={14} color={fg} />
                      {tx}
                    </div>
                    <div style={{ fontSize: 13.5, color: tc, fontStyle: "italic", whiteSpace: "normal", wordBreak: "break-word" }}>"{behavior}"</div>
                  </div>
                );
              })()}
            </div>
          </div>
          <div className="card" style={{ padding: 20 }}>
            <div className="section-title" style={{ fontSize: 15, marginBottom: 14 }}>Drift Score</div>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
              <span style={{ fontSize: 38, fontWeight: 700, color: scoreColor, letterSpacing: "-.03em", lineHeight: 1 }}>{r.agg.toFixed(2)}</span>
              <span style={{ fontSize: 13.5, color: "var(--ink-3)", fontWeight: 500 }}>{statusText}</span>
              <IpSevBadge level={sev(r.agg)} />
            </div>
            <IpScoreBar score={r.agg} />
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
        {cards.map((c) => <IpCard key={c.label} c={c} />)}
      </div>
    </div>
  );
}
window.IntentProfile = IntentProfile;


ReactDOM.createRoot(document.getElementById("root")).render(<App />);
