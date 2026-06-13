// ============================================================================
// Reva — Demo Seed  (src/api/demoSeed.ts)
// ----------------------------------------------------------------------------
// Synthetic governance data used ONLY by the Ask Reva AI agent (ask.ts). It is
// merged into the agent's Bedrock snapshot so questions about Amit / Chiranth /
// Shikhar, their sessions, JIT, decisions and quarantine status can be answered.
//
// IMPORTANT: this is NEVER written into sessionStore / decisionLog / svidStore /
// the quarantine store, so it does NOT appear in the dashboard or any of the
// /api/insights, /api/sessions or /api/identities endpoints — those keep
// deriving strictly from real, live data. This file is agent-context only.
//
// Toggle:  REVA_DEMO_SEED=0  disables it. Enabled by default.
// ============================================================================

export const DEMO_SEED_ENABLED = String(process.env.REVA_DEMO_SEED ?? '1') !== '0';

const ORG_UUID = '48315397-b7b9-4b42-bf6f-48392136c7a5';
const nowIso = () => new Date().toISOString();
const minsAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
const minsAhead = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

// ── Sessions (5: Amit ×3, Chiranth ×1, Shikhar ×1) ──────────────────────────
// Shaped to match the fields ask.ts buildSnapshot() reads off a session.
export const demoSessions = [
  // Amit Phadke — GitHub Copilot, VS Code, Windows
  ...['a91f0c2d-77bb-4e10-9f3a-2c4d8e6b1a90',
      'b02e7f31-1aa9-4c88-bd44-9e1f6a2c7d33',
      'c13d8a40-22bc-4d99-ae55-af207b3d8e44'].map((sid, i) => ({
    session_id: sid, coding_agent: 'github-copilot', surface: 'vscode', entrypoint: 'vscode',
    connection_type: 'local', ssh_client_ip: null,
    os_type: 'Windows', remote_os: null, hostname: `WIN-AMIT-0${i + 1}`, model: 'gpt-5.5',
    project_name: 'reva-portal', git_branch: 'feature/copilot-governance',
    oauth_email: 'amit.phadke@reva.ai', user_email: 'amit.phadke@reva.ai',
    git_email: 'amit.phadke@reva.ai', jira_assignee_email: 'amit.phadke@reva.ai',
    account_uuid: '7c2a91de-3b54-44f1-9a02-1de77a5c4410', org_uuid: ORG_UUID,
    spiffe_id: 'spiffe://reva.ai/agent/github-copilot/dev/7c2a91de-3b54-44f1-9a02-1de77a5c4410',
    mcp_servers_discovered: ['claude.ai Atlassian Rovo', 'claude.ai Google Drive'],
    enrolled_at: minsAgo(180 - i * 40),
  })),
  // Chiranth — Codex CLI, macOS
  {
    session_id: '019ec0f7-556e-7e40-98e2-97eded7c5ffa', coding_agent: 'codex',
    surface: 'codex_cli', entrypoint: 'codex_cli', connection_type: 'local', ssh_client_ip: null,
    os_type: 'Darwin', remote_os: null, hostname: 'mac-chiranth', model: 'gpt-5.5',
    project_name: 'reva-backend', git_branch: 'main',
    oauth_email: 'chiranth@reva.ai', user_email: 'chiranth@reva.ai',
    git_email: 'chiranth@reva.ai', jira_assignee_email: 'chiranth@reva.ai',
    account_uuid: '019ec0f7-556e-7e40-98e2-97eded7c5ffa', org_uuid: ORG_UUID,
    spiffe_id: 'spiffe://reva.ai/agent/codex/dev/019ec0f7-556e-7e40-98e2-97eded7c5ffa',
    mcp_servers_discovered: [], enrolled_at: minsAgo(95),
  },
  // Shikhar — Kiro CLI, macOS
  {
    session_id: '43d02ee8-8a64-4f28-8fa3-e191fd9877ea', coding_agent: 'kiro',
    surface: 'kiro_cli', entrypoint: 'kiro_cli', connection_type: 'local', ssh_client_ip: null,
    os_type: 'Darwin', remote_os: null, hostname: 'mac-shikhar', model: 'deepseek-3.2 (workspace)',
    project_name: 'reva-sdk', git_branch: 'main',
    oauth_email: 'shikhar@reva.ai', user_email: 'shikhar@reva.ai',
    git_email: 'shikhar@reva.ai', jira_assignee_email: 'shikhar@reva.ai',
    account_uuid: '43d02ee8-8a64-4f28-8fa3-e191fd9877ea', org_uuid: ORG_UUID,
    spiffe_id: 'spiffe://reva.ai/agent/kiro/dev/43d02ee8-8a64-4f28-8fa3-e191fd9877ea',
    mcp_servers_discovered: [], enrolled_at: minsAgo(60),
  },
];

// ── JIT / SVID (Amit holds 1 active short-lived credential, 10-min TTL) ──────
export const demoSvids = [
  {
    id: 'svid-demo-amit-01', developer_email: 'amit.phadke@reva.ai',
    action: 'push', project: 'reva-portal',
    spiffe_id: 'spiffe://reva.ai/agent/github-copilot/dev/7c2a91de-3b54-44f1-9a02-1de77a5c4410',
    issued_by: 'amit.phadke@reva.ai', status: 'active',
    issued_at: minsAgo(4), expires_at: minsAhead(6),
    coding_agent: 'github-copilot', os_user: 'amit.phadke@reva.ai',
    session_id: 'a91f0c2d-77bb-4e10-9f3a-2c4d8e6b1a90',
  },
];

// ── Quarantines (none active in this dataset) ───────────────────────────────
// To demo a non-empty quarantine list, add a record here, e.g.:
//   { osUser: 'chiranth@reva.ai', codingAgent: 'codex', sessionId: '019ec0f7-…',
//     policyId: 'AAI-UAP-001', policyName: 'Prompt Injection Detection',
//     reason: 'injection detected in prompt', status: 'Quarantined',
//     since: minsAgo(20), expiresAt: null }
export const demoQuarantines: any[] = [];

// ── Per-identity governance profile (mirrors /api/insights/summary identities)
// Authoritative aggregate data the agent reasons over. No individual decision
// rows are fabricated — these summaries ARE the decision ground truth.
export const demoIdentities = [
  {
    principal: 'Developer::"Amit Phadke"', coding_agent: 'github-copilot', coding_agent_label: 'GitHub Copilot',
    authenticated_as: 'amit.phadke@reva.ai', owner: 'Amit Phadke', surface: 'vscode',
    model: 'gpt-5.5', os: 'Windows', sessions: 3, trust: 72, state: 'Active',
    prompts_blocked: 0, jit_active: 1, quarantined: false, low_trust: false,
    spiffe_id: 'spiffe://reva.ai/agent/github-copilot/dev/7c2a91de-3b54-44f1-9a02-1de77a5c4410',
    account_uuid: '7c2a91de-3b54-44f1-9a02-1de77a5c4410', org_uuid: ORG_UUID,
    mcp_servers: ['claude.ai Atlassian Rovo', 'claude.ai Google Drive'],
    decisions: 62, denials: 29, deny_rate_pct: 47, deny_rate_dir: 'up',
    deny_reasons: [
      { label: 'Intent Drift', count: 12, pct: 41 },
      { label: 'Policy Denial', count: 10, pct: 34 },
      { label: 'Low Trust', count: 7, pct: 24 },
    ],
    surface_insights: [{ surface: 'vscode', sessions: 3, deny_pct: 47 }],
  },
  {
    principal: 'Developer::"Chiranth"', coding_agent: 'codex', coding_agent_label: 'Codex',
    authenticated_as: 'chiranth@reva.ai', owner: 'Chiranth', surface: 'codex_cli',
    model: 'gpt-5.5', os: 'Darwin', sessions: 1, trust: 78, state: 'Active',
    prompts_blocked: 0, jit_active: 0, quarantined: false, low_trust: false,
    spiffe_id: 'spiffe://reva.ai/agent/codex/dev/019ec0f7-556e-7e40-98e2-97eded7c5ffa',
    account_uuid: '019ec0f7-556e-7e40-98e2-97eded7c5ffa', org_uuid: ORG_UUID,
    mcp_servers: [],
    decisions: 51, denials: 24, deny_rate_pct: 47, deny_rate_dir: 'up',
    deny_reasons: [
      { label: 'Prompt Injection', count: 11, pct: 46 },
      { label: 'Policy Denial', count: 8, pct: 33 },
      { label: 'Intent Drift', count: 5, pct: 21 },
    ],
    surface_insights: [{ surface: 'codex_cli', sessions: 1, deny_pct: 47 }],
  },
  {
    principal: 'Developer::"Shikhar"', coding_agent: 'kiro', coding_agent_label: 'Kiro',
    authenticated_as: 'shikhar@reva.ai', owner: 'Shikhar', surface: 'kiro_cli',
    model: 'deepseek-3.2 (workspace)', os: 'Darwin', sessions: 1, trust: 81, state: 'Active',
    prompts_blocked: 0, jit_active: 0, quarantined: false, low_trust: false,
    spiffe_id: 'spiffe://reva.ai/agent/kiro/dev/43d02ee8-8a64-4f28-8fa3-e191fd9877ea',
    account_uuid: '43d02ee8-8a64-4f28-8fa3-e191fd9877ea', org_uuid: ORG_UUID,
    mcp_servers: [], kiro: { accountType: 'BuilderId', email: 'shikhar@reva.ai', region: 'us-east-1', startUrl: 'https://view.awsapps.com/start' },
    decisions: 44, denials: 20, deny_rate_pct: 45, deny_rate_dir: 'down',
    deny_reasons: [
      { label: 'Policy Denial', count: 9, pct: 45 },
      { label: 'Intent Drift', count: 7, pct: 35 },
      { label: 'Low Trust', count: 4, pct: 20 },
    ],
    surface_insights: [{ surface: 'kiro_cli', sessions: 1, deny_pct: 45 }],
  },
];

// ── Environment aggregates (permit/deny mix, usage by tool) ─────────────────
export const demoInsights = {
  permit_deny: {
    by: 'session', range: 'last-week', permit_pct: 65, deny_pct: 35,
    permit: 102, deny: 56, total: 158,
    deny_breakdown: [
      { label: 'Prompt Injection', count: 14, pct: 25 },
      { label: 'Intent Drift', count: 12, pct: 21 },
      { label: 'Low Trust', count: 2, pct: 4 },
      { label: 'Quarantine', count: 15, pct: 27 },
      { label: 'Policy Denial', count: 13, pct: 23 },
    ],
  },
  usage_by_tool: [
    { tool: 'prompt', count: 24, permits: 15, permit_pct: 62 },
    { tool: 'session-end', count: 7, permits: 7, permit_pct: 100 },
    { tool: 'ReadFile', count: 31, permits: 18, permit_pct: 58 },
    { tool: 'EditFile', count: 22, permits: 14, permit_pct: 64 },
    { tool: 'WriteFile', count: 12, permits: 7, permit_pct: 58 },
    { tool: 'RunBash', count: 40, permits: 21, permit_pct: 52 },
    { tool: 'SpawnAgent', count: 18, permits: 18, permit_pct: 100 },
    { tool: 'MCPRead', count: 14, permits: 11, permit_pct: 79 },
    { tool: 'MCPWrite', count: 9, permits: 2, permit_pct: 22 },
  ],
  totals: { agents: 3, jit_active: 1, active_quarantines: 0, low_trust: 0 },
  workload_owner: 'amit.phadke@reva.ai',
};
