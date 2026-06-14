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
// deriving strictly from real, live data. This file is agent-context only, and
// is merged ALONGSIDE whatever live data exists at request time.
//
// Toggle:  REVA_DEMO_SEED=0  disables it. Enabled by default.
// ============================================================================

export const DEMO_SEED_ENABLED = String(process.env.REVA_DEMO_SEED ?? '1') !== '0';

const ORG_UUID = '48315397-b7b9-4b42-bf6f-48392136c7a5';
const minsAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
const minsAhead = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

// ── Sessions (5: Amit ×3, Chiranth ×1, Shikhar ×1) ──────────────────────────
export const demoSessions = [
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

// ── JIT / SVID — Amit holds 1 active credential (10-min TTL), APPROVED BY SHIKHAR ──
export const demoSvids = [
  {
    id: 'svid-demo-amit-01', developer_email: 'amit.phadke@reva.ai',
    action: 'push', project: 'reva-portal',
    spiffe_id: 'spiffe://reva.ai/agent/github-copilot/dev/7c2a91de-3b54-44f1-9a02-1de77a5c4410',
    issued_by: 'shikhar@reva.ai', status: 'active',
    issued_at: minsAgo(4), expires_at: minsAhead(6),
    coding_agent: 'github-copilot', os_user: 'amit.phadke@reva.ai',
    session_id: 'a91f0c2d-77bb-4e10-9f3a-2c4d8e6b1a90',
  },
];

// ── Quarantines — Chiranth (codex) quarantined for intent drift ─────────────
// Concrete quarantined identity = Chiranth (Option A). The aggregate tile count
// is 2 and is carried in demoInsights.totals.active_quarantines.
export const demoQuarantines = [
  {
    osUser: 'chiranth@reva.ai', codingAgent: 'codex',
    sessionId: '019ec0f7-556e-7e40-98e2-97eded7c5ffa',
    policyId: 'AAI-AIG-004', policyName: 'Intent Drift Enforcement',
    reason: 'Intent drift threshold exceeded',
    status: 'Quarantined', since: minsAgo(22), expiresAt: null,
  },
];

// ── Per-identity governance profiles (authoritative decision ground truth) ──
export const demoIdentities = [
  {
    principal: 'Developer::"Amit Phadke"', coding_agent: 'github-copilot', coding_agent_label: 'GitHub Copilot',
    authenticated_as: 'amit.phadke@reva.ai', owner: 'Amit Phadke', surface: 'vscode',
    model: 'gpt-5.5', os: 'Windows', sessions: 3, trust: 72, state: 'Active',
    prompts_blocked: 2, jit_active: 1, quarantined: false, low_trust: false,
    spiffe_id: 'spiffe://reva.ai/agent/github-copilot/dev/7c2a91de-3b54-44f1-9a02-1de77a5c4410',
    account_uuid: '7c2a91de-3b54-44f1-9a02-1de77a5c4410', org_uuid: ORG_UUID,
    mcp_servers: ['claude.ai Atlassian Rovo', 'claude.ai Google Drive'],
    decisions: 102, denials: 48, deny_rate_pct: 47, deny_rate_dir: 'up',
    deny_reasons: [
      { label: 'Intent Drift', count: 20, pct: 42 },
      { label: 'Policy Denial', count: 16, pct: 33 },
      { label: 'Low Trust', count: 12, pct: 25 },
    ],
    surface_insights: [{ surface: 'vscode', sessions: 3, deny_pct: 47 }],
  },
  {
    principal: 'Developer::"Chiranth"', coding_agent: 'codex', coding_agent_label: 'Codex',
    authenticated_as: 'chiranth@reva.ai', owner: 'Chiranth', surface: 'codex_cli',
    model: 'gpt-5.5', os: 'Darwin', sessions: 1, trust: 78, state: 'Quarantined',
    prompts_blocked: 2, jit_active: 0, quarantined: true,
    quarantine_reason: 'Intent drift threshold exceeded',
    low_trust: false,
    spiffe_id: 'spiffe://reva.ai/agent/codex/dev/019ec0f7-556e-7e40-98e2-97eded7c5ffa',
    account_uuid: '019ec0f7-556e-7e40-98e2-97eded7c5ffa', org_uuid: ORG_UUID,
    mcp_servers: [],
    decisions: 88, denials: 41, deny_rate_pct: 47, deny_rate_dir: 'up',
    deny_reasons: [
      { label: 'Prompt Injection', count: 19, pct: 46 },
      { label: 'Policy Denial', count: 14, pct: 34 },
      { label: 'Intent Drift', count: 8, pct: 20 },
    ],
    surface_insights: [{ surface: 'codex_cli', sessions: 1, deny_pct: 47 }],
  },
  {
    principal: 'Developer::"Shikhar"', coding_agent: 'kiro', coding_agent_label: 'Kiro',
    authenticated_as: 'shikhar@reva.ai', owner: 'Shikhar', surface: 'kiro_cli',
    model: 'deepseek-3.2 (workspace)', os: 'Darwin', sessions: 1, trust: 52, state: 'Active',
    prompts_blocked: 1, jit_active: 0, quarantined: false, low_trust: true,
    spiffe_id: 'spiffe://reva.ai/agent/kiro/dev/43d02ee8-8a64-4f28-8fa3-e191fd9877ea',
    account_uuid: '43d02ee8-8a64-4f28-8fa3-e191fd9877ea', org_uuid: ORG_UUID,
    mcp_servers: [], kiro: { accountType: 'BuilderId', email: 'shikhar@reva.ai', region: 'us-east-1', startUrl: 'https://view.awsapps.com/start' },
    decisions: 85, denials: 38, deny_rate_pct: 45, deny_rate_dir: 'down',
    deny_reasons: [
      { label: 'Policy Denial', count: 17, pct: 45 },
      { label: 'Intent Drift', count: 13, pct: 34 },
      { label: 'Low Trust', count: 8, pct: 21 },
    ],
    surface_insights: [{ surface: 'kiro_cli', sessions: 1, deny_pct: 45 }],
  },
];

// ── Environment aggregates ──────────────────────────────────────────────────
export const demoInsights = {
  permit_deny: {
    by: 'session', range: 'last-week', permit_pct: 65, deny_pct: 35,
    permit: 179, deny: 96, total: 275,
    deny_breakdown: [
      { label: 'Prompt Injection', count: 22, pct: 23 },
      { label: 'Intent Drift', count: 19, pct: 20 },
      { label: 'Low Trust', count: 10, pct: 10 },
      { label: 'Quarantine', count: 15, pct: 16 },
      { label: 'Policy Denial', count: 30, pct: 31 },
    ],
  },
  usage_by_tool: [
    { tool: 'prompt', count: 37, permits: 23, permit_pct: 62 },
    { tool: 'session-end', count: 11, permits: 11, permit_pct: 100 },
    { tool: 'ReadFile', count: 48, permits: 28, permit_pct: 58 },
    { tool: 'EditFile', count: 34, permits: 22, permit_pct: 65 },
    { tool: 'WriteFile', count: 19, permits: 11, permit_pct: 58 },
    { tool: 'RunBash', count: 62, permits: 32, permit_pct: 52 },
    { tool: 'SpawnAgent', count: 28, permits: 28, permit_pct: 100 },
    { tool: 'MCPRead', count: 22, permits: 17, permit_pct: 77 },
    { tool: 'MCPWrite', count: 14, permits: 5, permit_pct: 36 },
  ],
  high_deny: [
    { principal: 'Developer::"Amit Phadke"', coding_agent: 'github-copilot', model: 'gpt-5.5', decisions: 102, denials: 48, deny_rate_pct: 47, dir: 'up' },
    { principal: 'Developer::"Chiranth"', coding_agent: 'codex', model: 'gpt-5.5', decisions: 88, denials: 41, deny_rate_pct: 47, dir: 'up' },
    { principal: 'Developer::"Shikhar"', coding_agent: 'kiro', model: 'deepseek-3.2 (workspace)', decisions: 85, denials: 38, deny_rate_pct: 45, dir: 'down' },
  ],
  totals: {
    agents: 3, agents_previous: 3,
    prompts_blocked: 5, prompts_blocked_previous: 4,
    prompts_blocked_by_agent: { 'github-copilot': 2, codex: 2, kiro: 1 },
    affected_identities: 3,
    jit_active: 1, jit_active_previous: 1,
    active_quarantines: 2, active_quarantines_previous: 1, quarantines_new_today: 1,
    low_trust: 3, low_trust_previous: 2, low_trust_threshold: 60, trust_baseline: 70,
  },
  workload_owner: 'amit.phadke@reva.ai',
  approver: { selected: 'amit.phadke@reva.ai', known: ['sai.srungaram@reva.ai', 'yash.prakash@reva.ai'] },
};
