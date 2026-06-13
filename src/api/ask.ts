// ============================================================================
// Reva — "Ask Reva AI"  (src/api/ask.ts)
// ----------------------------------------------------------------------------
// AI Governance Assistant. Assembles a live snapshot of
// the in-memory governance stores (sessions, decisions, quarantines, SVID/JIT),
// sends it to Claude on AWS Bedrock with a grounded system prompt, and returns a
// structured { summary, tables[] } answer the chat renders natively.
//
// Server-side only — AWS credentials live in the plugin's env, never the bundle.
//
// Env:
//   AWS_REGION         default ap-southeast-1
//   BEDROCK_MODEL_ID   default global.anthropic.claude-haiku-4-5-20251001-v1:0
//   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY [/ AWS_SESSION_TOKEN]  (SDK default chain)
//
// Mount: app.use('/api', askRouter)   // POST /api/ask
// ============================================================================

import { Router } from 'express';
import { BedrockRuntimeClient, ConverseCommand } from '@aws-sdk/client-bedrock-runtime';
import { sessionStore, decisionLog } from '../connector/discovery/enroll';
import { listQuarantines } from './quarantine';
import { listAllSVIDs } from './svid';
import { DEMO_SEED_ENABLED, demoSessions, demoSvids, demoQuarantines, demoIdentities, demoInsights } from './demoSeed';

const REGION = process.env.AWS_REGION || 'ap-southeast-1';
const MODEL_ID = process.env.BEDROCK_MODEL_ID || 'global.anthropic.claude-haiku-4-5-20251001-v1:0';

let _client: BedrockRuntimeClient | null = null;
function client(): BedrockRuntimeClient {
  if (!_client) _client = new BedrockRuntimeClient({ region: REGION });
  return _client;
}

// ── Live snapshot — the only ground truth the model may use ──────────────────
function buildSnapshot() {
  const sessions = Array.from(sessionStore.values()).map((raw) => {
    const s: any = raw;
    return {
      session_id: s.session_id, coding_agent: s.coding_agent,
      access_surface: s.surface || s.entrypoint || null,
      connection_type: s.connection_type || null, ssh_client_ip: s.ssh_client_ip || null,
      os: s.os_type || s.remote_os || null, hostname: s.hostname || null, model: s.model || null,
      project: s.project_name || null, git_branch: s.git_branch || null,
      // identity surfaces — divergence between these is a governance signal
      authenticated_oauth_email: s.oauth_email || s.user_email || null,
      git_email: s.git_email || null, jira_assignee_email: s.jira_assignee_email || null,
      account_uuid: s.account_uuid || null, org_uuid: s.org_uuid || null,
      spiffe_id: s.spiffe_id || null,
      mcp_servers_discovered: s.mcp_servers_discovered || [],
      enrolled_at: s.enrolled_at || null,
    };
  });

  // decisions: include ALL non-permits (the interesting ones) + recent permits, capped.
  const all = decisionLog.slice();
  const compact = (raw: any) => ({
    timestamp: raw.timestamp, session_id: raw.session_id, user_email: raw.user_email,
    tool: raw.tool, server: raw.server, effect: raw.effect, intent: raw.intent || null,
    reason: raw.reason || null, trust_score: raw.trust_score ?? null,
    command_risk: raw.command_risk || null, file_zone: raw.file_zone || null,
    cedar_policy: raw.cedar_policy_name || null, cedar_action: raw.cedar_action || null,
    cedar_resource: raw.cedar_resource || null,
    session_trace_id: (raw.cedar_context && raw.cedar_context.session_trace_id) || null,
  });
  const denies = all.filter((d: any) => d.effect !== 'Permit');
  const permits = all.filter((d: any) => d.effect === 'Permit');
  const recentPermits = permits.slice(-Math.max(0, 400 - denies.length));
  const decisions = [...denies, ...recentPermits]
    .sort((a: any, b: any) => String(a.timestamp).localeCompare(String(b.timestamp)))
    .map(compact);

  const quarantines = listQuarantines().map((q) => ({
    osUser: q.osUser, policyId: q.policyId, policyName: q.policyName, reason: q.reason,
    status: q.status, since: q.since, expiresAt: q.expiresAt ?? null,
  }));

  const svids = listAllSVIDs().map((s: any) => ({
    developer_email: s.developer_email, action: s.action, project: s.project,
    spiffe_id: s.spiffe_id, issued_by: s.issued_by, status: s.status,
    issued_at: s.issued_at, expires_at: s.expires_at,
  }));

  const snapshot: any = { generatedAt: new Date().toISOString(), sessions, decisions, quarantines, svids };

  // Demo seed — AGENT-ONLY. Merged into the snapshot the model sees so it can
  // answer about the demo identities, but never written to any shared store, so
  // the dashboard and all /api endpoints stay on real data only.
  if (DEMO_SEED_ENABLED) {
    const compactSeedSession = (s: any) => ({
      session_id: s.session_id, coding_agent: s.coding_agent,
      access_surface: s.surface || s.entrypoint || null,
      connection_type: s.connection_type || null, ssh_client_ip: s.ssh_client_ip || null,
      os: s.os_type || s.remote_os || null, hostname: s.hostname || null, model: s.model || null,
      project: s.project_name || null, git_branch: s.git_branch || null,
      authenticated_oauth_email: s.oauth_email || s.user_email || null,
      git_email: s.git_email || null, jira_assignee_email: s.jira_assignee_email || null,
      account_uuid: s.account_uuid || null, org_uuid: s.org_uuid || null,
      spiffe_id: s.spiffe_id || null, mcp_servers_discovered: s.mcp_servers_discovered || [],
      enrolled_at: s.enrolled_at || null,
    });
    snapshot.sessions = [...snapshot.sessions, ...demoSessions.map(compactSeedSession)];
    snapshot.svids = [...snapshot.svids, ...demoSvids.map((s: any) => ({
      developer_email: s.developer_email, action: s.action, project: s.project,
      spiffe_id: s.spiffe_id, issued_by: s.issued_by, status: s.status,
      issued_at: s.issued_at, expires_at: s.expires_at,
    }))];
    snapshot.quarantines = [...snapshot.quarantines, ...demoQuarantines.map((q: any) => ({
      osUser: q.osUser, policyId: q.policyId, policyName: q.policyName, reason: q.reason,
      status: q.status, since: q.since, expiresAt: q.expiresAt ?? null,
    }))];
    // Per-identity governance profiles + environment aggregates (the authoritative
    // decision ground truth for these identities — no individual rows fabricated).
    snapshot.identities = demoIdentities;
    snapshot.insights = demoInsights;
  }

  return snapshot;
}

const SYSTEM_PROMPT = `You are Reva AI, the AI Governance Assistant embedded in the Reva console for agentic workloads (Claude Code, Codex, Kiro). You help teams understand and manage how their AI agents are governed, using the LIVE governance data provided below.

RULES:
- Answer ONLY from the DATA snapshot. Never invent identities, sessions, decisions, or findings. If something is not in the data, do not assert it.
- The DATA snapshot may include: "sessions", "decisions", "quarantines", "svids" (live), and — when present — "identities" (a per-developer×coding-agent governance profile: owner, model, trust, session count, JIT, decision/denial counts, deny-reason breakdown, surface insights) and "insights" (environment aggregates: permit/deny mix, usage by tool, totals). Treat "identities" and "insights" as authoritative; the per-identity decision/denial counts and deny reasons ARE the decision ground truth for those identities even without individual decision rows.
- Reason across the data to answer questions about agentic workloads, access and policy decisions, identity and ownership, trust, behavioral anomalies, and quarantined access. Correlate across sessions, decisions, identity fields, time, and trace ids where it helps — e.g. access that no longer matches an identity, agents reaching scope outside their registered tools, activity diverging from declared intent, repeated policy denials, or credential/JIT use. Go beyond aggregate counts a dashboard already shows.
- If the data is insufficient to answer, say so plainly in "summary" and return an empty "tables" array. Never fabricate rows to fill a table.
- Respond with ONLY a single JSON object and nothing else (no prose, no markdown fences):
{"summary":"2-5 sentence answer","tables":[{"title":"string","columns":["col1","col2"],"rows":[["v1","v2"]]}],"note":"optional one-line caveat or suggested next step"}
- Keep each table focused: only the columns and rows relevant to the answer. Use "tables":[] when no table is warranted.`;

export const askRouter = Router();

// Starter content for the chat window — product + dashboard both fetch this so
// the welcome message and suggested questions come from one source of truth.
const WELCOME = "Welcome to Reva AI — your AI Governance Assistant. Ask about agentic workloads, access and policy decisions, behavioral anomaly analysis, and quarantined access across your environment.";
const EXAMPLES = [
  "Which agents hold access that no longer matches their owner or assigned identity?",
  "Show agents whose trust has dropped and what access they still hold.",
  "Summarize the access decisions for the most recently isolated agent.",
  "Where did an agent's recent activity diverge from its declared intent?",
];

askRouter.get('/ask/welcome', (_req, res) => {
  res.json({ welcome: WELCOME, examples: EXAMPLES });
});

askRouter.post('/ask', async (req, res) => {
  const question = String((req.body && req.body.question) || '').trim();
  if (!question) return res.status(400).json({ error: 'question required' });
  const history = Array.isArray(req.body && req.body.history) ? req.body.history : [];

  const snapshot = buildSnapshot();
  const system = [{ text: `${SYSTEM_PROMPT}\n\nDATA (live snapshot, JSON):\n${JSON.stringify(snapshot)}` }];

  // prior turns (text only) + current question
  const messages: any[] = [];
  for (const h of history.slice(-6)) {
    if (h && (h.role === 'user' || h.role === 'assistant') && h.text) {
      messages.push({ role: h.role, content: [{ text: String(h.text) }] });
    }
  }
  messages.push({ role: 'user', content: [{ text: question }] });

  try {
    const resp = await client().send(new ConverseCommand({
      modelId: MODEL_ID,
      system,
      messages,
      inferenceConfig: { maxTokens: 2000, temperature: 0 },
    }));
    const text = (resp.output?.message?.content || []).map((c: any) => c.text).filter(Boolean).join('\n').trim();
    const parsed = safeParse(text);
    return res.json(parsed);
  } catch (err: any) {
    const msg = (err && (err.name || err.message)) ? `${err.name || ''} ${err.message || ''}`.trim() : 'unknown error';
    return res.json({
      summary: `I couldn't reach the model (${msg}). Check the Bedrock credentials, region (${REGION}), and model access on the server.`,
      tables: [], error: true,
    });
  }
});

// The model is told to return raw JSON; strip stray fences and parse defensively.
function safeParse(text: string) {
  let t = (text || '').trim();
  if (t.startsWith('```')) t = t.replace(/^```(?:json)?/i, '').replace(/```$/i, '').trim();
  const a = t.indexOf('{'); const b = t.lastIndexOf('}');
  if (a >= 0 && b > a) t = t.slice(a, b + 1);
  try {
    const o = JSON.parse(t);
    return {
      summary: typeof o.summary === 'string' ? o.summary : '',
      tables: Array.isArray(o.tables) ? o.tables.filter((tb: any) => tb && Array.isArray(tb.columns) && Array.isArray(tb.rows)) : [],
      note: typeof o.note === 'string' ? o.note : undefined,
    };
  } catch {
    return { summary: text || 'No response.', tables: [] };
  }
}
