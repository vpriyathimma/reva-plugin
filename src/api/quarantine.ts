// Adaptive Access Isolation — the four policies shown on the AAI board home.
// No separate isolation policy store exists, so the four definitions are pinned
// here as a constant and the live quarantine state is held developer-scoped
// (Developer::"<osUser>"). Subagents are ephemeral and are never quarantined.
//
// Two enforcement tiers:
//   tier 'prompt'   -> blocks at UserPromptSubmit (developer cannot enter ANY
//                      prompt, even in a fresh session). Used by Ephemeral Agent
//                      Surge (5-min window) and Incident Blast Radius (revoke).
//   tier 'toolcall' -> blocks tool calls only (prompts still work, so the
//                      developer sees the pending-approval message). Used by
//                      High Denial Rate and Prompt Injection (both HITL/Slack).
//
// Reinstate paths: Auto-Restore (timer), HITL (Slack approval), Manual Admin
// Grant (admin button -> direct restore).
//
// Developer-facing messages NEVER mention Reva / governance / policy / Cedar.

import { Router, Request, Response } from 'express';
import { emitReva } from './events';

export type Resolution = 'HITL' | 'Auto-Restore' | 'Manual Admin Grant';
export type Tier = 'prompt' | 'toolcall';

export interface PolicyDef {
  id:         string;
  name:       string;
  trigger:    'Runtime' | 'Manual';
  resolution: Resolution;
  tier:       Tier;
  ttlSec?:    number;   // Auto-Restore window
  message:    string;   // developer-facing, neutral
}

// The four policies, exactly as on the AAI board home card.
export const POLICY_DEFS: Record<string, PolicyDef> = {
  'AAI-RBP-002': {
    id: 'AAI-RBP-002', name: 'High Denial Rate', trigger: 'Runtime',
    resolution: 'HITL', tier: 'toolcall',
    message: 'Your access is on hold. Please reach out to your administrator to restore access.',
  },
  'AAI-UAP-001': {
    id: 'AAI-UAP-001', name: 'Prompt Injection Detection', trigger: 'Runtime',
    resolution: 'HITL', tier: 'toolcall',
    message: 'Your access is on hold. Please reach out to your administrator to restore access.',
  },
  'AAI-RBP-003': {
    id: 'AAI-RBP-003', name: 'Ephemeral Agent Surge', trigger: 'Runtime',
    resolution: 'Auto-Restore', tier: 'prompt', ttlSec: 300,
    message: 'Too many parallel agents were started. Access is paused for 5 minutes — please wait, then start a new session.',
  },
  'AAI-AIG-003': {
    id: 'AAI-AIG-003', name: 'Incident Blast Radius', trigger: 'Manual',
    resolution: 'Manual Admin Grant', tier: 'prompt',
    message: 'Your access is on hold. Please reach out to your administrator to restore access.',
  },
};

export type QuarantineStatus = 'Quarantined' | 'Awaiting resolution' | 'Auto-restoring' | 'Approval sent';

export interface QuarantineRecord {
  osUser:     string;
  codingAgent: string;       // claude-code | codex | kiro
  sessionId?: string;        // the offending session (runtime triggers); absent for agent-wide manual clips
  scope:      'session' | 'agent';
  policyId:   string;
  policyName: string;
  reason:     string;        // contextual detail for the console (not shown to the developer)
  message:    string;        // developer-facing, neutral
  tier:       Tier;
  resolution: Resolution;
  since:      string;        // ISO
  ttlSec?:    number;
  expiresAt?: number;        // epoch ms (Auto-Restore)
  status:     QuarantineStatus;
}

// Quarantine state.
//   • SESSION scope — runtime triggers (prompt injection, high denial rate,
//     ephemeral surge) quarantine ONLY the session where they fired. Keyed by
//     session_id. Other sessions of the same developer/agent are untouched.
//   • AGENT scope — a manual Incident Blast Radius clip isolates the whole
//     (developer × coding agent). Keyed by "<osUser>::<codingAgent>".
const sessionQuarantine = new Map<string, QuarantineRecord>();   // session_id → record
const agentQuarantine   = new Map<string, QuarantineRecord>();   // osUser::agent → record

function agentKey(osUser: string, codingAgent?: string): string {
  return `${osUser}::${codingAgent || 'claude-code'}`;
}

// Per-session spawn cap state (surge). Once a session hits the cap it stays
// capped for its whole life; a brand-new session starts clean.
const sessionSpawn = new Map<string, { count: number; capped: boolean }>();
export const SPAWN_LIMIT = 5;

// High Denial Rate (AAI-RBP-002) — measured over the current session.
// A minimum decision count avoids a single denial reading as 100%.
export const DENY_RATE_THRESHOLD = 0.70;
export const DENY_RATE_MIN_DECISIONS = 3;

// ── Spawn-cap helpers (used by the tool-call hook) ──
export function getSpawnState(sessionId: string) {
  return sessionSpawn.get(sessionId) || { count: 0, capped: false };
}
export function noteSpawn(sessionId: string): { count: number; capped: boolean; overLimit: boolean } {
  const s = sessionSpawn.get(sessionId) || { count: 0, capped: false };
  const next = s.count + 1;
  const overLimit = next > SPAWN_LIMIT;
  const capped = s.capped || overLimit;
  const rec = { count: Math.min(next, SPAWN_LIMIT + 1), capped };
  sessionSpawn.set(sessionId, rec);
  return { count: rec.count, capped: rec.capped, overLimit };
}
export function isSessionCapped(sessionId: string): boolean {
  return !!sessionSpawn.get(sessionId)?.capped;
}

// ── Quarantine core ──
// Resolve the quarantine that applies to a tool call: the session-scoped record
// for THIS session wins; otherwise an agent-wide record (manual incident) applies.
export function isQuarantined(osUser: string, codingAgent?: string, sessionId?: string): QuarantineRecord | null {
  if (sessionId) {
    const sRec = sessionQuarantine.get(sessionId);
    if (sRec) {
      if (sRec.expiresAt && Date.now() >= sRec.expiresAt) { sessionQuarantine.delete(sessionId); emitReva({ type: 'quarantine' }); }
      else return sRec;
    }
  }
  if (!osUser) return null;
  const aKey = agentKey(osUser, codingAgent);
  const aRec = agentQuarantine.get(aKey);
  if (!aRec) return null;
  if (aRec.expiresAt && Date.now() >= aRec.expiresAt) { agentQuarantine.delete(aKey); emitReva({ type: 'quarantine' }); return null; }
  return aRec;
}

// Is a specific session quarantined? (session-scoped record OR an agent-wide one
// covering its developer/agent). Used for per-session highlighting.
export function isSessionQuarantined(sessionId: string, osUser?: string, codingAgent?: string): QuarantineRecord | null {
  const sRec = sessionId ? sessionQuarantine.get(sessionId) : null;
  if (sRec) {
    if (sRec.expiresAt && Date.now() >= sRec.expiresAt) { sessionQuarantine.delete(sessionId); }
    else return sRec;
  }
  if (osUser) {
    const aRec = agentQuarantine.get(agentKey(osUser, codingAgent));
    if (aRec && !(aRec.expiresAt && Date.now() >= aRec.expiresAt)) return aRec;
  }
  return null;
}

export function clip(params: {
  osUser: string; codingAgent?: string; sessionId?: string; policyId: string; reason: string; status?: QuarantineStatus;
}): QuarantineRecord | null {
  const def = POLICY_DEFS[params.policyId];
  if (!def || !params.osUser) return null;
  const codingAgent = params.codingAgent || 'claude-code';
  const scope: 'session' | 'agent' = params.sessionId ? 'session' : 'agent';
  const store = scope === 'session' ? sessionQuarantine : agentQuarantine;
  const key   = scope === 'session' ? params.sessionId! : agentKey(params.osUser, codingAgent);

  // Do not downgrade an existing prompt-tier (revoke) quarantine to a tool-call one.
  const existing = store.get(key);
  if (existing && existing.tier === 'prompt' && def.tier === 'toolcall') return existing;

  const now = Date.now();
  const rec: QuarantineRecord = {
    osUser:     params.osUser,
    codingAgent,
    sessionId:  params.sessionId,
    scope,
    policyId:   def.id,
    policyName: def.name,
    reason:     params.reason,
    message:    def.message,
    tier:       def.tier,
    resolution: def.resolution,
    since:      new Date(now).toISOString(),
    ttlSec:     def.ttlSec,
    expiresAt:  def.ttlSec ? now + def.ttlSec * 1000 : undefined,
    status:     params.status || (def.resolution === 'Auto-Restore' ? 'Auto-restoring' : 'Quarantined'),
  };
  store.set(key, rec);
  console.log(`[QUARANTINE] clip ${params.osUser} (${codingAgent}) scope=${scope}${params.sessionId ? ' session=' + params.sessionId : ''} via ${def.id} (${def.name})`);

  // A quarantined session can't act — its short-lived (JIT) credentials are
  // revoked immediately. Session scope → that session's JIT; agent scope → all
  // of the agent's JIT. Lazy require avoids a load-order cycle.
  try {
    const svid = require('./svid');
    let n = 0;
    if (scope === 'session') n = svid.revokeSVIDsForSession(params.sessionId);
    else n = svid.revokeSVIDsForAgent([params.osUser, params.osUser.split('@')[0]], codingAgent);
    if (n) console.log(`[QUARANTINE] revoked ${n} JIT credential(s) (${scope})`);
  } catch (e: any) { console.warn(`[QUARANTINE] JIT revoke skipped: ${e?.message}`); }

  emitReva({ type: 'quarantine' });
  return rec;
}

// Reinstate. With sessionId → lift that session. Without → lift the agent-wide
// record AND any session-scoped records for that developer/agent (full restore).
export function reinstate(osUser: string, codingAgent?: string, sessionId?: string): boolean {
  let had = false;
  if (sessionId) {
    had = sessionQuarantine.delete(sessionId);
  } else {
    had = agentQuarantine.delete(agentKey(osUser, codingAgent));
    const agent = codingAgent || 'claude-code';
    for (const [sid, r] of sessionQuarantine) {
      if (r.osUser === osUser && (r.codingAgent || 'claude-code') === agent) { sessionQuarantine.delete(sid); had = true; }
    }
  }
  if (had) {
    console.log(`[QUARANTINE] reinstate ${osUser} (${codingAgent || 'claude-code'})${sessionId ? ' session=' + sessionId : ''}`);
    emitReva({ type: 'quarantine' });
  }
  return had;
}

export function listQuarantines(): QuarantineRecord[] {
  const now = Date.now();
  for (const [k, r] of sessionQuarantine) { if (r.expiresAt && now >= r.expiresAt) { sessionQuarantine.delete(k); emitReva({ type: 'quarantine' }); } }
  for (const [k, r] of agentQuarantine)   { if (r.expiresAt && now >= r.expiresAt) { agentQuarantine.delete(k);   emitReva({ type: 'quarantine' }); } }
  return [...sessionQuarantine.values(), ...agentQuarantine.values()];
}

// Auto-Restore sweep — lifts expired surge quarantines on a timer.
setInterval(() => {
  const now = Date.now();
  for (const [k, r] of sessionQuarantine) { if (r.expiresAt && now >= r.expiresAt) { sessionQuarantine.delete(k); console.log(`[QUARANTINE] auto-restore session=${k} (${r.policyId})`); emitReva({ type: 'quarantine' }); } }
  for (const [k, r] of agentQuarantine)   { if (r.expiresAt && now >= r.expiresAt) { agentQuarantine.delete(k);   console.log(`[QUARANTINE] auto-restore ${k} (${r.policyId})`);   emitReva({ type: 'quarantine' }); } }
}, 15_000);

// ── API ──
export const quarantineRouter = Router();

quarantineRouter.get('/quarantine', (_req: Request, res: Response) => {
  const list = listQuarantines();
  res.json({
    policies:   Object.values(POLICY_DEFS),
    quarantined: list,
    capped_sessions: Array.from(sessionSpawn.entries()).filter(([, v]) => v.capped).map(([sid]) => sid),
    spawn_limit: SPAWN_LIMIT,
    total:      list.length,
  });
});

// Manual clip (e.g. Incident Blast Radius from the AAI board "Review"/clip action).
// Pass sessionId to quarantine a single session; omit it for an agent-wide clip.
quarantineRouter.post('/quarantine/clip', (req: Request, res: Response) => {
  const { osUser, codingAgent, sessionId, policyId, reason } = req.body || {};
  if (!osUser || !policyId) return res.status(400).json({ ok: false, error: 'osUser and policyId required' });
  const rec = clip({ osUser, codingAgent, sessionId, policyId, reason: reason || 'Manually clipped from console' });
  if (!rec) return res.status(400).json({ ok: false, error: 'Unknown policyId' });
  res.json({ ok: true, record: rec });
});

// Reinstate — Manual Admin Grant (direct) or after HITL approval.
quarantineRouter.post('/quarantine/reinstate', (req: Request, res: Response) => {
  const { osUser, codingAgent, sessionId } = req.body || {};
  if (!osUser) return res.status(400).json({ ok: false, error: 'osUser required' });
  const ok = reinstate(osUser, codingAgent, sessionId);
  res.json({ ok, reinstated: ok ? osUser : null });
});

// Send an approval request for a quarantined principal. Approvals land in the
// configured Slack channel; if Slack isn't configured we report that so the UI
// can prompt the admin to configure it (we do NOT silently fake an approval).
quarantineRouter.post('/quarantine/request-approval', async (req: Request, res: Response) => {
  const { osUser, codingAgent, sessionId } = req.body || {};
  if (!osUser) return res.status(400).json({ ok: false, error: 'osUser required' });
  const agent = codingAgent || 'claude-code';
  const rec = isSessionQuarantined(sessionId || '', osUser, agent);
  if (!rec) return res.status(404).json({ ok: false, error: 'not quarantined' });

  const hitl = require('./hitlConfig').getHITLConfig();
  const slackReady = hitl && hitl.integration === 'slack' && hitl.slack_connected
    && hitl.slack_bot_token && (hitl.slack_channel_id || hitl.slack_channel);
  if (!slackReady) {
    return res.json({ ok: false, reason: 'slack_not_configured' });
  }

  let approver = '';
  try { approver = require('./approverConfig').getApproverFor(osUser); } catch {}
  const send = require('./hitlConfig').sendQuarantineApprovalMessage;
  const result = await send(hitl.slack_bot_token, hitl.slack_channel_id || hitl.slack_channel, {
    principal: `user:${osUser}`, codingAgent: agent, policyName: rec.policyName, approver, detail: rec.reason,
  });
  if (!result.ok) {
    console.warn(`[QUARANTINE] approval send failed for ${osUser}: ${result.error}`);
    return res.json({ ok: false, reason: 'slack_send_failed', error: result.error });
  }
  rec.status = 'Approval sent';
  console.log(`[QUARANTINE] approval requested for ${osUser} → Slack (approver=${approver || 'n/a'})`);
  res.json({ ok: true, sent: true, channel: hitl.slack_channel || hitl.slack_channel_id, approver });
});
