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
  codingAgent: string;       // claude-code | codex | kiro — quarantine is scoped per agent
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

// Quarantine state, scoped per (developer × coding agent). A clip from Claude Code
// quarantines ONLY the developer's Claude Code access — Codex and Kiro stay live.
const quarantineStore = new Map<string, QuarantineRecord>();

function qKey(osUser: string, codingAgent?: string): string {
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
export function isQuarantined(osUser: string, codingAgent?: string): QuarantineRecord | null {
  if (!osUser) return null;
  const key = qKey(osUser, codingAgent);
  const rec = quarantineStore.get(key);
  if (!rec) return null;
  // Auto-Restore expiry check (lazy, in addition to the timer below)
  if (rec.expiresAt && Date.now() >= rec.expiresAt) {
    quarantineStore.delete(key);
    emitReva({ type: 'quarantine' });
    return null;
  }
  return rec;
}

export function clip(params: {
  osUser: string; codingAgent?: string; policyId: string; reason: string; status?: QuarantineStatus;
}): QuarantineRecord | null {
  const def = POLICY_DEFS[params.policyId];
  if (!def || !params.osUser) return null;
  const codingAgent = params.codingAgent || 'claude-code';
  const key = qKey(params.osUser, codingAgent);
  // Do not downgrade an existing prompt-tier (revoke) quarantine to a tool-call one.
  const existing = quarantineStore.get(key);
  if (existing && existing.tier === 'prompt' && def.tier === 'toolcall') return existing;

  const now = Date.now();
  const rec: QuarantineRecord = {
    osUser:     params.osUser,
    codingAgent,
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
  quarantineStore.set(key, rec);
  console.log(`[QUARANTINE] clip ${params.osUser} (${codingAgent}) via ${def.id} (${def.name}) tier=${def.tier} resolution=${def.resolution}`);

  // A quarantined session can't act — so its short-lived (JIT) credentials are
  // revoked immediately. Scoped to this coding agent only. Lazy require avoids a
  // load-order cycle and never throws into the clip path.
  try {
    const { revokeSVIDsForAgent } = require('./svid');
    const n = revokeSVIDsForAgent([params.osUser, params.osUser.split('@')[0]], codingAgent);
    if (n) console.log(`[QUARANTINE] revoked ${n} JIT credential(s) for ${params.osUser} (${codingAgent})`);
  } catch (e: any) { console.warn(`[QUARANTINE] JIT revoke skipped: ${e?.message}`); }

  emitReva({ type: 'quarantine' });
  return rec;
}

export function reinstate(osUser: string, codingAgent?: string): boolean {
  const key = qKey(osUser, codingAgent);
  const had = quarantineStore.delete(key);
  if (had) {
    console.log(`[QUARANTINE] reinstate ${osUser} (${codingAgent || 'claude-code'})`);
    emitReva({ type: 'quarantine' });
  }
  return had;
}

export function listQuarantines(): QuarantineRecord[] {
  // sweep expired auto-restores first
  const now = Date.now();
  for (const [u, r] of quarantineStore) {
    if (r.expiresAt && now >= r.expiresAt) { quarantineStore.delete(u); emitReva({ type: 'quarantine' }); }
  }
  return Array.from(quarantineStore.values());
}

// Auto-Restore sweep — lifts expired surge quarantines on a timer.
setInterval(() => {
  const now = Date.now();
  for (const [u, r] of quarantineStore) {
    if (r.expiresAt && now >= r.expiresAt) {
      quarantineStore.delete(u);
      console.log(`[QUARANTINE] auto-restore ${u} (${r.policyId})`);
      emitReva({ type: 'quarantine' });
    }
  }
}, 15_000);

// ── API ──
export const quarantineRouter = Router();

quarantineRouter.get('/quarantine', (_req: Request, res: Response) => {
  res.json({
    policies:   Object.values(POLICY_DEFS),
    quarantined: listQuarantines(),
    capped_sessions: Array.from(sessionSpawn.entries()).filter(([, v]) => v.capped).map(([sid]) => sid),
    spawn_limit: SPAWN_LIMIT,
    total:      quarantineStore.size,
  });
});

// Manual clip (e.g. Incident Blast Radius from the AAI board "Review"/clip action)
quarantineRouter.post('/quarantine/clip', (req: Request, res: Response) => {
  const { osUser, codingAgent, policyId, reason } = req.body || {};
  if (!osUser || !policyId) return res.status(400).json({ ok: false, error: 'osUser and policyId required' });
  const rec = clip({ osUser, codingAgent, policyId, reason: reason || 'Manually clipped from console' });
  if (!rec) return res.status(400).json({ ok: false, error: 'Unknown policyId' });
  res.json({ ok: true, record: rec });
});

// Reinstate — Manual Admin Grant (direct) or after HITL approval.
quarantineRouter.post('/quarantine/reinstate', (req: Request, res: Response) => {
  const { osUser, codingAgent } = req.body || {};
  if (!osUser) return res.status(400).json({ ok: false, error: 'osUser required' });
  const ok = reinstate(osUser, codingAgent);
  res.json({ ok, reinstated: ok ? osUser : null });
});

// Send an approval request for a quarantined principal. Approvals land in the
// configured Slack channel; if Slack isn't configured we report that so the UI
// can prompt the admin to configure it (we do NOT silently fake an approval).
quarantineRouter.post('/quarantine/request-approval', async (req: Request, res: Response) => {
  const { osUser, codingAgent } = req.body || {};
  if (!osUser) return res.status(400).json({ ok: false, error: 'osUser required' });
  const agent = codingAgent || 'claude-code';
  const rec = quarantineStore.get(qKey(osUser, agent));
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
