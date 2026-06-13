// SVID — Short-Lived Credential for Privileged Operations
// Issued after HITL approval for actions like git push, merge, PR creation
// TTL configurable (default 10 minutes)
// Cryptographically represents: this developer is authorized for this action, right now

import crypto from 'crypto';

export interface SVIDRecord {
  id:              string;
  developer_email: string;
  action:          string;
  project:         string;
  spiffe_id:       string;
  issued_at:       string;
  expires_at:      string;
  issued_by:       string;   // approver who triggered the issuance
  status:          'active' | 'expired' | 'revoked';
  jwt:             string;  // Real JWT SVID from SPIRE
  // Session attachment — a JIT credential belongs to the session that earned it,
  // not to the developer at large. Lets the dashboard render it under the session
  // and lets quarantine/terminate revoke it by session or by (developer × agent).
  session_id?:     string;
  coding_agent?:   string;   // claude-code | codex | kiro
  os_user?:        string;   // OS username, for agent-scoped revocation
}

// In-memory SVID store
const svidStore = new Map<string, SVIDRecord>();

// Default TTL: 10 minutes
const SVID_TTL_MINUTES = parseInt(process.env.SVID_TTL_MINUTES || '10', 10);

const SPIRE_API_URL = process.env.SPIRE_API_URL || 'http://3.233.113.248:8090';

// ── Issue SVID via SPIRE ──
export async function issueSVID(params: {
  developer_email: string;
  action:          string;
  project:         string;
  spiffe_id:       string;
  issued_by:       string;
  account_uuid?:   string;
  session_id?:     string;
  coding_agent?:   string;
  os_user?:        string;
}): Promise<SVIDRecord> {
  const now = new Date();
  const expires = new Date(now.getTime() + SVID_TTL_MINUTES * 60 * 1000);

  // Extract accountUuid from spiffe_id: spiffe://reva.ai/agent/claude-code/dev/{uuid}
  const accountUuid = params.account_uuid
    || params.spiffe_id.split('/').pop()
    || '';

  let jwt = '';

  // Call SPIRE to mint real JWT SVID
  if (accountUuid) {
    try {
      const resp = await fetch(`${SPIRE_API_URL}/mint/${accountUuid}`, {
        signal: AbortSignal.timeout(5000),
      });
      if (resp.ok) {
        const data = await resp.json() as any;
        jwt = data.svid || '';
        console.log(`[SVID] SPIRE minted JWT for ${accountUuid} — ${jwt.slice(0, 30)}...`);
      } else {
        console.warn(`[SVID] SPIRE mint failed: HTTP ${resp.status}`);
      }
    } catch (err: any) {
      console.warn(`[SVID] SPIRE mint error: ${err.message}`);
    }
  }

  const svid: SVIDRecord = {
    id:              `svid-${crypto.randomBytes(8).toString('hex')}`,
    developer_email: params.developer_email,
    action:          params.action,
    project:         params.project,
    spiffe_id:       params.spiffe_id,
    issued_at:       now.toISOString(),
    expires_at:      expires.toISOString(),
    issued_by:       params.issued_by,
    status:          'active',
    jwt,
    session_id:      params.session_id,
    coding_agent:    params.coding_agent || 'claude-code',
    os_user:         params.os_user,
  };

  const key = svidKey(params.developer_email, params.project);
  svidStore.set(key, svid);

  console.log(`[SVID] Issued: ${svid.id} for ${params.developer_email} on ${params.project} — expires ${svid.expires_at}, jwt=${jwt ? 'yes' : 'no'}`);
  return svid;
}

// ── Validate SVID ──
export function validateSVID(developerEmail: string, project: string): SVIDRecord | null {
  const key = svidKey(developerEmail, project);
  const svid = svidStore.get(key);

  if (!svid) return null;

  // Check expiry
  if (new Date(svid.expires_at) < new Date()) {
    svid.status = 'expired';
    svidStore.set(key, svid);
    console.log(`[SVID] Expired: ${svid.id} for ${developerEmail} on ${project}`);
    return null;
  }

  if (svid.status !== 'active') return null;

  return svid;
}

// ── Revoke SVID ──
export function revokeSVID(developerEmail: string, project: string): boolean {
  const key = svidKey(developerEmail, project);
  const svid = svidStore.get(key);
  if (!svid) return false;

  svid.status = 'revoked';
  svidStore.set(key, svid);
  console.log(`[SVID] Revoked: ${svid.id} for ${developerEmail} on ${project}`);
  return true;
}

// ── Revoke every ACTIVE JIT credential attached to a session ──
// Used when a session is terminated or quarantined: the credential dies with the
// session. Expired/already-revoked records are left untouched.
export function revokeSVIDsForSession(sessionId: string): number {
  if (!sessionId) return 0;
  let n = 0;
  for (const [, svid] of svidStore) {
    if (svid.session_id === sessionId && svid.status === 'active') {
      svid.status = 'revoked';
      n++;
      console.log(`[SVID] Revoked (session terminated): ${svid.id} session=${sessionId}`);
    }
  }
  return n;
}

// ── Revoke active JIT for a (developer × coding agent) ──
// Quarantine is scoped to one coding agent, so only that agent's credentials are
// revoked. `candidates` are the developer's identity forms (os_user, email,
// local-part); any active SVID whose coding_agent matches and whose owner is in
// `candidates` is revoked. Returns the number revoked.
export function revokeSVIDsForAgent(candidates: string[], codingAgent: string): number {
  const cand = new Set(candidates.filter(Boolean).map((c) => String(c).toLowerCase()));
  const agent = codingAgent || 'claude-code';
  let n = 0;
  for (const [, svid] of svidStore) {
    if (svid.status !== 'active') continue;
    if ((svid.coding_agent || 'claude-code') !== agent) continue;
    const owners = [svid.os_user, svid.developer_email, (svid.developer_email || '').split('@')[0]]
      .filter(Boolean).map((o) => String(o).toLowerCase());
    if (owners.some((o) => cand.has(o) || cand.has(o.split('@')[0]))) {
      svid.status = 'revoked';
      n++;
      console.log(`[SVID] Revoked (quarantine): ${svid.id} agent=${agent} owner=${svid.developer_email}`);
    }
  }
  return n;
}

// ── Get SVID details (for dashboard/logs) ──
export function getSVIDDetails(developerEmail: string, project: string): SVIDRecord | null {
  const key = svidKey(developerEmail, project);
  return svidStore.get(key) || null;
}

// ── List all active SVIDs ──
export function listActiveSVIDs(): SVIDRecord[] {
  const now = new Date();
  const active: SVIDRecord[] = [];
  for (const svid of svidStore.values()) {
    if (svid.status === 'active' && new Date(svid.expires_at) > now) {
      active.push(svid);
    }
  }
  return active;
}

// ── List ALL SVIDs (active + expired + revoked) — powers the JIT ledger ──
// Lazily refreshes status for any SVID whose TTL has lapsed so the ledger never
// reports a stale "active". The store is keyed by (developer_email::project), so
// this returns the most recent issuance per (developer, project) pair.
export function listAllSVIDs(): SVIDRecord[] {
  const now = new Date();
  const all: SVIDRecord[] = [];
  for (const [key, svid] of svidStore) {
    if (svid.status === 'active' && new Date(svid.expires_at) < now) {
      svid.status = 'expired';
      svidStore.set(key, svid);
    }
    all.push(svid);
  }
  return all;
}

// ── Classify privileged commands ──
export function isPrivilegedCommand(command: string): { privileged: boolean; type: string } {
  const cmd = command.trim().toLowerCase();

  if (/git\s+push/.test(cmd)) return { privileged: true, type: 'push' };
  if (/git\s+merge/.test(cmd)) return { privileged: true, type: 'merge' };
  if (/gh\s+pr\s+create/.test(cmd)) return { privileged: true, type: 'pr_create' };
  if (/gh\s+pr\s+merge/.test(cmd)) return { privileged: true, type: 'pr_merge' };
  if (/git\s+tag/.test(cmd)) return { privileged: true, type: 'tag' };

  return { privileged: false, type: 'none' };
}

// ── Helpers ──
function svidKey(email: string, project: string): string {
  return `${email}::${project}`;
}

// Clean up expired SVIDs periodically
setInterval(() => {
  const now = new Date();
  for (const [key, svid] of svidStore) {
    if (svid.status === 'active' && new Date(svid.expires_at) < now) {
      svid.status = 'expired';
      svidStore.set(key, svid);
    }
  }
}, 60_000);
