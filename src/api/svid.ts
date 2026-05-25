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
