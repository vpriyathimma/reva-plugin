// Approver directory — a shared list of approver emails plus an osUser→approver
// mapping. Used both for Slack HITL approval addressing and for quarantine
// reinstatement approvals, so a single approver selection drives both flows.
//
// The known-approver list seeds from env (REVA_APPROVERS, comma-separated) or a
// sensible default, and can be extended at runtime. The map is what the console
// edits via the Slack "Approver email mapping" dropdown.

import { Router, Request, Response } from 'express';

const seed = (process.env.REVA_APPROVERS || 'sai.srungaram@reva.ai,yash.prakash@reva.ai')
  .split(',').map((s) => s.trim()).filter(Boolean);

let knownApprovers: string[] = Array.from(new Set(seed));
let approverMap: Record<string, string> = {};  // osUser -> approver email

export function getKnownApprovers(): string[] { return knownApprovers; }
export function getApproverMap(): Record<string, string> { return approverMap; }

// Resolve the approver for a developer; falls back to the first known approver.
export function getApproverFor(osUser: string): string {
  if (!osUser) return knownApprovers[0] || '';
  const key = String(osUser).toLowerCase();
  return approverMap[key] || approverMap[key.split('@')[0]] || knownApprovers[0] || '';
}

export function addApprover(email: string): void {
  if (email && !knownApprovers.includes(email)) knownApprovers.push(email);
}

export const approverConfigRouter = Router();

approverConfigRouter.get('/config/approvers', (_req: Request, res: Response) => {
  res.json({ approvers: knownApprovers, map: approverMap });
});

approverConfigRouter.post('/config/approvers', (req: Request, res: Response) => {
  const body = req.body || {};
  if (Array.isArray(body.approvers)) {
    knownApprovers = Array.from(new Set(body.approvers.map((s: any) => String(s).trim()).filter(Boolean)));
  }
  if (body.map && typeof body.map === 'object') {
    const next: Record<string, string> = {};
    for (const [k, v] of Object.entries(body.map)) {
      if (!k || !v) continue;
      const email = String(v).trim();
      next[String(k).toLowerCase()] = email;
      if (!knownApprovers.includes(email)) knownApprovers.push(email);
    }
    approverMap = next;
  }
  console.log(`[CONFIG:approvers] approvers=${knownApprovers.length} map=${JSON.stringify(approverMap)}`);
  res.json({ approvers: knownApprovers, map: approverMap });
});
