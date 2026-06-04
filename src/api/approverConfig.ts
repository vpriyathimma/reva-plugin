// Approver directory — a list of known approver emails plus a single selected
// approver. The selected approver receives ALL approval requests for now
// (quarantine reinstatement, short-lived SVID tokens, etc.) — there is no
// per-osUser mapping.
//
// The known-approver list seeds from env (REVA_APPROVERS, comma-separated) or a
// sensible default, and can be extended at runtime. `selected` is what the
// console sets via the Approver dropdown.

import { Router, Request, Response } from 'express';

const seed = (process.env.REVA_APPROVERS || 'sai.srungaram@reva.ai,yash.prakash@reva.ai')
  .split(',').map((s) => s.trim()).filter(Boolean);

let knownApprovers: string[] = Array.from(new Set(seed));
let selectedApprover: string = knownApprovers[0] || '';

export function getKnownApprovers(): string[] { return knownApprovers; }
export function getSelectedApprover(): string { return selectedApprover; }

// Single global approver — osUser is ignored (kept for signature compatibility).
export function getApproverFor(_osUser?: string): string {
  return selectedApprover || knownApprovers[0] || '';
}

export function addApprover(email: string): void {
  if (email && !knownApprovers.includes(email)) knownApprovers.push(email);
}

export const approverConfigRouter = Router();

approverConfigRouter.get('/config/approvers', (_req: Request, res: Response) => {
  res.json({ approvers: knownApprovers, selected: selectedApprover });
});

approverConfigRouter.post('/config/approvers', (req: Request, res: Response) => {
  const body = req.body || {};
  if (Array.isArray(body.approvers)) {
    knownApprovers = Array.from(new Set(body.approvers.map((s: any) => String(s).trim()).filter(Boolean)));
    if (selectedApprover && !knownApprovers.includes(selectedApprover)) knownApprovers.push(selectedApprover);
  }
  if (typeof body.selected === 'string' && body.selected.trim()) {
    selectedApprover = body.selected.trim();
    if (!knownApprovers.includes(selectedApprover)) knownApprovers.push(selectedApprover);
  }
  console.log(`[CONFIG:approvers] selected=${selectedApprover} approvers=${knownApprovers.length}`);
  res.json({ approvers: knownApprovers, selected: selectedApprover });
});
