// ============================================================================
// Reva — Adaptive Access Isolation (AAI) API   (src/api/aai.ts)
// ----------------------------------------------------------------------------
// Read-only API that feeds the Home page's AAI board. Returns the full 25-policy
// OOTB catalog, with each policy's live isolated principals merged in from the
// quarantine ledger (grouped by policyId) — the exact same source that drives the
// principals shown under quarantine policies today. All 25 are live; a policy
// with no current isolations simply returns an empty principals[].
//
// Mount: app.use('/api', aaiRouter)   // see src/index.ts
//
// Endpoints (GET):
//   /api/aai/policies            full catalog + live principals + rollups
//   /api/aai/policies/:policyId  one policy + its live principals
// ============================================================================

import { Router } from 'express';
import { listQuarantines } from './quarantine';

// ── Category metadata ────────────────────────────────────────────────────────
const CATEGORIES: Record<string, string> = {
  rbp: 'Runtime Behavioral Protection',
  iaa: 'Identity-Aware Access',
  mwb: 'Malicious Website Blocking',
  uap: 'Unsafe Action Prevention',
  aig: 'AI Governance',
};

// ── OOTB catalog — 25 policies (definitions only; principals are live) ───────
interface PolicyDef { id: string; name: string; category: string; resolution: string; }
const CATALOG: PolicyDef[] = [
  // Runtime Behavioral Protection
  { id: 'AAI-RBP-001', name: 'Tool Invocation Surge',        category: 'rbp', resolution: 'Auto Restore' },
  { id: 'AAI-RBP-002', name: 'High Denial Rate',             category: 'rbp', resolution: 'Conditional Grant' },
  { id: 'AAI-RBP-003', name: 'Ephemeral Agent Surge',        category: 'rbp', resolution: 'Auto Restore' },
  { id: 'AAI-RBP-004', name: 'Data exfiltration pattern',    category: 'rbp', resolution: 'Conditional Grant' },
  { id: 'AAI-RBP-005', name: 'HITL timeout escalation',      category: 'rbp', resolution: 'Access Review' },
  // Identity-Aware Access
  { id: 'AAI-IAA-001', name: 'Authentication failure lockout', category: 'iaa', resolution: 'Auto Restore' },
  { id: 'AAI-IAA-002', name: 'Impossible travel detection',  category: 'iaa', resolution: 'Conditional Grant' },
  { id: 'AAI-IAA-003', name: 'Dormant access reactivation',  category: 'iaa', resolution: 'Access Review' },
  { id: 'AAI-IAA-004', name: 'Session concurrency anomaly',  category: 'iaa', resolution: 'Auto Restore' },
  { id: 'AAI-IAA-005', name: 'NHI token origin anomaly',     category: 'iaa', resolution: 'Conditional Grant' },
  // Malicious Website Blocking
  { id: 'AAI-MWB-001', name: 'Malicious URL access attempt', category: 'mwb', resolution: 'Auto Restore' },
  { id: 'AAI-MWB-002', name: 'MCP server untrusted redirect', category: 'mwb', resolution: 'Conditional Grant' },
  { id: 'AAI-MWB-003', name: 'Phishing content in agent output', category: 'mwb', resolution: 'Access Review' },
  { id: 'AAI-MWB-004', name: 'Unapproved external API call', category: 'mwb', resolution: 'Manual Grant' },
  // Unsafe Action Prevention
  { id: 'AAI-UAP-001', name: 'Prompt injection detection',   category: 'uap', resolution: 'Conditional Grant' },
  { id: 'AAI-UAP-002', name: 'PII / sensitive data exposure', category: 'uap', resolution: 'Access Review' },
  { id: 'AAI-UAP-003', name: 'Destructive operation attempt', category: 'uap', resolution: 'Manual Grant' },
  { id: 'AAI-UAP-004', name: 'Privilege escalation attempt', category: 'uap', resolution: 'Conditional Grant' },
  // AI Governance
  { id: 'AAI-AIG-001', name: 'Certification dispute hold',   category: 'aig', resolution: 'Access Review' },
  { id: 'AAI-AIG-002', name: 'SoD conflict detection',       category: 'aig', resolution: 'Access Review' },
  { id: 'AAI-AIG-003', name: 'Incident Blast Radius',        category: 'aig', resolution: 'Manual Grant' },
  { id: 'AAI-AIG-004', name: 'Model drift detection',        category: 'aig', resolution: 'Conditional Grant' },
  { id: 'AAI-AIG-005', name: 'Unregistered tool exposure',   category: 'aig', resolution: 'Manual Grant' },
  { id: 'AAI-AIG-006', name: 'Delegation chain depth breach', category: 'aig', resolution: 'Manual Grant' },
  { id: 'AAI-AIG-007', name: 'Scope creep — unmanifested tool', category: 'aig', resolution: 'Conditional Grant' },
];

// ── Live principals from the quarantine ledger, grouped by policyId ──────────
// Mirrors the dashboard's merge: one principal per quarantine record on that
// policy, shaped { pid, type, trigger, reason, quarantineSec, status }.
interface Principal { pid: string; type: string; trigger: string; reason: string; quarantineSec: number; status: string; }

function livePrincipalsByPolicy(): Record<string, Principal[]> {
  const out: Record<string, Principal[]> = {};
  listQuarantines().forEach((q) => {
    const p: Principal = {
      pid: 'user:' + q.osUser,
      type: 'User',
      trigger: 'Runtime',
      reason: q.reason || q.policyName,
      quarantineSec: q.expiresAt ? Math.max(0, Math.round((q.expiresAt - Date.now()) / 1000)) : 0,
      status: q.status,
    };
    (out[q.policyId] = out[q.policyId] || []).push(p);
  });
  return out;
}

function statusBreakdown(principals: Principal[]): Record<string, number> {
  const by: Record<string, number> = {};
  principals.forEach((p) => { by[p.status] = (by[p.status] || 0) + 1; });
  return by;
}

function hydrate(def: PolicyDef, live: Record<string, Principal[]>) {
  const principals = live[def.id] || [];
  return {
    id: def.id,
    name: def.name,
    category: def.category,
    categoryLabel: CATEGORIES[def.category] || def.category,
    resolution: def.resolution,
    live: true,
    isolatedCount: principals.length,
    byStatus: statusBreakdown(principals),
    principals,
  };
}

// ── Router ───────────────────────────────────────────────────────────────────
export const aaiRouter = Router();

// Full catalog + live principals + category rollups
aaiRouter.get('/aai/policies', (req, res) => {
  const live = livePrincipalsByPolicy();
  let catalog = CATALOG;
  const cat = req.query.category ? String(req.query.category).toLowerCase() : '';
  if (cat) catalog = catalog.filter((p) => p.category === cat);

  const policies = catalog.map((p) => hydrate(p, live));
  const totalIsolated = policies.reduce((n, p) => n + p.isolatedCount, 0);

  const categories = Object.keys(CATEGORIES).map((key) => {
    const inCat = policies.filter((p) => p.category === key);
    return {
      key,
      label: CATEGORIES[key],
      policyCount: CATALOG.filter((p) => p.category === key).length,
      isolatedCount: inCat.reduce((n, p) => n + p.isolatedCount, 0),
    };
  });

  res.json({
    categories,
    totalPolicies: catalog.length,
    totalIsolated,
    policies,
    generatedAt: new Date().toISOString(),
  });
});

// One policy + its live principals
aaiRouter.get('/aai/policies/:policyId', (req, res) => {
  const def = CATALOG.find((p) => p.id.toLowerCase() === String(req.params.policyId).toLowerCase());
  if (!def) return res.status(404).json({ error: 'policy not found', policyId: req.params.policyId });
  res.json(hydrate(def, livePrincipalsByPolicy()));
});
