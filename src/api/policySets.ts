// Policy-set registry for the Policies tab.
//
// These 15 sets are a presentation/control-plane grouping of the underlying
// Cedar policies. This module ONLY stores the set list + each set's enabled
// flag (all default ON = today's behavior). It does NOT touch the evaluation
// path or the PDP — toggling here records intent for the (later) context-guard
// wiring. Nothing in the live decision flow reads this yet, so enabling it
// cannot change current enforcement.

import { Router, Request, Response } from 'express';

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export interface PolicySet {
  id: string;
  name: string;
  description: string;
  risk: RiskLevel;
  enabled: boolean;
}

const SETS: PolicySet[] = [
  { id: 'prompt_injection_protection', name: 'Prompt Injection Protection', risk: 'Critical',
    description: 'Blocks prompt submission when injection or jailbreak content is detected.', enabled: true },
  { id: 'baseline_safety_controls', name: 'Baseline Safety Controls', risk: 'Critical',
    description: 'Global floor that blocks all actions on a high injection score or critically low trust.', enabled: true },
  { id: 'intent_drift_validation', name: 'Intent Drift Validation', risk: 'High',
    description: 'Blocks command execution when activity drifts from the declared intent.', enabled: true },
  { id: 'destructive_command_control', name: 'Destructive Command Control', risk: 'High',
    description: 'Blocks shell commands classified as destructive.', enabled: true },
  { id: 'ephemeral_agent_protection', name: 'Ephemeral Agent Protection', risk: 'High',
    description: 'Prevents spawned subagents from modifying files.', enabled: true },
  { id: 'protected_branch_control', name: 'Protected Branch Control', risk: 'High',
    description: 'Blocks edits on protected branches without approver consent.', enabled: true },
  { id: 'itsm_change_control', name: 'ITSM Change Control', risk: 'Medium',
    description: 'Requires a valid in-progress change ticket before code changes.', enabled: true },
  { id: 'identity_integrity_evaluation', name: 'Identity Integrity Evaluation', risk: 'High',
    description: 'Blocks edits when committer or assignee identity does not match the authenticated user.', enabled: true },
  { id: 'environment_based_access_control', name: 'Environment-Based Access Control', risk: 'High',
    description: 'Restricts protected-project changes to secure SSH sessions.', enabled: true },
  { id: 'conditional_access_grants', name: 'Conditional Access Grants', risk: 'High',
    description: 'Grants edit, write, and command access only when verified conditions are met.', enabled: true },
  { id: 'sensitive_file_access_control', name: 'Sensitive File Access Control', risk: 'High',
    description: 'Requires AppSec review before edits to secret or config files.', enabled: true },
  { id: 'safe_command_access', name: 'Safe Command Access', risk: 'Low',
    description: 'Allows low-risk shell commands for verified, active sessions.', enabled: true },
  { id: 'read_access_grants', name: 'Read Access Grants', risk: 'Low',
    description: 'Allows read-only access to files and MCP tools.', enabled: true },
  { id: 'mcp_tool_governance', name: 'MCP Tool Governance', risk: 'High',
    description: 'Governs MCP tool write and execute operations.', enabled: true },
  { id: 'ephemeral_agent_spawn_control', name: 'Ephemeral Agent Spawn Control', risk: 'Medium',
    description: 'Controls when an agent may spawn subagents.', enabled: true },
];

export function getPolicySets(): PolicySet[] { return SETS; }

export const policySetsRouter = Router();

policySetsRouter.get('/config/policy-sets', (_req: Request, res: Response) => {
  res.json({ sets: SETS });
});

// Toggle a single set: { id, enabled }
policySetsRouter.post('/config/policy-sets', (req: Request, res: Response) => {
  const { id, enabled } = req.body || {};
  const set = SETS.find((s) => s.id === id);
  if (!set) return res.status(404).json({ error: 'unknown policy set', id });
  if (typeof enabled === 'boolean') set.enabled = enabled;
  console.log(`[CONFIG:policy-sets] ${set.id} enabled=${set.enabled}`);
  res.json({ sets: SETS });
});
