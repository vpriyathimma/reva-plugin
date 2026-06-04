// Security feature flags — the five detectors shown on the Settings tab.
// Default ALL ON, so day-one behaviour is byte-for-byte what runs today; the
// gates only change behaviour when an admin deliberately turns one OFF.
//
//   prompt_injection         OFF -> no injection scoring, no injection context
//                                   attributes, and NO prompt-injection entries
//                                   in the decision log (Claude Code blocks it
//                                   anyway — Reva just stops attributing it).
//   intent_drift             OFF -> no drift compute, neutral intent attributes,
//                                   no intent-drift entries in the decision log.
//   commands_classification  OFF -> RunBash command-risk classification disabled.
//   file_sensitivity         OFF -> file_zone classification disabled.
//   quarantine_access        OFF -> no new quarantine clips fire.

import { Router, Request, Response } from 'express';

export interface SecurityConfig {
  prompt_injection:        boolean;
  intent_drift:            boolean;
  commands_classification: boolean;
  file_sensitivity:        boolean;
  quarantine_access:       boolean;
}

let securityConfig: SecurityConfig = {
  prompt_injection:        true,
  intent_drift:            true,
  commands_classification: true,
  file_sensitivity:        true,
  quarantine_access:       true,
};

export function getSecurityConfig(): SecurityConfig { return securityConfig; }

export function isEnabled(key: keyof SecurityConfig): boolean {
  return securityConfig[key] !== false;
}

export function updateSecurityConfig(patch: Partial<SecurityConfig>): SecurityConfig {
  securityConfig = { ...securityConfig, ...patch };
  console.log(`[CONFIG:security] ${JSON.stringify(securityConfig)}`);
  return securityConfig;
}

export const securityConfigRouter = Router();

securityConfigRouter.get('/config/security', (_req: Request, res: Response) => {
  res.json(getSecurityConfig());
});

securityConfigRouter.post('/config/security', (req: Request, res: Response) => {
  const body = req.body || {};
  const patch: Partial<SecurityConfig> = {};
  (['prompt_injection', 'intent_drift', 'commands_classification', 'file_sensitivity', 'quarantine_access'] as const)
    .forEach((k) => { if (typeof body[k] === 'boolean') patch[k] = body[k]; });
  res.json(updateSecurityConfig(patch));
});
