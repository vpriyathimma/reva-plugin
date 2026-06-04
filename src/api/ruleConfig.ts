// Developer Integration config — command classification + file-sensitivity zones.
// The editable "display form" (chips / globs) is the source of truth here and is
// projected into the enforcement rules used by pdpEvaluate. On boot the display
// form is PARSED from the existing enforcement defaults, so the console shows
// exactly what is enforced today — default behaviour is unchanged. Saves apply
// to all sessions on the next prompt (rules are read at call-time).

import { Router, Request, Response } from 'express';
import {
  getCommandRules, setCommandRules,
  getFileZoneRules, setFileZoneRules,
} from './pdpEvaluate';

// ── Command classification (Safe / Restricted / Destructive) ──
interface CommandDisplay { safe: string[]; restricted: string[]; destructive: string[]; }

function splitPattern(p: string): string[] {
  return (p || '').split('|').map((s) => s.trim()).filter(Boolean);
}
function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Parse current enforcement rules into display chips (no behaviour change).
function readCommandDisplay(): CommandDisplay {
  const rules = getCommandRules();
  const find = (risk: string) => {
    const r = rules.find((x) => x.risk === risk);
    return r ? splitPattern(r.pattern) : [];
  };
  return {
    safe:        find('safe'),
    restricted:  find('restricted'),
    destructive: find('destructive'),
  };
}

// Project display chips back into enforcement rules. Order matters: destructive
// and restricted are evaluated before the (harmless) trailing safe rule.
function writeCommandDisplay(d: CommandDisplay): void {
  const rule = (chips: string[], risk: 'safe' | 'restricted' | 'destructive') =>
    ({ pattern: chips.map((c) => escapeRe(c.toLowerCase())).join('|'), risk });
  const rules: any[] = [];
  if (d.destructive?.length) rules.push(rule(d.destructive, 'destructive'));
  if (d.restricted?.length)  rules.push(rule(d.restricted, 'restricted'));
  if (d.safe?.length)        rules.push(rule(d.safe, 'safe'));
  setCommandRules(rules);
}

// ── File sensitivity zones ──
interface ZoneDisplay { zone: string; tone: string; globs: string[]; desc: string; }

const ZONE_META: Record<string, { tone: string; desc: string }> = {
  secrets: { tone: 'red',   desc: 'Read denied to agents' },
  config:  { tone: 'amber', desc: 'Drift-monitored' },
  tests:   { tone: 'blue',  desc: 'Test files' },
  src:     { tone: 'blue',  desc: 'Default working zone' },
  docs:    { tone: 'green', desc: 'Freely readable' },
};

function glob2re(g: string): string {
  return g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*');
}

function readZoneDisplay(): ZoneDisplay[] {
  return getFileZoneRules().map((r) => ({
    zone: r.zone,
    tone: ZONE_META[r.zone]?.tone || 'blue',
    globs: splitPattern(r.pattern),
    desc: ZONE_META[r.zone]?.desc || '',
  }));
}
function writeZoneDisplay(zones: ZoneDisplay[]): void {
  setFileZoneRules(zones.map((z) => ({ pattern: z.globs.map(glob2re).join('|'), zone: z.zone })));
}

export const ruleConfigRouter = Router();

ruleConfigRouter.get('/config/commands', (_req: Request, res: Response) => {
  res.json(readCommandDisplay());
});
ruleConfigRouter.post('/config/commands', (req: Request, res: Response) => {
  const b = req.body || {};
  const d: CommandDisplay = {
    safe:        Array.isArray(b.safe) ? b.safe : [],
    restricted:  Array.isArray(b.restricted) ? b.restricted : [],
    destructive: Array.isArray(b.destructive) ? b.destructive : [],
  };
  writeCommandDisplay(d);
  res.json(readCommandDisplay());
});

ruleConfigRouter.get('/config/filezones', (_req: Request, res: Response) => {
  res.json({ zones: readZoneDisplay() });
});
ruleConfigRouter.post('/config/filezones', (req: Request, res: Response) => {
  const zones = Array.isArray(req.body?.zones) ? req.body.zones : [];
  if (zones.length) writeZoneDisplay(zones);
  res.json({ zones: readZoneDisplay() });
});
