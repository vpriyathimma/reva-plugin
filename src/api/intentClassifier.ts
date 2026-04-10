// Intent Classifier — Phase 4 (keyword-based)
// Phase 9: replaced by LSA + HMM + Isolation Forest ML engine
// Cedar receives all scores. Cedar makes all decisions.

export interface IntentResult {
  intent:            string;
  confidence:        number; // 0-100
  trust_score:       number; // 0-100
  sensitivity:       string; // low | medium | high | critical
  scores:            GuardrailScores;
}

export interface GuardrailScores {
  injection_score:        number;
  jailbreak_score:        number;
  exfiltration_score:     number;
  recon_score:            number;
  escalation_score:       number;
  sod_violation:          boolean;
  sod_score:              number;
  time_anomaly_score:     number;
  velocity_score:         number;
  cross_tenant:           boolean;
  cross_tenant_score:     number;
  intent_mismatch_score:  number;
  cover_tracks_score:     number;
  scope_creep_score:      number;
  after_hours_score:      number;
  bypass_attempts_score:  number;
  bulk_operation_score:   number;
  intent_pool_score:      number;
  intent_pool_pattern:    string;
}

// ── Intent corpus ─────────────────────────────────────────────────
// NOTE: only VERBS here — not nouns like "email", "message"
// "send an email" → communicate (verb: send)
// "search my emails" → read (verb: search)
const INTENT_CORPUS: Record<string, string[]> = {
  read:        ['get','list','search','find','fetch','view','query','lookup','read','retrieve','check','show','summarise','summarize','export','download','monitor','browse'],
  write:       ['create','add','insert','draft','upload','push','commit','post','new','write','generate','build','import','compose'],
  modify:      ['update','edit','patch','modify','change','rename','move','replace','set','put','transition','assign'],
  destructive: ['delete','remove','drop','purge','destroy','truncate','archive','clear','wipe','erase'],
  communicate: ['send','forward','share','publish','broadcast','reply','notify','distribute','cc','bcc'],
  govern:      ['approve','authorize','reject','escalate','resolve','close','merge','deploy','promote','review'],
  exfiltrate:  ['send all','forward all','export all','copy all','download all','extract all'],
};

const INJECTION_PATTERNS = [
  'ignore previous instructions',
  'ignore your instructions',
  'disregard previous',
  'you are now',
  'pretend you',
  'act as if',
  'forget your',
  'new instructions',
  'bypass',
  'jailbreak',
];

const JAILBREAK_PATTERNS = [
  'dan mode',
  'developer mode',
  'no restrictions',
  'without restrictions',
  'unrestricted',
  'do anything now',
  'ignore all rules',
  'as an ai without',
];

const ESCALATION_PATTERNS = [
  'as admin',
  'admin access',
  'skip approval',
  'skip hitl',
  'no approval',
  'without permission',
  'bypass policy',
  'override policy',
  'ignore policy',
];

// ── Keyword classifier (Phase 4) ──────────────────────────────────
function classifyIntent(text: string): { intent: string; confidence: number } {
  const normalized = text.toLowerCase().replace(/[_-]/g, ' ');
  let bestIntent   = 'read'; // safe default
  let bestScore    = 0;

  for (const [intent, keywords] of Object.entries(INTENT_CORPUS)) {
    // Count keyword matches using word boundary check
    const matches = keywords.filter(k => {
      const regex = new RegExp(`\\b${k}\\b`, 'i');
      return regex.test(normalized);
    }).length;

    const score = matches > 0 ? matches / keywords.length : 0;
    if (score > bestScore) {
      bestScore  = score;
      bestIntent = intent;
    }
  }

  // Minimum confidence of 40 for matched intent, 30 for default
  const confidence = bestScore > 0
    ? Math.max(40, Math.round(bestScore * 100))
    : 30;

  return { intent: bestIntent, confidence };
}

function scoreInjection(text: string): number {
  const normalized = text.toLowerCase();
  const matches    = INJECTION_PATTERNS.filter(p => normalized.includes(p)).length;
  return Math.min(matches * 35, 100);
}

function scoreJailbreak(text: string): number {
  const normalized = text.toLowerCase();
  const matches    = JAILBREAK_PATTERNS.filter(p => normalized.includes(p)).length;
  return Math.min(matches * 40, 100);
}

function scoreEscalation(text: string): number {
  const normalized = text.toLowerCase();
  const matches    = ESCALATION_PATTERNS.filter(p => normalized.includes(p)).length;
  return Math.min(matches * 30, 100);
}

function scoreAfterHours(): number {
  const hour = new Date().getUTCHours();
  // UTC+5:30 IST — business hours 9am-6pm IST = 3:30-12:30 UTC
  // Use UTC directly — only score extreme hours
  if (hour >= 22 || hour < 2) return 60; // midnight-2am UTC = very late night
  if (hour >= 2  && hour < 4) return 30; // early morning
  return 0; // all other hours = no penalty
}

// ── Trust Score computation ────────────────────────────────────────
// Starts at 70 (neutral baseline) — deductions for guardrail hits
// Phase 9: replaced by LSA × 0.5 + Markov × 0.5
function computeTrustScore(
  intentConfidence: number,
  guardrails:       GuardrailScores
): number {
  // Start at neutral baseline — not intent confidence
  // Intent confidence adjusts slightly but is not the foundation
  let score = 70 + Math.round((intentConfidence - 50) * 0.2);

  // Hard deductions for active guardrail hits
  if (guardrails.injection_score > 50)       score -= 60;
  if (guardrails.jailbreak_score > 50)       score -= 60;
  if (guardrails.escalation_score > 50)      score -= 40;
  if (guardrails.exfiltration_score > 50)    score -= 40;
  if (guardrails.sod_violation)              score -= 60;
  if (guardrails.intent_mismatch_score > 50) score -= 30;
  if (guardrails.intent_pool_score > 60)     score -= 35;
  if (guardrails.bypass_attempts_score > 40) score -= 25;

  // Soft deductions — only if significant
  if (guardrails.after_hours_score > 50)     score -= 15;
  if (guardrails.velocity_score > 50)        score -= 15;

  return Math.max(0, Math.min(100, Math.round(score)));
}

// ── Sensitivity derivation ────────────────────────────────────────
// Base sensitivity = floor — Trust Score can only elevate, never lower
function deriveSensitivity(
  baseSensitivity: string,
  trustScore:      number
): string {
  const levels = ['low', 'medium', 'high', 'critical'];
  const baseIdx = levels.indexOf(baseSensitivity);

  let elevate = 0;
  if      (trustScore < 20) elevate = 2;
  else if (trustScore < 40) elevate = 1;
  // trust 40+ → no elevation from trust score alone

  return levels[Math.min(baseIdx + elevate, 3)];
}

// ── Session velocity tracker ──────────────────────────────────────
const sessionVelocity = new Map<string, number[]>();

function scoreVelocity(sessionId: string): number {
  const now     = Date.now();
  const history = sessionVelocity.get(sessionId) || [];
  const recent  = history.filter(t => now - t < 60000);
  recent.push(now);
  sessionVelocity.set(sessionId, recent);

  if (recent.length > 20) return 80;
  if (recent.length > 15) return 50;
  if (recent.length > 10) return 30;
  return 0;
}

// ── Bypass attempt tracker ────────────────────────────────────────
const bypassAttempts = new Map<string, number>();

export function recordBypassAttempt(sessionId: string): void {
  bypassAttempts.set(sessionId, (bypassAttempts.get(sessionId) || 0) + 1);
}

// ── Main classifiers ──────────────────────────────────────────────
export function classifyPrompt(
  promptText: string,
  sessionId:  string,
  userEmail:  string
): IntentResult {
  const { intent, confidence } = classifyIntent(promptText);

  const guardrails: GuardrailScores = {
    injection_score:       scoreInjection(promptText),
    jailbreak_score:       scoreJailbreak(promptText),
    exfiltration_score:    0,
    recon_score:           0,
    escalation_score:      scoreEscalation(promptText),
    sod_violation:         false,
    sod_score:             0,
    time_anomaly_score:    0,
    velocity_score:        scoreVelocity(sessionId),
    cross_tenant:          false,
    cross_tenant_score:    0,
    intent_mismatch_score: 0,
    cover_tracks_score:    0,
    scope_creep_score:     0,
    after_hours_score:     scoreAfterHours(),
    bypass_attempts_score: Math.min((bypassAttempts.get(sessionId) || 0) * 20, 100),
    bulk_operation_score:  0,
    intent_pool_score:     0,
    intent_pool_pattern:   'none',
  };

  const trust_score = computeTrustScore(confidence, guardrails);
  const sensitivity = deriveSensitivity('medium', trust_score);

  return { intent, confidence, trust_score, sensitivity, scores: guardrails };
}

export function classifyToolCall(
  toolName:        string,
  serverName:      string,
  baseSensitivity: string,
  sessionId:       string,
  promptIntent:    string
): IntentResult {
  const { intent, confidence } = classifyIntent(`${toolName} ${serverName}`);

  // Intent-action mismatch: prompt said read but tool is write/destructive/communicate
  const readIntents       = ['read'];
  const nonReadIntents    = ['write', 'destructive', 'communicate', 'exfiltrate'];
  const intentMismatch    = (readIntents.includes(promptIntent) && nonReadIntents.includes(intent))
    ? 65 : 0;

  const guardrails: GuardrailScores = {
    injection_score:       0,
    jailbreak_score:       0,
    exfiltration_score:    0,
    recon_score:           0,
    escalation_score:      0,
    sod_violation:         false,
    sod_score:             0,
    time_anomaly_score:    0,
    velocity_score:        scoreVelocity(sessionId),
    cross_tenant:          false,
    cross_tenant_score:    0,
    intent_mismatch_score: intentMismatch,
    cover_tracks_score:    0,
    scope_creep_score:     0,
    after_hours_score:     scoreAfterHours(),
    bypass_attempts_score: Math.min((bypassAttempts.get(sessionId) || 0) * 20, 100),
    bulk_operation_score:  toolName.includes('batch') || toolName.includes('bulk') ? 60 : 0,
    intent_pool_score:     0,
    intent_pool_pattern:   'none',
  };

  const trust_score = computeTrustScore(confidence, guardrails);
  const sensitivity = deriveSensitivity(baseSensitivity, trust_score);

  return { intent, confidence, trust_score, sensitivity, scores: guardrails };
}
