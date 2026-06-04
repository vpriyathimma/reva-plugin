// Intent Classifier — Phase 4 (keyword-based)
// Phase 9: replaced by LSA + HMM + Isolation Forest ML engine
// Cedar receives all scores. Cedar makes all decisions.

export interface IntentResult {
  intent:            string;
  confidence:        number;
  trust_score:       number;
  sensitivity:       string;
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

// ── Intent corpus — verbs only, no nouns ──────────────────────────
const INTENT_CORPUS: Record<string, string[]> = {
  read:        ['get','list','search','find','fetch','view','query','lookup','read','retrieve','check','show','summarise','summarize','export','download','monitor','browse'],
  write:       ['create','add','insert','draft','upload','push','commit','post','new','write','generate','build','import','compose'],
  modify:      ['update','edit','patch','modify','change','rename','move','replace','set','put','transition','assign'],
  destructive: ['delete','remove','drop','purge','destroy','truncate','archive','clear','wipe','erase'],
  communicate: ['send','forward','share','publish','broadcast','reply','notify','distribute'],
  govern:      ['approve','authorize','reject','escalate','resolve','close','merge','deploy','promote','review'],
  exfiltrate:  ['send all','forward all','export all','copy all','download all','extract all'],
};

const INJECTION_PATTERNS = [
  /ignore.*(?:previous|prior|above|all).*instructions/,
  /ignore.*your.*instructions/,
  /disregard.*(?:previous|prior|above)/,
  /you are now/,
  /pretend you/,
  /act as if/,
  /forget.*your/,
  /new instructions/,
  /bypass/,
  /jailbreak/,
  /backdoor/,
  /add.*admin.*(?:account|password|user)/,
  /(?:password|pwd)\s*(?:admin|root|123)/,
  /override.*(?:security|policy|rules)/,
  /skip.*(?:security|auth|validation)/,
  // Indirect injection — file-based
  /read.*(?:file|config|yaml|json).*(?:follow|execute|apply|do what|run what|act on)/,
  /(?:follow|execute|apply|do what|run).*(?:instructions|steps|commands).*(?:in|from|inside).*(?:file|config|yaml)/,
  /(?:setup|migration|deploy).*instructions/,
  // Indirect injection — stealth / authority framing embedded in read content
  /do not (?:mention|tell|reveal|disclose|report|log|include)/,
  /(?:complete|do|run|execute)\s+(?:it|this|the following|the above)?\s*silently/,
  /without (?:mentioning|telling|informing|notifying)/,
  /\b(?:agent|ai|assistant|system)\s+(?:note|instruction|directive|task)\b/,
  /(?:exfiltrat|dump|leak)\w*.*(?:env|secret|token|credential|key)/,
];

const JAILBREAK_PATTERNS = [
  /dan\s*mode/,
  /developer\s*mode/,
  /no\s*restrictions/,
  /without\s*restrictions/,
  /unrestricted/,
  /do\s*anything\s*now/,
  /ignore\s*all\s*rules/,
  /as\s*an?\s*ai\s*without/,
  /enable.*(?:developer|admin|root)\s*mode/,
  /delete\s*all/,
];

const ESCALATION_PATTERNS = [
  /as\s*admin/,
  /admin\s*access/,
  /skip\s*approval/,
  /skip\s*hitl/,
  /no\s*approval/,
  /without\s*permission/,
  /bypass\s*policy/,
  /override\s*policy/,
  /ignore\s*policy/,
];

function classifyIntent(text: string): { intent: string; confidence: number } {
  const normalized = text.toLowerCase().replace(/[_-]/g, ' ');
  let bestIntent   = 'read';
  let bestScore    = 0;

  for (const [intent, keywords] of Object.entries(INTENT_CORPUS)) {
    const matches = keywords.filter(k => {
      const regex = new RegExp(`\\b${k}\\b`, 'i');
      return regex.test(normalized);
    }).length;
    const score = matches > 0 ? matches / keywords.length : 0;
    if (score > bestScore) { bestScore = score; bestIntent = intent; }
  }

  const confidence = bestScore > 0 ? Math.max(40, Math.round(bestScore * 100)) : 30;
  return { intent: bestIntent, confidence };
}

function scoreInjection(text: string): number {
  const normalized = text.toLowerCase();
  const matches    = INJECTION_PATTERNS.filter(p => p.test(normalized)).length;
  return Math.min(matches * 35, 100);
}

function scoreJailbreak(text: string): number {
  const normalized = text.toLowerCase();
  const matches    = JAILBREAK_PATTERNS.filter(p => p.test(normalized)).length;
  return Math.min(matches * 40, 100);
}

function scoreEscalation(text: string): number {
  const normalized = text.toLowerCase();
  const matches    = ESCALATION_PATTERNS.filter(p => p.test(normalized)).length;
  return Math.min(matches * 30, 100);
}

function scoreAfterHours(): number {
  const hour = new Date().getUTCHours();
  if (hour >= 22 || hour < 2) return 60;
  if (hour >= 2  && hour < 4) return 30;
  return 0;
}

// ── Trust score — starts at 70, deduct for guardrail hits ─────────
// promptLevel: true = include bypass counter, false = tool call only
function computeTrustScore(
  intentConfidence: number,
  guardrails:       GuardrailScores,
  promptLevel:      boolean = true
): number {
  let score = 70 + Math.round((intentConfidence - 50) * 0.2);

  if (guardrails.injection_score > 50)       score -= 60;
  if (guardrails.jailbreak_score > 50)       score -= 60;
  if (guardrails.escalation_score > 50)      score -= 40;
  if (guardrails.exfiltration_score > 50)    score -= 40;
  if (guardrails.sod_violation)              score -= 60;
  if (guardrails.intent_mismatch_score > 50) score -= 30;
  if (guardrails.intent_pool_score > 60)     score -= 35;
  if (guardrails.after_hours_score > 50)     score -= 15;
  if (guardrails.velocity_score > 50)        score -= 15;

  // bypass_attempts only affects prompt-level trust, not tool calls
  if (promptLevel && guardrails.bypass_attempts_score > 40) score -= 25;

  return Math.max(0, Math.min(100, Math.round(score)));
}

// ── Base sensitivity = floor, elevation only below trust 30 ───────
function deriveSensitivity(baseSensitivity: string, trustScore: number): string {
  const levels  = ['low', 'medium', 'high', 'critical'];
  const baseIdx = levels.indexOf(baseSensitivity);

  let elevate = 0;
  if      (trustScore < 15) elevate = 2;
  else if (trustScore < 30) elevate = 1;
  // trust 30+ → no elevation

  return levels[Math.min(baseIdx + elevate, 3)];
}

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

const bypassAttempts = new Map<string, number>();

export function recordBypassAttempt(sessionId: string): void {
  bypassAttempts.set(sessionId, (bypassAttempts.get(sessionId) || 0) + 1);
}

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

  const trust_score = computeTrustScore(confidence, guardrails, true);
  const sensitivity = deriveSensitivity('medium', trust_score);
  // Prompt Injection toggle: when OFF, strip injection signals so no injection
  // context attribute flows downstream (Claude Code blocks injection itself).
  if (!require('./securityConfig').isEnabled('prompt_injection')) {
    guardrails.injection_score = 0;
    guardrails.jailbreak_score = 0;
  }
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

  const dangerousMismatch =
    ['read'].includes(promptIntent) &&
    ['destructive', 'exfiltrate'].includes(intent);

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
    intent_mismatch_score: dangerousMismatch ? 65 : 0,
    cover_tracks_score:    0,
    scope_creep_score:     0,
    after_hours_score:     scoreAfterHours(),
    bypass_attempts_score: 0, // not inherited at tool call level
    bulk_operation_score:  toolName.includes('batch') || toolName.includes('bulk') ? 60 : 0,
    intent_pool_score:     0,
    intent_pool_pattern:   'none',
  };

  // Tool calls: promptLevel=false so bypass counter not included
  const trust_score = computeTrustScore(confidence, guardrails, false);
  const sensitivity = deriveSensitivity(baseSensitivity, trust_score);
  return { intent, confidence, trust_score, sensitivity, scores: guardrails };
}

// ── Prompt Block Tracker ──
// Tracks when Claude itself blocks dangerous prompts or file content
// Keyed by os_user (same as PIP) to avoid session_id mismatch between hooks

export interface BlockRecord {
  type:      'prompt_injection' | 'file_injection' | 'jailbreak_attempt' | 'intent_drift';
  prompt:    string;
  score:     number;
  timestamp: string;
}

const blockStore = new Map<string, BlockRecord[]>();

export function recordBlock(osUser: string, block: BlockRecord): void {
  const blocks = blockStore.get(osUser) || [];
  blocks.push(block);
  blockStore.set(osUser, blocks);
  console.log(`[BLOCK] ${block.type} for ${osUser} — total blocks: ${blocks.length}, trust penalty: -${blocks.length * 15}`);
}

export function getBlockCount(osUser: string): number {
  return (blockStore.get(osUser) || []).length;
}

export function getBlocks(osUser: string): BlockRecord[] {
  return blockStore.get(osUser) || [];
}

export function getAllBlocks(): Map<string, BlockRecord[]> {
  return blockStore;
}

// Trust penalty from blocks — 15 points per block
export function getBlockTrustPenalty(osUser: string): number {
  return getBlockCount(osUser) * 15;
}

// Persistent actor trust — baseline minus accumulated block penalty.
// Decays 15 per recorded block (injection/jailbreak) and carries forward across
// prompts: a clean prompt does NOT reset it to baseline. This is distinct from
// computeTrustScore (per-prompt risk), which can crash to 0 on a single prompt.
// In-memory: persists across prompts within the running process; resets only on
// process restart (move blockStore to a durable store for cross-restart decay).
export const TRUST_BASELINE = 70;
export function getPersistentTrust(osUser: string): number {
  return Math.max(0, TRUST_BASELINE - getBlockTrustPenalty(osUser));
}

// ─────────────────────────────────────────────────────────────────────────────
// Intent drift = the agent did something the developer didn't ask for.
//
// NOT about risk tier. A developer who asks "remove the changelog" and gets it
// removed has no drift, even though that's destructive. A subagent told to
// "review docs and tests" that reads src/ HAS drift, even though reading is safe.
// We compare the resource THIS action targets against what was actually asked in
// declared_scope (the prompt that drove this action) ∪ initial_scope (the
// originating prompt). If the target isn't referenced in the ask, it's drift.
//
// An unspecific ask ("list my files") names no concrete target, so nothing can be
// "outside" it — no drift is raised. Drift fires only when the ask names targets
// and the action reaches outside them. Same mechanism for files (src vs
// docs/tests) and hosts/resources (staging vs local DB).
// ─────────────────────────────────────────────────────────────────────────────

// Generic words carrying no target identity — stripped from BOTH the ask and the
// action target, so the comparison turns on the distinctive qualifier
// (src vs docs, staging vs local), not the shared type noun (file, db, folder).
const SCOPE_STOPWORDS = new Set<string>([
  'the','a','an','and','or','to','of','in','on','for','with','my','me','our','your','this','that','these','those','it','all','some','any',
  'please','also','then','just','from','into','at','by','as','is','are','be','do','can','could','would','should','let','lets','will',
  'review','read','list','show','summarize','summarise','check','inspect','audit','analyze','analyse','explore','look','examine','understand','explain','describe','find','search','get','see','give','tell','report','current','state','status',
  'remove','delete','drop','edit','write','update','modify','change','fix','create','add','make','build','connect','run','open','use',
  'file','files','folder','folders','directory','directories','dir','db','database','server','servers','repo','repository','project','code','codebase','contents','content','here','data',
  'spawn','multiple','agents','agent','subagent','subagents','parallel','task','tasks','them','each','both','few','several','about','what','which','where',
]);

function scopeTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of (text || '').toLowerCase().split(/[^a-z0-9.]+/)) {
    const norm = raw.replace(/^[._]+|[._]+$/g, '');
    if (!norm || SCOPE_STOPWORDS.has(norm)) continue;
    out.add(norm);
    const stem = norm.split('.')[0];                          // app.js → app
    if (stem && stem !== norm && !SCOPE_STOPWORDS.has(stem)) out.add(stem);
    if (norm === 'test' || norm === 'tests') { out.add('test'); out.add('tests'); }
  }
  return out;
}

// The resource a tool call targets — pulled from a file path, a bash command's
// path/host args, or a URL. Path tails (last two segments) are used so the home/
// project prefix (/Users/<me>/<project>/...) doesn't leak generic tokens.
function actionTargetTokens(target: string): Set<string> {
  if (!target) return new Set();
  const candidates = /\s/.test(target)
    ? target.split(/\s+/).filter(a => a && !a.startsWith('-') && (a.includes('/') || a.includes('.') || a.includes(':')))
    : [target];
  const list = candidates.length ? candidates : [target];
  const out = new Set<string>();
  for (const c of list) {
    let frag = c.includes('://') ? (c.split('://')[1] || c) : c;
    const segs = frag.split('/').filter(Boolean);
    const tail = (segs.length ? segs.slice(-2) : [frag]).join(' ');
    for (const tok of scopeTokens(tail)) out.add(tok);
  }
  return out;
}

// Did the developer's request itself ask to CHANGE something? If they asked to
// edit/delete/write, a mutating action is in scope. If they only asked to
// read/review, a mutating action is DRASTIC drift.
const ASKED_MUTATE = /\b(edit|edits|edited|editing|update|updates|updated|updating|modify|modifies|modified|modifying|change|changes|changed|remove|removes|removed|removing|delete|deletes|deleted|deleting|drop|drops|write|writes|writing|create|creates|created|add|adds|added|fix|fixes|fixed|refactor|refactors|rename|renames|install|installs|deploy|deploys|push|pushes|commit|commits|merge|merges|rewrite|patch|append)\b/i;

// Does THIS action mutate state (vs. read/inspect)?
const MUTATING_TOOL = /^(edit|write|multiedit|notebookedit|str_replace|create_file)$/i;
const MUTATING_CMD  = /\b(rm|rmdir|mv|cp|mkdir|touch|truncate|dd|tee|chmod|chown|ln|shred)\b|\bsed\s+-i\b|\bgit\s+(commit|push|merge|rebase|reset|stash|tag|cherry-pick)\b|\b(npm|yarn|pnpm|pip|pip3|gem|cargo|go|apt|brew)\s+(install|add|remove|uninstall)\b/i;
function isMutatingAction(tool_name: string, target: string): boolean {
  if (MUTATING_TOOL.test(tool_name || '')) return true;
  return MUTATING_CMD.test(target || '');   // for Bash, target is the command
}

export function checkIntentDrift(params: {
  target:         string;   // file_path | bash command | url the action operates on
  tool_name?:     string;
  declared_scope: string;   // the prompt that drove this action
  initial_scope:  string;   // the originating prompt
}): { is_intent_drift: boolean; intent_drift_score: number; reduces_trust: boolean } {
  const askedMutate  = ASKED_MUTATE.test(`${params.declared_scope || ''} ${params.initial_scope || ''}`);
  const actionMutate = isMutatingAction(params.tool_name || '', params.target || '');

  // Drastic drift — developer asked to read/review, agent MUTATES (edit/update/
  // remove/delete/write). Denied AND erodes trust, like a prompt injection.
  if (!askedMutate && actionMutate) {
    return { is_intent_drift: true, intent_drift_score: 90, reduces_trust: true };
  }

  // Scope drift — action targets a resource the developer never asked for (a
  // different folder / host). Denied, but NO trust penalty — it's containment, not
  // a trust signal. An unspecific ask ("list my files") names no target → no drift.
  const asked = new Set<string>([...scopeTokens(params.declared_scope), ...scopeTokens(params.initial_scope)]);
  if (asked.size === 0) return { is_intent_drift: false, intent_drift_score: 0, reduces_trust: false };
  const target = actionTargetTokens(params.target);
  if (target.size === 0) return { is_intent_drift: false, intent_drift_score: 0, reduces_trust: false };
  for (const tok of target) if (asked.has(tok)) return { is_intent_drift: false, intent_drift_score: 0, reduces_trust: false };
  return { is_intent_drift: true, intent_drift_score: 50, reduces_trust: false };
}
