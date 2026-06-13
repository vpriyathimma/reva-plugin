// Session Control — admin terminates a specific session from the dashboard.
//
// Termination is SESSION-SCOPED: the kill switch is keyed by session_id (the same
// id every live hook carries), so terminating one session never touches the
// developer's other sessions or other coding agents. A terminated session:
//   • is blocked at BOTH UserPromptSubmit and PreToolUse (Claude Code), and at
//     the evaluate gate for Codex and Kiro;
//   • has its short-lived (JIT) credentials revoked immediately.
//
// Distinct from quarantine: quarantine pauses access (session stays live, JIT
// revoked, "Quarantined" highlight) while termination ends the session outright.

import { Router, Request, Response } from 'express';
import { emitReva } from './events';

// Keyed by session_id.
const terminatedSessions = new Set<string>();

export function terminateSession(sessionId: string): { revokedJit: number } {
  terminatedSessions.add(sessionId);
  let revokedJit = 0;
  try {
    const { revokeSVIDsForSession } = require('./svid');
    revokedJit = revokeSVIDsForSession(sessionId);
  } catch (e: any) { console.warn(`[SESSION] JIT revoke skipped on terminate: ${e?.message}`); }
  console.log(`[SESSION] Terminated: ${sessionId} (JIT revoked: ${revokedJit})`);
  try { emitReva({ type: 'quarantine' }); } catch { /* */ }
  return { revokedJit };
}

export function isSessionTerminated(sessionId: string): boolean {
  return terminatedSessions.has(sessionId);
}

export function restoreSession(sessionId: string): void {
  terminatedSessions.delete(sessionId);
  console.log(`[SESSION] Restored: ${sessionId}`);
  try { emitReva({ type: 'quarantine' }); } catch { /* */ }
}

export function getTerminatedSessions(): string[] {
  return Array.from(terminatedSessions);
}

// API Routes
export const sessionControlRouter = Router();

// POST /api/session/terminate  { session_id }  (legacy alias: { key })
// Terminates one session and revokes its JIT credentials.
sessionControlRouter.post('/session/terminate', (req: Request, res: Response) => {
  const sessionId = req.body?.session_id || req.body?.key;
  if (!sessionId) return res.status(400).json({ ok: false, error: 'session_id required' });
  const { revokedJit } = terminateSession(sessionId);
  res.json({ ok: true, terminated: sessionId, jit_revoked: revokedJit });
});

// POST /api/session/restore  { session_id }  (legacy alias: { key })
sessionControlRouter.post('/session/restore', (req: Request, res: Response) => {
  const sessionId = req.body?.session_id || req.body?.key;
  if (!sessionId) return res.status(400).json({ ok: false, error: 'session_id required' });
  restoreSession(sessionId);
  res.json({ ok: true, restored: sessionId });
});

sessionControlRouter.get('/session/terminated', (_req: Request, res: Response) => {
  res.json({ terminated: getTerminatedSessions() });
});
