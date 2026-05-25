// Session Control — admin can terminate developer sessions from dashboard
// Terminate = block all tool calls for developer+machine until restored or new session

import { Router, Request, Response } from 'express';

const terminatedSessions = new Set<string>();

export function terminateSession(key: string): void {
  terminatedSessions.add(key);
  console.log(`[SESSION] Terminated: ${key}`);
}

export function isSessionTerminated(key: string): boolean {
  return terminatedSessions.has(key);
}

export function restoreSession(key: string): void {
  terminatedSessions.delete(key);
  console.log(`[SESSION] Restored: ${key}`);
}

export function getTerminatedSessions(): string[] {
  return Array.from(terminatedSessions);
}

// API Routes
export const sessionControlRouter = Router();

sessionControlRouter.post('/session/terminate', (req: Request, res: Response) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ ok: false, error: 'key required' });
  terminateSession(key);
  res.json({ ok: true, terminated: key });
});

sessionControlRouter.post('/session/restore', (req: Request, res: Response) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ ok: false, error: 'key required' });
  restoreSession(key);
  res.json({ ok: true, restored: key });
});

sessionControlRouter.get('/session/terminated', (_req: Request, res: Response) => {
  res.json({ terminated: getTerminatedSessions() });
});
