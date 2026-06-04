// In-process event bus — lets the SSE stream push live updates to the console
// without polling. logDecision and quarantine changes emit here; /api/stream
// subscribes. Purely additive: nothing in the enforcement path depends on it.

import { EventEmitter } from 'events';

export const revaEvents = new EventEmitter();
revaEvents.setMaxListeners(100);

export type RevaEvent =
  | { type: 'decision' }
  | { type: 'session' }
  | { type: 'quarantine' };

export function emitReva(ev: RevaEvent): void {
  try { revaEvents.emit('reva', ev); } catch { /* never break the caller */ }
}
