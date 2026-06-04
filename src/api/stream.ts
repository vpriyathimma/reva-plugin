// Live updates for the console — Server-Sent Events. The Insights page
// subscribes with EventSource and refreshes on the fly (no polling) whenever a
// decision is logged or a quarantine changes. Additive: degrades to polling if
// unused. Also exposes per-developer trust (baseline 70 minus 15 per block).

import { Router, Request, Response } from 'express';
import { revaEvents, RevaEvent } from './events';
import { getPersistentTrust, getAllBlocks } from './intentClassifier';

export const streamRouter = Router();

streamRouter.get('/stream', (req: Request, res: Response) => {
  res.set({
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection':    'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders?.();
  res.write(`retry: 5000\n\n`);
  res.write(`event: hello\ndata: {"ok":true}\n\n`);

  const onEvent = (ev: RevaEvent) => {
    try { res.write(`data: ${JSON.stringify(ev)}\n\n`); } catch { /* client gone */ }
  };
  revaEvents.on('reva', onEvent);

  // heartbeat so proxies (Render) don't drop the idle connection
  const hb = setInterval(() => { try { res.write(`: ping\n\n`); } catch { /* */ } }, 25_000);

  req.on('close', () => {
    clearInterval(hb);
    revaEvents.off('reva', onEvent);
  });
});

// Per-developer trust, derived from the same persistent block-penalty model the
// hooks use. Keyed by osUser; blocks come back so the console can show why.
streamRouter.get('/trust', (_req: Request, res: Response) => {
  const out: Record<string, { trust: number; blocks: number }> = {};
  for (const [osUser, blocks] of getAllBlocks()) {
    out[osUser] = { trust: getPersistentTrust(osUser), blocks: blocks.length };
  }
  res.json({ trust: out });
});
