// PDP API routes
// POST /api/pdp/prompt   → UserPromptSubmit hook handler
// POST /api/pdp/evaluate → PreToolUse hook handler
// GET  /api/pdp/decisions → decision feed for dashboard
// POST /api/pdp/intents/suggest → REVA AI intent suggestion
// PATCH /api/pdp/intents → admin tool registry update

import { Router, Request, Response } from 'express';
import { handlePromptSubmit }  from '../connector/hooks/beforePrompt';
import { handleToolCall }      from '../connector/hooks/beforeToolCall';
import { decisionLog }         from '../connector/discovery/enroll';
import { knownServers, updateToolEntry } from './knownServers';
import { verifyConnectorToken } from '../connector/oauth/token';

const router = Router();

// ── Auth middleware for hook endpoints ────────────────────────────
function verifyHookToken(req: Request, res: Response, next: Function) {
  const auth  = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  const user  = verifyConnectorToken(token);
  if (!user) return res.status(401).json({ error: 'Invalid connector token' });
  (req as any).user = user;
  next();
}

// ── Hook endpoints ────────────────────────────────────────────────
router.post('/pdp/prompt',   verifyHookToken, handlePromptSubmit);
router.post('/pdp/evaluate', verifyHookToken, handleToolCall);

// ── Decision feed ─────────────────────────────────────────────────
router.get('/pdp/decisions', verifyHookToken, (_req, res) => {
  const recent = [...decisionLog]
    .reverse()
    .slice(0, 100);
  res.json({ decisions: recent, total: decisionLog.length });
});

// ── Tool registry — get all known servers ─────────────────────────
router.get('/pdp/registry', verifyHookToken, (_req, res) => {
  res.json({ registry: knownServers });
});

// ── Tool registry — admin update ──────────────────────────────────
router.patch('/pdp/intents', verifyHookToken, (req, res) => {
  const { server_url, tool_name, intent, sensitivity, reason } = req.body;
  const user = (req as any).user;

  if (!server_url || !tool_name || !intent || !sensitivity) {
    return res.status(400).json({ error: 'server_url, tool_name, intent, sensitivity required' });
  }

  updateToolEntry(server_url, tool_name, intent, sensitivity, user.email, reason || 'Admin override');

  return res.json({
    status:   'updated',
    server:   server_url,
    tool:     tool_name,
    intent,
    sensitivity,
    by:       user.email,
    version:  knownServers[server_url]?.version,
  });
});

// ── REVA AI intent suggestion ─────────────────────────────────────
router.post('/pdp/intents/suggest', verifyHookToken, async (req, res) => {
  const { tool_name, server_url, description, input_schema } = req.body;

  if (!tool_name) {
    return res.status(400).json({ error: 'tool_name required' });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         process.env.ANTHROPIC_API_KEY || '',
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-20250514',
        max_tokens: 256,
        system: `You are a security governance assistant for an enterprise AI platform.
Analyse MCP tool names and descriptions to classify their security properties.
Respond ONLY with valid JSON — no markdown, no explanation outside the JSON.`,
        messages: [{
          role: 'user',
          content: `Classify this MCP tool for security governance.

Tool name: ${tool_name}
Server: ${server_url || 'unknown'}
Description: ${description || 'not provided'}
Input schema: ${input_schema ? JSON.stringify(input_schema) : 'not provided'}

Respond with exactly this JSON structure:
{
  "intent": ["one of: read, write, modify, destructive, communicate, govern"],
  "sensitivity": "one of: low, medium, high, critical",
  "reason": "one sentence explaining why"
}`,
        }],
      }),
    });

    const data     = await response.json() as any;
    const text     = data?.content?.[0]?.text || '{}';
    const clean    = text.replace(/```json|```/g, '').trim();
    const parsed   = JSON.parse(clean);

    return res.json({
      tool_name,
      suggestion: parsed,
      source:     'reva-ai',
    });

  } catch (err: any) {
    return res.status(500).json({ error: 'REVA AI suggestion failed', detail: err.message });
  }
});

export default router;
