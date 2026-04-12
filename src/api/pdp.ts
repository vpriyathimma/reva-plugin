import { Router, Request, Response } from 'express';
import { handlePromptSubmit }  from '../connector/hooks/beforePrompt';
import { handleToolCall }      from '../connector/hooks/beforeToolCall';
import { decisionLog }         from '../connector/discovery/enroll';
import { knownServers, updateToolEntry, resolveServer } from './knownServers';
import { verifyConnectorToken } from '../connector/oauth/token';

const router = Router();

function verifyHookToken(req: Request, res: Response, next: Function) {
  const auth  = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  const user  = verifyConnectorToken(token);

  // Allow unauthenticated hook calls from Cowork plugin
  // User identity comes from the hook payload (session data)
  if (!user) {
    (req as any).user = { email: req.body?.user_email || 'cowork-hook@reva.ai', name: 'Cowork Hook' };
  } else {
    (req as any).user = user;
  }
  next();
}

// ── Hook endpoints ────────────────────────────────────────────────
router.post('/pdp/prompt',   verifyHookToken, handlePromptSubmit);
router.post('/pdp/evaluate', verifyHookToken, handleToolCall);

// ── Decision feed ─────────────────────────────────────────────────
router.get('/pdp/decisions', verifyHookToken, (_req, res) => {
  const recent = [...decisionLog].reverse().slice(0, 100);
  res.json({ decisions: recent, total: decisionLog.length });
});

// ── Tool registry — get all ───────────────────────────────────────
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

  // Find the updated entry to return version
  const match = resolveServer(server_url, server_url);
  return res.json({
    status:      'updated',
    server:      server_url,
    tool:        tool_name,
    intent,
    sensitivity,
    by:          user.email,
    version:     match?.entry.version,
  });
});

// ── REVA AI intent suggestion (Phase 5 — needs ANTHROPIC_API_KEY) ─
router.post('/pdp/intents/suggest', verifyHookToken, async (req, res) => {
  const { tool_name, server_url, description, input_schema } = req.body;

  if (!tool_name) return res.status(400).json({ error: 'tool_name required' });
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'ANTHROPIC_API_KEY not configured' });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method:  'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-20250514',
        max_tokens: 256,
        system: `You are a security governance assistant. Analyse MCP tool names and descriptions to classify their security properties. Respond ONLY with valid JSON — no markdown, no explanation.`,
        messages: [{
          role:    'user',
          content: `Classify this MCP tool for security governance.
Tool name: ${tool_name}
Server: ${server_url || 'unknown'}
Description: ${description || 'not provided'}
Input schema: ${input_schema ? JSON.stringify(input_schema) : 'not provided'}

Respond with exactly this JSON:
{"intent":["one of: read,write,modify,destructive,communicate,govern"],"sensitivity":"one of: low,medium,high,critical","reason":"one sentence"}`,
        }],
      }),
    });

    const data   = await response.json() as any;
    const text   = data?.content?.[0]?.text || '{}';
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());

    return res.json({ tool_name, suggestion: parsed, source: 'reva-ai' });
  } catch (err: any) {
    return res.status(500).json({ error: 'REVA AI suggestion failed', detail: err.message });
  }
});

export default router;

// ── HITL log — dashboard visibility ──────────────────────────────
import { hitlLog, getHITLStatus } from '../connector/hitl/callback';
import { hitlStore }              from '../connector/hooks/beforeToolCall';

router.get('/pdp/hitl', verifyHookToken, (_req, res) => {
  res.json({ hitl_log: [...hitlLog].reverse().slice(0, 50), total: hitlLog.length });
});

router.get('/pdp/hitl/:session_id/:tool_name', verifyHookToken, (req, res) => {
  const { session_id, tool_name } = req.params;
  const record = getHITLStatus(session_id, tool_name);
  const acknowledged = hitlStore.get(`${session_id}:${tool_name}`)?.acknowledged || false;
  res.json({ record, acknowledged });
});
