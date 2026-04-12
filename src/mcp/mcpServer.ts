import { Router, Request, Response } from 'express';
import { verifyConnectorToken } from '../connector/oauth/token';
import { sessionStore, logDecision } from '../connector/discovery/enroll';
import { resolveAgentName } from '../api/agentResolver';
import { evaluateCedar, buildCallToolPayload, buildSubmitPromptPayload, getOrCreateSessionTrace } from '../api/pdpEvaluate';
import { classifyToolCall, classifyPrompt } from '../api/intentClassifier';
import { getToolSensitivity } from '../api/knownServers';
import { sessionIntentStore, queryHistoryStore } from '../connector/hooks/beforePrompt';
import { hitlStore } from '../connector/hooks/beforeToolCall';
import { triggerHITL } from '../connector/hitl/trigger';
import { pollHITL } from '../connector/hitl/poll';
import { recordHITLApproval, recordHITLDenial } from '../connector/hitl/callback';

const router = Router();

const OKTA_DOMAIN = process.env.OKTA_DOMAIN || 'demo-ai-auth-raah.okta.com';

// Cache userinfo to avoid repeated Okta calls
const userInfoCache = new Map<string, { email: string; name: string; expires: number }>();

// ── Resolve user from any token type ─────────────────────────────
async function getMcpUser(req: Request): Promise<{ email: string; name: string } | null> {
  const auth  = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;

  // 1. Try Reva connector token
  const connectorUser = verifyConnectorToken(token);
  if (connectorUser) return connectorUser;

  // 2. Check cache
  const cached = userInfoCache.get(token);
  if (cached && cached.expires > Date.now()) {
    return { email: cached.email, name: cached.name };
  }

  // 3. Try Okta userinfo endpoint — for Okta access tokens from Cowork
  try {
    const res = await fetch(`https://${OKTA_DOMAIN}/oauth2/v1/userinfo`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.ok) {
      const data = await res.json() as any;
      const user = { email: data.email || data.sub, name: data.name || data.email || data.sub };
      userInfoCache.set(token, { ...user, expires: Date.now() + 3600000 });
      return user;
    }
  } catch (err: any) {
    console.warn('[MCP] Okta userinfo failed:', err.message);
  }

  // 4. Try decoding JWT sub claim as fallback
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    if (payload.sub) return { email: payload.sub, name: payload.name || payload.sub };
  } catch {}

  return null;
}

// ── MCP tool definitions ──────────────────────────────────────────
const MCP_TOOLS = [
  {
    name:        'reva_governance_status',
    description: 'Get Reva governance status for the current session — trust score, active policies, HITL status',
    inputSchema: { type: 'object', properties: { session_id: { type: 'string' } } },
  },
  {
    name:        'reva_evaluate_prompt',
    description: 'Evaluate a prompt against Reva Cedar governance policies before execution',
    inputSchema: {
      type: 'object',
      properties: {
        prompt:     { type: 'string', description: 'The prompt text to evaluate' },
        session_id: { type: 'string' },
        agent_cid:  { type: 'string', description: 'Agent client ID from Okta' },
      },
      required: ['prompt'],
    },
  },
  {
    name:        'reva_evaluate_tool',
    description: 'Evaluate a tool call against Reva Cedar governance policies',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name:   { type: 'string' },
        server_name: { type: 'string' },
        server_url:  { type: 'string' },
        session_id:  { type: 'string' },
        agent_cid:   { type: 'string' },
      },
      required: ['tool_name', 'server_name'],
    },
  },
];

// ── POST /mcp — Streamable HTTP ───────────────────────────────────
router.post('/mcp', async (req: Request, res: Response) => {
  const user = await getMcpUser(req);

  if (!user) {
    return res.status(401).json({
      jsonrpc: '2.0',
      error:   { code: -32001, message: 'Unauthorized' },
      id:      req.body?.id || null,
    });
  }

  const { method, params, id } = req.body || {};
  console.log(`[MCP] ${method} — ${user.email}`);

  // ── initialize ────────────────────────────────────────────────
  if (method === 'initialize') {
    return res.json({
      jsonrpc: '2.0',
      result: {
        protocolVersion: '2024-11-05',
        capabilities:    { tools: {} },
        serverInfo:      { name: 'reva-governance', version: '1.0.0' },
      },
      id,
    });
  }

  // ── tools/list ────────────────────────────────────────────────
  if (method === 'tools/list') {
    return res.json({
      jsonrpc: '2.0',
      result:  { tools: MCP_TOOLS },
      id,
    });
  }

  // ── tools/call ────────────────────────────────────────────────
  if (method === 'tools/call') {
    const toolName  = params?.name;
    const toolInput = params?.arguments || {};
    const sessionId = toolInput.session_id || `mcp-${Date.now()}`;

    // reva_governance_status
    if (toolName === 'reva_governance_status') {
      const session    = sessionStore.get(sessionId);
      const traceId    = getOrCreateSessionTrace(sessionId);
      const intentData = sessionIntentStore.get(sessionId);

      return res.json({
        jsonrpc: '2.0',
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              session_id:    sessionId,
              session_trace: traceId,
              user:          user.email,
              trust_score:   intentData?.trust_score || 70,
              intent:        intentData?.intent || 'unknown',
              prior_intents: intentData?.prior_intents || '',
              tool_count:    session?.tool_count || 0,
              status:        'active',
            }, null, 2),
          }],
        },
        id,
      });
    }

    // reva_evaluate_prompt
    if (toolName === 'reva_evaluate_prompt') {
      const prompt    = toolInput.prompt    || '';
      const agentCid  = toolInput.agent_cid || '';
      const agentName = agentCid ? await resolveAgentName(agentCid) : 'CoworkAICodingAgent';

      const result       = classifyPrompt(prompt, sessionId, user.email);
      const history      = queryHistoryStore.get(sessionId) || [];
      const queryHistory = history.slice(-3).join(', ');
      const prevIntent   = sessionIntentStore.get(sessionId);
      const priorIntents = prevIntent
        ? `${prevIntent.prior_intents},${prevIntent.intent}`.replace(/^,/, '')
        : '';

      sessionIntentStore.set(sessionId, {
        intent:        result.intent,
        trust_score:   result.trust_score,
        query:         prompt.slice(0, 500),
        prior_intents: priorIntents,
        timestamp:     new Date().toISOString(),
      });

      history.push(prompt.slice(0, 200));
      queryHistoryStore.set(sessionId, history.slice(-10));
      getOrCreateSessionTrace(sessionId);

      const cedarPayload = buildSubmitPromptPayload({
        agentName,
        agentId:      agentCid,
        humanSub:     user.email,
        clientSource: 'cowork',
        sessionId,
        scores:       { ...result.scores, trust_score: result.trust_score },
        intent:       result.intent,
        priorIntents,
        query:        prompt,
        queryHistory,
      });

      const cedarResult = await evaluateCedar(cedarPayload);
      const permitted   = cedarResult.decision === 'allow';

      logDecision({
        timestamp:  new Date().toISOString(),
        session_id: sessionId,
        user_email: user.email,
        tool:       'prompt',
        server:     'cowork',
        sensitivity: result.sensitivity,
        effect:     permitted ? 'Permit' : 'Deny',
        reason:     cedarResult.policy_name || (permitted ? 'Permitted' : 'Denied by Cedar'),
      });

      return res.json({
        jsonrpc: '2.0',
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              permitted,
              effect:      permitted ? 'Permit' : 'Deny',
              intent:      result.intent,
              trust_score: result.trust_score,
              cedar:       cedarResult,
            }, null, 2),
          }],
        },
        id,
      });
    }

    // reva_evaluate_tool
    if (toolName === 'reva_evaluate_tool') {
      const mcpToolName  = toolInput.tool_name   || '';
      const serverName   = toolInput.server_name || '';
      const serverUrl    = toolInput.server_url  || '';
      const agentCid     = toolInput.agent_cid   || '';
      const agentName    = agentCid ? await resolveAgentName(agentCid) : 'CoworkAICodingAgent';

      const sessionIntent   = sessionIntentStore.get(sessionId);
      const promptIntent    = sessionIntent?.intent        || 'unknown';
      const priorIntents    = sessionIntent?.prior_intents || '';
      const query           = sessionIntent?.query         || '';
      const baseSensitivity = getToolSensitivity(serverName, serverUrl, mcpToolName);
      const result          = classifyToolCall(mcpToolName, serverName, baseSensitivity, sessionId, promptIntent);
      const hitlKey         = `${sessionId}:${mcpToolName}`;
      const hitlAcknowledged = hitlStore.get(hitlKey)?.acknowledged || false;

      const SENSITIVITY_SCOPE: Record<string, string> = {
        low: 'MCPTool:Read', medium: 'MCPTool:Write',
        high: 'MCPTool:Communicate', critical: 'MCPTool:Destructive',
      };

      getOrCreateSessionTrace(sessionId);

      const cedarPayload = buildCallToolPayload({
        agentName, agentId: agentCid, toolName: mcpToolName,
        serverName, humanSub: user.email, clientSource: 'cowork',
        sessionId, sensitivity: result.sensitivity,
        toolScope: SENSITIVITY_SCOPE[result.sensitivity] || 'MCPTool:Read',
        scores: { ...result.scores, trust_score: result.trust_score },
        hitlAcknowledged, intent: result.intent, priorIntents, query,
        queryHistory: priorIntents,
      });

      const cedarResult = await evaluateCedar(cedarPayload);

      let effect: 'Permit' | 'Deny' | 'HITL' = 'Permit';
      let reason = 'Tool call permitted';

      if (cedarResult.decision === 'deny') {
        effect = 'Deny';
        reason = cedarResult.policy_name ? `Denied by policy: ${cedarResult.policy_name}` : 'Denied by Cedar';
      } else if (cedarResult.decision === 'conditional_allow') {
        effect = 'HITL';
        reason = 'HITL required';
      }

      if (effect === 'HITL' && !hitlAcknowledged) {
        (async () => {
          const t = await triggerHITL(user.email, mcpToolName, sessionId);
          if (t.success && t.poll_url) {
            const s = await pollHITL(t.poll_url);
            if (s === 'approved') recordHITLApproval(sessionId, mcpToolName, user.email, t.poll_url);
            else recordHITLDenial(sessionId, mcpToolName, user.email, s === 'waiting' ? 'timeout' : s as any, t.poll_url);
          }
        })();
      }

      logDecision({
        timestamp: new Date().toISOString(), session_id: sessionId,
        user_email: user.email, tool: mcpToolName, server: serverName,
        sensitivity: result.sensitivity, effect, reason,
      });

      return res.json({
        jsonrpc: '2.0',
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              permitted: effect === 'Permit', effect, reason,
              tool: mcpToolName, sensitivity: result.sensitivity,
              trust_score: result.trust_score, hitl: effect === 'HITL',
              cedar: cedarResult,
            }, null, 2),
          }],
        },
        id,
      });
    }

    return res.json({
      jsonrpc: '2.0',
      error:   { code: -32601, message: `Unknown tool: ${toolName}` },
      id,
    });
  }

  return res.json({
    jsonrpc: '2.0',
    error:   { code: -32601, message: `Method not found: ${method}` },
    id,
  });
});

// ── GET /mcp — SSE fallback ───────────────────────────────────────
router.get('/mcp', async (req: Request, res: Response) => {
  const user = await getMcpUser(req);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.write(`data: ${JSON.stringify({ type: 'connected', server: 'reva-governance', user: user.email })}\n\n`);

  const keepAlive = setInterval(() => res.write(': keepalive\n\n'), 15000);
  req.on('close', () => clearInterval(keepAlive));
});

export default router;
