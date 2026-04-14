import { Request, Response }     from 'express';
import { classifyToolCall }      from '../../api/intentClassifier';
import { logDecision }           from '../discovery/enroll';
import { sessionIntentStore }    from './beforePrompt';
import { sessionStore }          from '../discovery/enroll';
import { claudeSessionUserStore } from './onSessionStart';
import { getToolSensitivity }    from '../../api/knownServers';
import { triggerHITL }           from '../hitl/trigger';
import { pollHITL }              from '../hitl/poll';
import { recordHITLApproval, recordHITLDenial } from '../hitl/callback';
import { resolveAgentName }      from '../../api/agentResolver';
import { evaluateCedar, buildCallToolPayload, buildFileOperationPayload, getOrCreateSessionTrace } from '../../api/pdpEvaluate';

// Track active MCP servers discovered via PreToolUse
export const activeMcpServers = new Map<string, Set<string>>(); // session_id → Set of server names

function trackMcpServer(session_id: string, tool_name: string): void {
  if (!tool_name.startsWith('mcp__')) return;
  const parts = tool_name.split('__');
  if (parts.length < 2) return;
  const server_name = parts[1];
  if (!activeMcpServers.has(session_id)) {
    activeMcpServers.set(session_id, new Set());
  }
  activeMcpServers.get(session_id)!.add(server_name);
}

export const hitlStore = new Map<string, {
  acknowledged: boolean;
  approved_at:  string;
  tool_name:    string;
}>();

const hitlInFlight = new Map<string, boolean>();

// Scope mapping — tool sensitivity → MCPTool scope
const SENSITIVITY_SCOPE: Record<string, string> = {
  low:      'MCPTool:Read',
  medium:   'MCPTool:Write',
  high:     'MCPTool:Communicate',
  critical: 'MCPTool:Destructive',
};

export async function handleToolCall(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization || '';
    const token      = authHeader.replace('Bearer ', '');
    // Allow unauthenticated hook calls from Claude Code plugin

    const {
      session_id    = `session-${Date.now()}`,
      tool_name     = '',
      server_name   = '',
      server_url    = '',
      user_email_body = (req as any).user?.email || '',
      agent_cid     = '',
      client_source = 'claude-code',
    } = req.body;

    // Resolve OS user from SessionStart — try claudeSessionUserStore first
    const osUserFromSession = claudeSessionUserStore.get(session_id);
    const enrolledSession   = sessionStore.get(session_id);
    const user_email = osUserFromSession || enrolledSession?.user_email || user_email_body || 'claude-code-hook@reva.ai';

    const sessionIntent   = sessionIntentStore.get(session_id);
    const promptIntent    = sessionIntent?.intent        || 'unknown';
    const priorIntents    = sessionIntent?.prior_intents || '';
    const query           = sessionIntent?.query         || '';
    const baseSensitivity = getToolSensitivity(server_name, server_url, tool_name);

    // Track MCP server usage dynamically
    trackMcpServer(session_id, tool_name);

    // Detect if this is a Claude Code native tool call (not MCP)
    const claudeCodeTools = ['Read', 'Write', 'Edit', 'MultiEdit', 'Bash', 'Glob', 'Grep', 'Task', 'Agent', 'WorktreeTool'];
    const isClaudeCodeTool = claudeCodeTools.some(t => tool_name === t || tool_name.toLowerCase() === t.toLowerCase());

    const result = classifyToolCall(tool_name, server_name, baseSensitivity, session_id, promptIntent);

    const hitlKey          = `${session_id}:${tool_name}`;
    const hitlAcknowledged = hitlStore.get(hitlKey)?.acknowledged || false;

    // Resolve agent name from Okta (cached)
    const agentName = agent_cid ? await resolveAgentName(agent_cid) : 'CoworkAICodingAgent';

    // Ensure session trace ID
    getOrCreateSessionTrace(session_id);

    // Scope from sensitivity
    const toolScope = SENSITIVITY_SCOPE[result.sensitivity] || 'MCPTool:Read';

    // ── Cedar PDP evaluation ──────────────────────────────────────
    // Use ClaudeCode payload builder for claude-code hooks, Cowork builder otherwise
    const cedarPayload = client_source === 'claude-code'
      ? buildFileOperationPayload({
          osUser:          user_email,
          projectName:     server_name || 'claude-demo-project',
          toolName:        tool_name,
          filePath:        req.body?.tool_input?.file_path || req.body?.tool_input?.path || req.body?.tool_input?.new_path || '',
          command:         req.body?.tool_input?.command || '',
          agentType:       req.body?.agent_type || 'main',
          sessionId:       session_id,
          hitlAcknowledged,
          scores:          { ...result.scores, trust_score: result.trust_score },
        })
      : buildCallToolPayload({
          agentName,
          agentId:         agent_cid,
          toolName:        tool_name,
          serverName:      server_name,
          humanSub:        user_email,
          clientSource:    client_source,
          sessionId:       session_id,
          sensitivity:     result.sensitivity,
          toolScope,
          scores:          { ...result.scores, trust_score: result.trust_score },
          hitlAcknowledged,
          intent:          result.intent,
          priorIntents,
          query,
          queryHistory:    priorIntents,
        });

    const cedarResult = await evaluateCedar(cedarPayload);

    let effect: 'Permit' | 'Deny' | 'HITL' = 'Permit';
    let reason  = 'Tool call permitted';

    if (cedarResult.decision === 'deny') {
      effect = 'Deny';
      reason = cedarResult.policy_name
        ? `Denied by policy: ${cedarResult.policy_name}`
        : 'Denied by Cedar PDP';
    } else if (cedarResult.decision === 'conditional_allow') {
      effect = 'HITL';
      reason = cedarResult.policy_name
        ? `HITL required by policy: ${cedarResult.policy_name}`
        : 'HITL required by Cedar PDP';
    }

    logDecision({
      timestamp:   new Date().toISOString(),
      session_id,
      user_email,
      tool:        tool_name,
      server:      server_name,
      sensitivity: result.sensitivity,
      effect,
      reason,
    });

    // HITL: trigger Okta Verify push in background
    if (effect === 'HITL' && !hitlInFlight.get(hitlKey)) {
      hitlInFlight.set(hitlKey, true);
      (async () => {
        try {
          const triggerResult = await triggerHITL(user_email, tool_name, session_id);
          if (!triggerResult.success || !triggerResult.poll_url) {
            recordHITLDenial(session_id, tool_name, user_email, 'error');
            hitlInFlight.delete(hitlKey);
            return;
          }
          const status = await pollHITL(triggerResult.poll_url);
          if (status === 'approved') {
            recordHITLApproval(session_id, tool_name, user_email, triggerResult.poll_url);
          } else {
            const denyStatus = status === 'waiting' ? 'timeout' : status as 'denied' | 'timeout' | 'error';
            recordHITLDenial(session_id, tool_name, user_email, denyStatus, triggerResult.poll_url);
          }
        } catch (err: any) {
          console.error(`[HITL] Background error: ${err.message}`);
        } finally {
          hitlInFlight.delete(hitlKey);
        }
      })();
    }

    if (effect === 'Deny') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: reason,
        },
        reva: { effect, reason, trust_score: result.trust_score, sensitivity: result.sensitivity, hitlAcknowledged, cedar: cedarResult },
      });
    }

    if (effect === 'HITL') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: `${reason}. A push notification has been sent to your Okta Verify app. Approve it then re-submit.`,
        },
        reva: { effect: 'HITL', reason, hitl_required: true, hitl_key: hitlKey, trust_score: result.trust_score, sensitivity: result.sensitivity, hitlAcknowledged, cedar: cedarResult },
      });
    }

    return res.json({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
      reva: { effect: 'Permit', reason, trust_score: result.trust_score, sensitivity: result.sensitivity, cedar: cedarResult },
    });

  } catch (err: any) {
    console.error('beforeToolCall error:', err.message);
    return res.json({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } });
  }
}
