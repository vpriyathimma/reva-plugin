// SessionEnd (Stop) — session summary + cleanup
// Fires when Claude Code session ends
// Feeds: Dashboard Section A (online/offline), Section C (session insights)

import { Request, Response }       from 'express';
import { logDecision, sessionStore, decisionLog } from '../discovery/enroll';
import { claudeSessionUserStore }  from './onSessionStart';
import { sessionIntentStore, queryHistoryStore } from './beforePrompt';
import { subagentContextStore, activeMcpServers, hitlStore } from './beforeToolCall';
import { auditLog, errorStore }    from './postToolUse';

// Session summary store — persists after session ends for dashboard
export interface SessionSummary {
  session_id:      string;
  user_email:      string;
  started_at:      string;
  ended_at:        string;
  duration_mins:   number;
  total_decisions: number;
  permits:         number;
  denies:          number;
  hitls:           number;
  tools_used:      string[];
  mcp_servers:     string[];
  errors:          number;
  subagent_spawns: number;
  prompts:         number;
}

export const sessionSummaries: SessionSummary[] = [];

export async function handleSessionEnd(req: Request, res: Response) {
  try {
    const osUserFromHeader = (req.headers['x-os-user'] as string) || (req.headers['x-os-username'] as string) || '';

    const {
      session_id = '',
    } = req.body;

    const osUser        = osUserFromHeader || claudeSessionUserStore.get(session_id) || 'unknown';
    const enrolled      = sessionStore.get(session_id);
    const user_email    = osUser || enrolled?.user_email || 'unknown';
    const startedAt     = enrolled?.enrolled_at || new Date().toISOString();

    // Aggregate session decisions
    const sessionDecisions = decisionLog.filter(d => d.session_id === session_id);
    const permits          = sessionDecisions.filter(d => d.effect === 'Permit').length;
    const denies           = sessionDecisions.filter(d => d.effect === 'Deny').length;
    const hitls            = sessionDecisions.filter(d => d.effect === 'HITL').length;

    // Tools used
    const toolsUsed = [...new Set(sessionDecisions.map(d => d.tool).filter(t => t !== 'prompt'))];

    // MCP servers
    const mcpServers = [...(activeMcpServers.get(session_id) || new Set())];

    // Errors
    const errors = errorStore.get(session_id)?.count || 0;

    // Subagent spawns
    const subagentSpawns = subagentContextStore.get(session_id)?.spawn_count || 0;

    // Prompts
    const prompts = (queryHistoryStore.get(session_id) || []).length;

    // Duration
    const durationMins = Math.round((Date.now() - new Date(startedAt).getTime()) / 60000);

    const summary: SessionSummary = {
      session_id,
      user_email,
      started_at:      startedAt,
      ended_at:        new Date().toISOString(),
      duration_mins:   durationMins,
      total_decisions: sessionDecisions.length,
      permits,
      denies,
      hitls,
      tools_used:      toolsUsed,
      mcp_servers:     mcpServers,
      errors,
      subagent_spawns: subagentSpawns,
      prompts,
    };

    sessionSummaries.push(summary);

    // Keep last 100 summaries
    if (sessionSummaries.length > 100) sessionSummaries.splice(0, sessionSummaries.length - 100);

    // Log
    logDecision({
      timestamp:   new Date().toISOString(),
      session_id,
      user_email,
      tool:        'session-end',
      server:      'claude-code',
      sensitivity: 'low',
      effect:      'Permit',
      reason:      `Session ended — ${durationMins}min, ${sessionDecisions.length} decisions, ${denies} denies, ${errors} errors`,
      intent:      'govern',
      trust_score: 70,
    });

    console.log(`[SessionEnd] session=${session_id} user=${user_email} duration=${durationMins}min decisions=${sessionDecisions.length} denies=${denies} errors=${errors}`);

    // Cleanup in-memory stores for this session
    claudeSessionUserStore.delete(session_id);
    sessionIntentStore.delete(session_id);
    queryHistoryStore.delete(session_id);
    subagentContextStore.delete(session_id);
    errorStore.delete(session_id);
    // Keep activeMcpServers + hitlStore — dashboard may still reference

    return res.json({});

  } catch (err: any) {
    console.error('[SessionEnd] Error:', err.message);
    return res.json({});
  }
}
