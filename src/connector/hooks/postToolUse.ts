// PostToolUse — audit log of what actually executed + error tracking
// Fires AFTER a tool call completes (success or failure)
// Feeds: Dashboard Section C (usage analytics), risk scoring

import { Request, Response } from 'express';
import { logDecision }       from '../discovery/enroll';
import { sessionIntentStore } from './beforePrompt';
import { claudeSessionUserStore } from './onSessionStart';
import { sessionStore }       from '../discovery/enroll';
import { activeMcpServers }   from './beforeToolCall';

// Audit store — what actually executed (separate from PDP decisions)
export interface AuditEntry {
  timestamp:     string;
  session_id:    string;
  user_email:    string;
  tool_name:     string;
  server_name:   string;
  success:       boolean;
  error_message: string;
  duration_ms:   number;
  output_size:   number;
}

export const auditLog: AuditEntry[] = [];

// Error tracking per session — feeds risk scoring
export const errorStore = new Map<string, { count: number; last_error: string; last_at: string }>();

export async function handlePostToolUse(req: Request, res: Response) {
  try {
    const osUserFromHeader = (req.headers['x-os-user'] as string) || '';

    const {
      session_id   = '',
      tool_name    = '',
      server_name  = '',
      tool_result  = '',
      tool_error   = '',
      duration_ms  = 0,
    } = req.body;

    const osUserFromSession = claudeSessionUserStore.get(session_id);
    const enrolledSession   = sessionStore.get(session_id);
    const user_email = osUserFromHeader || osUserFromSession || enrolledSession?.user_email || 'unknown';

    const isError  = !!tool_error || (typeof tool_result === 'string' && tool_result.includes('Error'));
    const success  = !isError;
    const outputSize = typeof tool_result === 'string' ? tool_result.length : JSON.stringify(tool_result || '').length;

    // Track MCP server usage
    if (tool_name.startsWith('mcp__')) {
      const parts = tool_name.split('__');
      const serverKey = parts[1] || '';
      if (serverKey && session_id) {
        if (!activeMcpServers.has(session_id)) activeMcpServers.set(session_id, new Set());
        activeMcpServers.get(session_id)!.add(serverKey);
      }
    }

    // Record audit entry
    const entry: AuditEntry = {
      timestamp:     new Date().toISOString(),
      session_id,
      user_email,
      tool_name,
      server_name,
      success,
      error_message: tool_error || '',
      duration_ms:   duration_ms || 0,
      output_size:   outputSize,
    };
    auditLog.push(entry);

    // Keep last 500 entries
    if (auditLog.length > 500) auditLog.splice(0, auditLog.length - 500);

    // Error tracking
    if (isError) {
      const existing = errorStore.get(session_id) || { count: 0, last_error: '', last_at: '' };
      errorStore.set(session_id, {
        count:      existing.count + 1,
        last_error: (tool_error || tool_result || '').slice(0, 200),
        last_at:    new Date().toISOString(),
      });

      console.log(`[PostToolUse] ERROR session=${session_id} tool=${tool_name} error=${(tool_error || '').slice(0, 100)}`);
    }

    // Log for dashboard
    const sessionIntent = sessionIntentStore.get(session_id);
    logDecision({
      timestamp:   new Date().toISOString(),
      session_id,
      user_email,
      tool:        tool_name,
      server:      server_name || 'claude-code',
      sensitivity: 'low',
      effect:      'Permit',
      reason:      isError ? `PostToolUse: tool failed — ${(tool_error || '').slice(0, 100)}` : 'PostToolUse: executed successfully',
      intent:      sessionIntent?.intent || '',
      trust_score: sessionIntent?.trust_score,
      prompt:      sessionIntent?.prompt?.slice(0, 200) || '',
      agent_type:  'main',
    });

    console.log(`[PostToolUse] session=${session_id} tool=${tool_name} success=${success} duration=${duration_ms}ms output=${outputSize}b`);

    return res.json({
      hookSpecificOutput: { hookEventName: 'PostToolUse' },
    });

  } catch (err: any) {
    console.error('[PostToolUse] Error:', err.message);
    return res.json({ hookSpecificOutput: { hookEventName: 'PostToolUse' } });
  }
}
