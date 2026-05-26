// PostToolUse — audit log of what actually executed + error tracking
// Fires AFTER a tool call completes (success or failure)
// Feeds: Dashboard Section C (usage analytics), risk scoring

import { Request, Response } from 'express';
import { logDecision }       from '../discovery/enroll';
import { sessionIntentStore } from './beforePrompt';
import { claudeSessionUserStore } from './onSessionStart';
import { sessionStore }       from '../discovery/enroll';
import { activeMcpServers }   from './beforeToolCall';
import { enrichSession, getPIPContext } from '../../api/pip';

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

    // ── PIP re-enrichment on branch change ──
    // Detect git checkout/switch in bash tool output and re-enrich PIP
    if (tool_name === 'Bash' && success && typeof tool_result === 'string') {
      const branchMatch = tool_result.match(/Switched to (?:a new )?branch '([^']+)'/);
      if (branchMatch) {
        const newBranch = branchMatch[1];
        const ticketMatch = newBranch.match(/([A-Z]+-[0-9]+)/);
        const ticketId = ticketMatch ? ticketMatch[1] : '';
        const existingPip = getPIPContext(user_email);
        const remoteUrl = existingPip?.github?.github_repo
          ? `https://github.com/${existingPip.github.github_repo}.git`
          : '';

        console.log(`[PostToolUse] Branch changed to '${newBranch}', ticket=${ticketId || 'none'} — re-enriching PIP for ${user_email}`);

        try {
          await enrichSession(user_email, ticketId, remoteUrl, newBranch, {
            oauth_email:     existingPip?.oauth_email,
            connection_type: existingPip?.connection_type,
            git_email:       existingPip?.git_email,
            git_name:        existingPip?.git_name,
          });
          console.log(`[PostToolUse] PIP re-enriched for ${user_email} on branch ${newBranch}`);
        } catch (err: any) {
          console.warn(`[PostToolUse] PIP re-enrichment failed: ${err.message}`);
        }
      }
    }

    // ── File injection scanning — check ReadFile output for malicious content ──
    if ((tool_name === 'Read' || tool_name === 'ReadFile') && success && typeof tool_result === 'string' && tool_result.length > 0) {
      const content = tool_result.toLowerCase();
      const fileInjectionPatterns = [
        'ignore previous instructions', 'ignore your instructions', 'disregard previous',
        'you are now', 'pretend you', 'act as if', 'forget your', 'new instructions',
        'bypass', 'jailbreak', 'admin/admin', 'password admin', 'backdoor',
        'echo.*>>.*\\.env', 'ADMIN_TOKEN', 'skip approval', 'override policy',
      ];
      const matches = fileInjectionPatterns.filter(p => content.includes(p.toLowerCase())).length;
      if (matches > 0) {
        const injScore = Math.min(matches * 35, 100);
        const { recordBlock } = require('../../api/intentClassifier');
        recordBlock(user_email, {
          type: 'file_injection' as const,
          prompt: `File content injection detected (${matches} patterns matched)`,
          score: injScore,
          timestamp: new Date().toISOString(),
        });
      }
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
