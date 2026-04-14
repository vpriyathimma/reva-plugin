// SessionStart hook handler
// Fires when Claude Code session begins
// Validates: OS user, project access, cwd
// Enrolls session in dashboard with MCP servers and tools list

import { Request, Response } from 'express';
import { resolveSession }    from '../../api/sessionResolver';
import { enrollSession }     from '../discovery/enroll';
import { getOrCreateSessionTrace } from '../../api/pdpEvaluate';

interface SessionStartInput {
  hook_event_name: string;
  session_id:      string;
  cwd:             string;
  // env vars passed by Claude Code
  env?: Record<string, string>;
  // MCP servers active in this session
  mcp_servers?: string[];
  // Tools allowed in this session
  allowed_tools?: string[];
}

export async function handleSessionStart(req: Request, res: Response) {
  try {
    const body: SessionStartInput = req.body || {};

    const session_id    = body.session_id || `session-${Date.now()}`;
    const cwd           = body.cwd        || '';
    const os_user       = body.env?.USER  || process.env.USER || 'unknown';
    const mcp_servers   = body.mcp_servers  || [];
    const allowed_tools = body.allowed_tools || [];
    const project_name  = cwd.split('/').pop() || '';

    console.log(`[SessionStart] session=${session_id} os_user=${os_user} cwd=${cwd}`);

    // Resolve identity and access
    const { allowed, identity, reason } = resolveSession(os_user, cwd);

    if (!allowed) {
      console.warn(`[SessionStart] DENIED — ${reason}`);

      // Exit code 2 blocks the session in Claude Code
      return res.status(200).json({
        decision:  'block',
        reason,
        hookSpecificOutput: {
          hookEventName: 'SessionStart',
          decision:      'block',
          reason,
        },
      });
    }

    // Create session trace
    getOrCreateSessionTrace(session_id);

    // Build tool list for dashboard
    const tools = allowed_tools.map(tool_name => ({
      server_name:        tool_name.startsWith('mcp__') ? tool_name.split('__')[1] : 'claude-code',
      server_url:         '',
      server_type:        tool_name.startsWith('mcp__') ? 'streamable-http' : 'built-in',
      tool_name,
      description:        '',
      sensitivity:        tool_name.includes('delete') || tool_name.includes('bash') ? 'high' : 'low',
      sensitivity_reason: 'Derived from tool name',
    }));

    // Enroll session in dashboard
    enrollSession(session_id, os_user, tools);

    console.log(`[SessionStart] ALLOWED — ${reason}`);
    console.log(`[SessionStart] MCP servers: ${mcp_servers.join(', ') || 'none'}`);
    console.log(`[SessionStart] Tools: ${allowed_tools.length}`);

    // Return allow — session proceeds
    return res.status(200).json({
      decision: 'allow',
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: `Reva governance active. Session: ${session_id}. User: ${identity.display_name}. Project: ${project_name}.`,
      },
    });

  } catch (err: any) {
    console.error('[SessionStart] Error:', err.message);
    // On error — allow session to proceed (fail open for SessionStart)
    return res.status(200).json({ decision: 'allow' });
  }
}
