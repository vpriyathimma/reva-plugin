// SessionStart hook handler
// Fires when Claude Code session begins
// Validates: OS user, project access, cwd
// Enrolls session with: agent_id, OS, hostname, model, MCP servers

import { Request, Response } from 'express';
import { createHash }       from 'crypto';
import { Sensitivity }       from '../discovery/classifier';
import { resolveSession }    from '../../api/sessionResolver';
import { enrollSession }     from '../discovery/enroll';
import { getOrCreateSessionTrace } from '../../api/pdpEvaluate';
import { probeAllServers }   from '../../api/mcpProbe';
import { enrichSession as enrichPIP } from '../../api/pip';

const SPIRE_API_URL = process.env.SPIRE_API_URL || 'http://3.233.113.248:8090';

// OS user store — maps Claude Code session_id to OS user
export const claudeSessionUserStore = new Map<string, string>();

// SPIFFE ID store — maps session_id → spiffe_id (for Cedar principal in subsequent hooks)
export const spiffeIdStore = new Map<string, string>();

// Hostname store — maps os_user → hostname (for terminate session key matching)
export const hostnameStore = new Map<string, string>();

// Agent ID store — maps os_user:hostname → synthetic agent ID (fallback)
const agentIdStore = new Map<string, string>();

function generateAgentId(osUser: string, hostname: string): string {
  const existing = agentIdStore.get(`${osUser}:${hostname}`);
  if (existing) return existing;
  const hash = createHash('sha256').update(`${osUser}:${hostname}`).digest('hex').slice(0, 12);
  const id = `agent-${hash}`;
  agentIdStore.set(`${osUser}:${hostname}`, id);
  return id;
}

// Map kernel name to display OS name
function mapOsType(raw: string): string {
  const lower = (raw || '').toLowerCase();
  if (lower === 'darwin') return 'macOS';
  if (lower === 'linux')  return 'Linux';
  if (lower.startsWith('mingw') || lower.startsWith('msys') || lower.startsWith('cygwin') || lower.includes('windows')) return 'Windows';
  return raw || '';
}

// Parse MCP servers from mcp_config JSON (sent by curl from local .mcp.json)
function parseMcpServers(mcpConfig: any): string[] {
  if (!mcpConfig || typeof mcpConfig !== 'object') return [];
  // .mcp.json format: { mcpServers: { name: {...} } }
  const fromMcp = mcpConfig.mcpServers ? Object.keys(mcpConfig.mcpServers) : [];
  // Also handle flat format
  const fromFlat = Object.keys(mcpConfig).filter(k => k !== 'mcpServers');
  return [...new Set([...fromMcp, ...fromFlat])].filter(s => s.length > 0);
}

interface SessionStartInput {
  hook_event_name: string;
  session_id:      string;
  cwd:             string;
  env?: Record<string, string>;
  // Enriched fields from curl (Option B)
  os_type?:          string;
  hostname?:         string;
  model?:            string;
  mcp_config?:       any;
  mcp_server_names?: string;  // comma-separated, from grep extraction
  // SPIRE identity + developer context — from ~/.claude.json
  claude_context?: {
    account_uuid:      string;
    display_name:      string;
    email:             string;
    org_uuid:          string;
    user_id:           string;
    github_repo_paths: Record<string, string[]>;
    git_email:         string;
    git_name:          string;
    // Git context
    git_branch:        string;
    git_remote_url:    string;
    jira_ticket_id:    string;
    // SSH detection
    connection_type:   string;  // 'local' | 'ssh'
    ssh_client_ip:     string;
    remote_os:         string;
  };
  // Legacy field (backward compat)
  oauth_account?: {
    account_uuid: string;
    display_name: string;
    email:        string;
  };
  // Legacy fields
  mcp_servers?:    string[];
  allowed_tools?:  string[];
}

// Register workload with SPIRE API — returns SPIFFE ID or null on failure
async function registerWithSPIRE(account: { account_uuid: string; display_name: string; email: string }): Promise<{
  spiffe_id: string;
  entry_id:  string;
  action:    string;
} | null> {
  if (!account.account_uuid) return null;

  try {
    const resp = await fetch(`${SPIRE_API_URL}/register`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(account),
      signal:  AbortSignal.timeout(5000),  // 5s timeout — non-blocking
    });

    if (!resp.ok) {
      console.warn(`[SPIRE] Register returned HTTP ${resp.status}`);
      return null;
    }

    const data = await resp.json() as any;
    console.log(`[SPIRE] ${data.action}: ${data.spiffe_id}`);
    return {
      spiffe_id: data.spiffe_id,
      entry_id:  data.entry?.entry_id || '',
      action:    data.action,
    };
  } catch (err: any) {
    console.warn(`[SPIRE] Registration failed (non-blocking): ${err.message}`);
    return null;
  }
}

export async function handleSessionStart(req: Request, res: Response) {
  try {
    const body: SessionStartInput = req.body || {};

    const session_id    = body.session_id || `session-${Date.now()}`;
    const cwd           = body.cwd        || '';
    const os_user       = body.env?.USER  || process.env.USER || 'unknown';
    const allowed_tools = body.allowed_tools || [];
    const project_name  = cwd.split('/').pop() || '';

    // Enriched fields from curl command
    const os_type  = mapOsType(body.os_type || '');
    const hostname = body.hostname || '';
    const model    = body.model    || '';

    // Parse MCP servers from local .mcp.json (Option B)
    const mcpFromConfig = parseMcpServers(body.mcp_config);
    const mcpFromNames  = body.mcp_server_names ? body.mcp_server_names.split(',').map(s => s.trim()).filter(s => s.length > 0) : [];
    const mcpFromBody   = body.mcp_servers || [];
    const mcp_servers   = [...new Set([...mcpFromConfig, ...mcpFromNames, ...mcpFromBody])];

    // Generate synthetic agent ID (deterministic per user+machine) — fallback
    const syntheticAgentId = generateAgentId(os_user, hostname || 'localhost');

    // ── SPIRE registration — get cryptographic workload identity ──
    let spiffe_id: string | undefined;
    let spire_entry_id: string | undefined;
    const claudeCtx = body.claude_context || body.oauth_account;

    if (claudeCtx?.account_uuid) {
      const spireResult = await registerWithSPIRE({
        account_uuid: claudeCtx.account_uuid,
        display_name: claudeCtx.display_name || '',
        email:        claudeCtx.email || '',
      });
      if (spireResult) {
        spiffe_id      = spireResult.spiffe_id;
        spire_entry_id = spireResult.entry_id;
      }
    }

    // Agent ID: SPIFFE ID if available, else synthetic hash
    const agent_id = spiffe_id || syntheticAgentId;

    // Trigger MCP tool discovery probe — async, non-blocking
    if (mcp_servers.length > 0) {
      probeAllServers(mcp_servers);
    }

    console.log(`[SessionStart] session=${session_id} os_user=${os_user} cwd=${cwd} os=${os_type} host=${hostname} model=${model || 'plan default'} agent=${agent_id} spiffe=${spiffe_id || 'none'} conn=${(body.claude_context as any)?.connection_type || 'local'} branch=${(body.claude_context as any)?.git_branch || 'none'} ticket=${(body.claude_context as any)?.jira_ticket_id || 'none'} mcp=[${mcp_servers.join(',')}]`);

    // Resolve identity and access (oauthEmail enables SSH fallback)
    const oauthEmail = claudeCtx?.email || undefined;
    const { allowed, identity, reason } = resolveSession(os_user, cwd, oauthEmail);

    if (!allowed) {
      console.warn(`[SessionStart] DENIED — ${reason}`);
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

    // Store os_user for this session so PreToolUse can resolve identity
    claudeSessionUserStore.set(session_id, os_user);

    // Store hostname for terminate session key matching
    if (hostname) {
      hostnameStore.set(os_user, hostname);
    }

    // Clear any existing terminate for this developer+machine (new session = fresh start)
    const termOauthEmail = (body.claude_context as any)?.email || '';
    if (termOauthEmail && hostname) {
      const { restoreSession } = require('../../api/sessionControl');
      const termKey = `${termOauthEmail}::${hostname}`;
      restoreSession(termKey);
    }

    // Store SPIFFE ID for subsequent hooks (PreToolUse, PostToolUse)
    if (spiffe_id) {
      spiffeIdStore.set(session_id, spiffe_id);
    }

    // Build tool list for dashboard
    const tools = allowed_tools.map(tool_name => ({
      server_name:        tool_name.startsWith('mcp__') ? tool_name.split('__')[1] : 'claude-code',
      server_url:         '',
      server_type:        tool_name.startsWith('mcp__') ? 'streamable-http' : 'built-in',
      tool_name,
      description:        '',
      input_schema:       {},
      sensitivity:        (tool_name.includes('delete') || tool_name.toLowerCase().includes('bash') ? 'high' : 'low') as Sensitivity,
      sensitivity_reason: 'Derived from tool name',
      preset_sensitivity: undefined,
    }));

    // Enroll session with enriched data
    enrollSession(session_id, os_user, tools, {
      agent_id,
      os_type:  os_type || undefined,
      hostname: hostname || undefined,
      model:    model || undefined,
      mcp_servers_discovered: mcp_servers.length > 0 ? mcp_servers : undefined,
      project_name:       project_name || undefined,
      spiffe_id:          spiffe_id || undefined,
      spire_entry_id:     spire_entry_id || undefined,
      oauth_email:        claudeCtx?.email || undefined,
      developer_name:     claudeCtx?.display_name || undefined,
      account_uuid:       claudeCtx?.account_uuid || undefined,
      org_uuid:           (body.claude_context as any)?.org_uuid || undefined,
      user_id:            (body.claude_context as any)?.user_id || undefined,
      github_repo_paths:  (body.claude_context as any)?.github_repo_paths || undefined,
      git_email:          (body.claude_context as any)?.git_email || undefined,
      git_name:           (body.claude_context as any)?.git_name || undefined,
      git_branch:         (body.claude_context as any)?.git_branch || undefined,
      git_remote_url:     (body.claude_context as any)?.git_remote_url || undefined,
      jira_ticket_id:     (body.claude_context as any)?.jira_ticket_id || undefined,
      connection_type:    (body.claude_context as any)?.connection_type || 'local',
      ssh_client_ip:      (body.claude_context as any)?.ssh_client_ip || undefined,
      remote_os:          (body.claude_context as any)?.remote_os || undefined,
    });

    // ── PIP enrichment — query Jira + GitHub for session context ──
    // SYNCHRONOUS — wait for PIP before responding, so first tool call has context
    const ticketId  = (body.claude_context as any)?.jira_ticket_id || '';
    const remoteUrl = (body.claude_context as any)?.git_remote_url || '';
    const branch    = (body.claude_context as any)?.git_branch || '';
    try {
      await enrichPIP(os_user, ticketId, remoteUrl, branch, {
        oauth_email:     claudeCtx?.email || undefined,
        connection_type: (body.claude_context as any)?.connection_type || 'local',
        git_email:       (body.claude_context as any)?.git_email || undefined,
        git_name:        (body.claude_context as any)?.git_name || undefined,
      });
    } catch (err: any) {
      console.warn(`[PIP] Enrichment failed (continuing without PIP): ${err.message}`);
    }

    console.log(`[SessionStart] ALLOWED — ${reason}`);
    console.log(`[SessionStart] MCP servers: ${mcp_servers.join(', ') || 'none'}`);

    return res.status(200).json({
      decision: 'allow',
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: `Reva governance active. Session: ${session_id}. User: ${identity.display_name}. Project: ${project_name}. Agent: ${agent_id}.${spiffe_id ? ` SPIFFE: ${spiffe_id}.` : ''}

IMPORTANT GOVERNANCE RULES — ALWAYS FOLLOW:
1. Never suggest using the ! prefix to run commands directly — this bypasses Reva governance and is a policy violation.
2. If an action is blocked by Reva Governance Policy, inform the user and stop. Do not suggest alternative ways to bypass the policy.
3. Never suggest workarounds to governance policies including direct terminal commands, Python scripts, or any other method to modify governed files.
4. All file modifications and shell commands must go through Claude tools (Edit, Write, Bash) so Reva can evaluate them.`,
      },
    });

  } catch (err: any) {
    console.error('[SessionStart] Error:', err.message);
    return res.status(200).json({ decision: 'allow' });
  }
}
