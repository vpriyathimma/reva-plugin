// ──────────────────────────────────────────────────────────────────────────
// Kiro adapter — pure helpers for the Kiro governance path.
//
// This file is ADDITIVE. It does not import from, modify, or affect any
// Claude Code or Codex hook handler. It only provides:
//   1. mapKiroToolToAction()  — Kiro tool_name → Cedar action (Kiro vocab)
//   2. extractKiroTarget()    — best-effort command/file extraction from tool_input
//   3. CODING_AGENT constant  — the discriminator stamped into every Kiro decision
//
// The Cedar payload builders, evaluateCedar(), logDecision(), enrollSession(),
// PIP enrichment, and the prompt/injection classifiers are all reused VERBATIM
// from the existing modules via src/api/kiroPdp.ts.
// ──────────────────────────────────────────────────────────────────────────

import { classifyMCPTool } from '../../api/pdpEvaluate';

export const CODING_AGENT = 'kiro';

// Kiro tool vocabulary. Kiro CLI/IDE emit tools such as `fs_write`, `fs_read`,
// `execute_bash`, `code` (search), `use_aws`, `glob`, `grep`, and MCP tools
// (namespaced as `mcp__server__tool` or `@server/tool`).
//
// NOTE: the live `tool_name` values are logged on every preToolUse in
// kiroPdp.ts ([KIRO:tool] raw=…). After the first local run, tune the cases
// below against whatever Kiro actually sends — do not assume; read the log.
export function mapKiroToolToAction(toolName: string): string {
  const t = (toolName || '').toLowerCase();

  // Shell / exec → RunBash
  if (t === 'execute_bash' || t === 'shell' || t === 'bash' || t === 'exec'
      || t === 'run_command' || t === 'local_shell' || t.includes('execute_bash')) {
    return 'RunBash';
  }
  // File write/create → WriteFile
  if (t === 'fs_write' || t === 'write' || t === 'write_file' || t === 'create_file') {
    return 'WriteFile';
  }
  // File edit/replace → EditFile
  if (t === 'fs_edit' || t === 'edit' || t === 'replace' || t === 'str_replace'
      || t === 'apply_patch' || t === 'patch' || t === 'edit_file') {
    return 'EditFile';
  }
  // File reads → ReadFile
  if (t === 'fs_read' || t === 'read' || t === 'read_file' || t === 'view'
      || t === 'cat' || t === 'open' || t === 'list_dir' || t === 'list_directory'
      || t === 'glob' || t === 'grep' || t === 'ripgrep' || t === 'code'
      || t === 'search_files') {
    return 'ReadFile';
  }
  // AWS operations → treat as MCP-level exec
  if (t === 'use_aws' || t.startsWith('aws_') || t.startsWith('use_aws')) {
    return 'MCPExecute';
  }
  // MCP tools — Kiro namespaces them as mcp__server__tool or @server/tool
  if (t.startsWith('mcp__') || t.startsWith('@') || t.includes('.') || t.startsWith('mcp_')) {
    let leaf = t;
    if (t.startsWith('mcp__')) {
      leaf = t.split('__')[2] || t;
    } else if (t.startsWith('@')) {
      leaf = t.split('/').pop() || t;
    } else if (t.includes('.')) {
      leaf = t.split('.').pop() || t;
    }
    return classifyMCPTool(leaf);
  }
  // Web / search → treat as read
  if (t === 'web_search' || t === 'web_fetch' || t === 'fetch' || t === 'websearch') return 'ReadFile';

  // Default safe
  return 'ReadFile';
}

// True when the resolved action is the cross-tool shell gate.
export function isBashAction(action: string): boolean {
  return action === 'RunBash';
}

// Best-effort extraction of the governed target (command for shell, file path
// for file ops) from Kiro's tool_input. Never throws.
export function extractKiroTarget(
  toolName: string,
  toolInput: any,
): { command: string; filePath: string; serverName: string; mcpTool: string; operation: string } {
  const out = { command: '', filePath: '', serverName: '', mcpTool: '', operation: '' };
  const t = (toolName || '').toLowerCase();
  try {
    // Shell — command may be a string or an argv array
    const cmd = toolInput?.command ?? toolInput?.cmd ?? toolInput?.script ?? toolInput?.input;
    if (cmd != null && (t.includes('bash') || t.includes('shell') || t.includes('exec'))) {
      out.command = Array.isArray(cmd) ? cmd.join(' ') : String(cmd);
    }

    // File path — Kiro uses `path`, `file_path`, or `file`
    if (!out.filePath) {
      out.filePath = String(toolInput?.path ?? toolInput?.file_path ?? toolInput?.file ?? '');
    }

    // Operation detection
    if (!out.operation) {
      const op = String(toolInput?.operation ?? toolInput?.op ?? toolInput?.type ?? '').toLowerCase();
      if (op.includes('delete') || op.includes('remove')) out.operation = 'delete';
      else if (op.includes('create') || op.includes('add')) out.operation = 'add';
      else if (op.includes('update') || op.includes('edit')) out.operation = 'update';
    }

    // fs_write is always a write/create
    if (!out.operation && (t === 'fs_write' || t === 'write_file' || t === 'create_file')) {
      out.operation = 'add';
    }

    // Shell deletes (rm / unlink / shred / git rm) — surface as destructive intent
    if (!out.operation && out.command && /\b(rm|unlink|shred|trash)\b|\bgit\s+rm\b/.test(out.command)) {
      out.operation = 'delete';
    }

    // MCP — Kiro passes server + tool when calling an MCP tool
    out.serverName = String(toolInput?.server ?? toolInput?.server_name ?? '');
    if (t.startsWith('mcp__')) {
      const parts = t.split('__');
      out.serverName = out.serverName || parts[1] || '';
      out.mcpTool    = parts[2] || toolName;
    } else if (t.startsWith('@')) {
      const slashIdx = t.indexOf('/');
      out.serverName = out.serverName || t.slice(1, slashIdx) || '';
      out.mcpTool    = t.slice(slashIdx + 1) || toolName;
    } else if (t.includes('.')) {
      const parts = toolName.split('.');
      out.serverName = out.serverName || parts[0] || '';
      out.mcpTool    = parts.slice(1).join('.') || toolName;
    }
  } catch { /* best-effort only */ }
  return out;
}
