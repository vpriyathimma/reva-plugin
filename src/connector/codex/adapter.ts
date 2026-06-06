// ──────────────────────────────────────────────────────────────────────────
// Codex adapter — pure helpers for the Codex governance path.
//
// This file is ADDITIVE. It does not import from, modify, or affect any
// Claude Code hook handler. It only provides:
//   1. mapCodexToolToAction()  — Codex tool_name → Cedar action (Codex vocab)
//   2. extractCodexTarget()    — best-effort command/file extraction from tool_input
//   3. CODING_AGENT constant   — the discriminator stamped into every Codex decision
//
// The Cedar payload builders, evaluateCedar(), logDecision(), enrollSession(),
// PIP enrichment, and the prompt/injection classifiers are all reused VERBATIM
// from the existing modules via src/api/codexPdp.ts.
// ──────────────────────────────────────────────────────────────────────────

import { classifyMCPTool } from '../../api/pdpEvaluate';

export const CODING_AGENT = 'codex';

// Codex tool-name vocabulary differs from Claude Code's (read/write/edit/bash/…).
// Codex emits tools such as `shell` (exec), `apply_patch` (file mutations),
// `read_file`/`view`, MCP tools (server.tool / namespaced), `update_plan`,
// `web_search`. This map is intentionally separate from the Claude
// mapToolToAction() so the existing function is never touched.
//
// NOTE: the live `tool_name` values are logged on every PermissionRequest in
// codexPdp.ts ([CODEX:tool] raw=…). After the first local run, tune the cases
// below against whatever Codex actually sends — do not assume; read the log.
export function mapCodexToolToAction(toolName: string): string {
  const t = (toolName || '').toLowerCase();

  // Shell / exec → RunBash
  if (t === 'shell' || t === 'exec' || t === 'local_shell' || t === 'bash' || t === 'run' || t.includes('shell')) {
    return 'RunBash';
  }
  // File mutations → EditFile (apply_patch covers create + edit in Codex)
  if (t === 'apply_patch' || t === 'applypatch' || t === 'edit' || t === 'write' || t === 'write_file' || t === 'patch') {
    return 'EditFile';
  }
  // File reads → ReadFile
  if (t === 'read' || t === 'read_file' || t === 'view' || t === 'cat' || t === 'open' || t === 'list_dir' || t === 'glob' || t === 'grep' || t === 'ripgrep') {
    return 'ReadFile';
  }
  // MCP tools — Codex namespaces them; route through the existing MCP classifier
  if (t.startsWith('mcp__') || t.includes('.') || t.startsWith('mcp_')) {
    const leaf = t.startsWith('mcp__') ? (t.split('__')[2] || t) : (t.split('.').pop() || t);
    return classifyMCPTool(leaf);
  }
  // Web / search → treat as read
  if (t === 'web_search' || t === 'websearch' || t === 'fetch' || t === 'web_fetch') return 'ReadFile';

  // Default safe
  return 'ReadFile';
}

// True when the resolved action is the cross-tool shell gate.
export function isBashAction(action: string): boolean {
  return action === 'RunBash';
}

// Best-effort extraction of the governed target (command for shell, file path
// for apply_patch) from Codex's free-form tool_input. Never throws.
// Also detects the apply_patch operation: 'add' | 'update' | 'delete' — critical
// because apply_patch can DELETE files, which an agent will use to route around a
// blocked `rm`. Deletes must be classified destructive, not a benign edit.
export function extractCodexTarget(toolName: string, toolInput: any): { command: string; filePath: string; serverName: string; mcpTool: string; operation: string } {
  const out = { command: '', filePath: '', serverName: '', mcpTool: '', operation: '' };
  const t = (toolName || '').toLowerCase();
  try {
    // Shell — command may be a string or an argv array
    const cmd = toolInput?.command ?? toolInput?.cmd ?? toolInput?.script;
    if (cmd != null) {
      out.command = Array.isArray(cmd) ? cmd.join(' ') : String(cmd);
    }
    // apply_patch — pull the operation + first file path out of the patch envelope
    const patch = toolInput?.input ?? toolInput?.patch ?? '';
    if (typeof patch === 'string' && patch) {
      const m = patch.match(/\*\*\*\s+(Add|Update|Delete)\s+File:\s*(.+)/i);
      if (m) {
        out.operation = m[1].toLowerCase();   // add | update | delete
        if (!out.filePath) out.filePath = m[2].trim();
      }
    }
    // Explicit path fields
    if (!out.filePath) out.filePath = String(toolInput?.path ?? toolInput?.file_path ?? toolInput?.file ?? '');
    // Some shapes pass an explicit delete flag / op
    if (!out.operation) {
      const op = String(toolInput?.operation ?? toolInput?.op ?? toolInput?.type ?? '').toLowerCase();
      if (op.includes('delete') || op.includes('remove')) out.operation = 'delete';
    }
    // Shell deletes (rm / unlink / shred / git rm) — surface as destructive intent too
    if (!out.operation && out.command && /\b(rm|unlink|shred|trash)\b|\bgit\s+rm\b/.test(out.command)) {
      out.operation = 'delete';
    }
    // MCP — Codex passes server + tool when calling an MCP tool
    out.serverName = String(toolInput?.server ?? toolInput?.server_name ?? '');
    if (t.startsWith('mcp__')) {
      const parts = t.split('__');
      out.serverName = out.serverName || parts[1] || '';
      out.mcpTool    = parts[2] || toolName;
    } else if (t.includes('.')) {
      const parts = toolName.split('.');
      out.serverName = out.serverName || parts[0] || '';
      out.mcpTool    = parts.slice(1).join('.') || toolName;
    }
  } catch { /* best-effort only */ }
  return out;
}
