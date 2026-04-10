// Known servers registry
// Pre-populated for Gmail and Jira
// Admin extends via Tool Registry UI — version controlled
// Phase 9: intent values replaced by ML engine output

export interface ToolEntry {
  intent:      string[];
  sensitivity: string;
  source:      'known' | 'metadata' | 'admin' | 'auto';
  version:     number;
}

export interface ServerRegistry {
  [serverUrl: string]: {
    version:  number;
    history:  Array<{ v: number; by: string; at: string; reason: string }>;
    tools:    Record<string, ToolEntry>;
  };
}

export const knownServers: ServerRegistry = {
  'gmail.mcp.claude.com': {
    version: 1,
    history: [{ v: 1, by: 'system', at: new Date().toISOString(), reason: 'Initial population from Anthropic docs' }],
    tools: {
      'gmail_get_profile':       { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'gmail_search_messages':   { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'gmail_get_message':       { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'gmail_list_drafts':       { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'gmail_create_draft':      { intent: ['write'],       sensitivity: 'medium',   source: 'known', version: 1 },
      'gmail_send_email':        { intent: ['communicate'], sensitivity: 'high',     source: 'known', version: 1 },
      'gmail_modify_message':    { intent: ['modify'],      sensitivity: 'medium',   source: 'known', version: 1 },
      'gmail_delete_message':    { intent: ['destructive'], sensitivity: 'high',     source: 'known', version: 1 },
      'gmail_batch_delete':      { intent: ['destructive'], sensitivity: 'critical', source: 'known', version: 1 },
    },
  },
  'mcp.atlassian.com': {
    version: 1,
    history: [{ v: 1, by: 'system', at: new Date().toISOString(), reason: 'Initial population from Atlassian docs' }],
    tools: {
      'search_issues':           { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'get_issue':               { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'list_projects':           { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'get_project':             { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'create_issue':            { intent: ['write'],       sensitivity: 'medium',   source: 'known', version: 1 },
      'add_comment':             { intent: ['write'],       sensitivity: 'low',      source: 'known', version: 1 },
      'update_issue':            { intent: ['modify'],      sensitivity: 'medium',   source: 'known', version: 1 },
      'assign_issue':            { intent: ['govern'],      sensitivity: 'medium',   source: 'known', version: 1 },
      'transition_issue':        { intent: ['govern'],      sensitivity: 'medium',   source: 'known', version: 1 },
      'delete_issue':            { intent: ['destructive'], sensitivity: 'critical', source: 'known', version: 1 },
    },
  },
  'richard-unshunted-aubri.ngrok-free.dev': {
    version: 1,
    history: [{ v: 1, by: 'system', at: new Date().toISOString(), reason: 'Authoritative from metadata endpoint' }],
    tools: {
      'getCreditScore':          { intent: ['read'],        sensitivity: 'high',     source: 'metadata', version: 1 },
    },
  },
};

// ── Lookup ────────────────────────────────────────────────────────
export function getToolSensitivity(serverName: string, toolName: string): string {
  // Try exact URL match first
  for (const [url, registry] of Object.entries(knownServers)) {
    if (serverName.includes(url) || url.includes(serverName)) {
      const tool = registry.tools[toolName];
      if (tool) return tool.sensitivity;
    }
  }
  // Default medium for unknown tools
  return 'medium';
}

export function getToolEntry(serverName: string, toolName: string): ToolEntry | null {
  for (const [url, registry] of Object.entries(knownServers)) {
    if (serverName.includes(url) || url.includes(serverName)) {
      return registry.tools[toolName] || null;
    }
  }
  return null;
}

// ── Admin override ────────────────────────────────────────────────
export function updateToolEntry(
  serverUrl:   string,
  toolName:    string,
  intent:      string[],
  sensitivity: string,
  adminEmail:  string,
  reason:      string,
): void {
  if (!knownServers[serverUrl]) {
    knownServers[serverUrl] = {
      version: 1,
      history: [],
      tools:   {},
    };
  }
  const registry = knownServers[serverUrl];
  const newVersion = (registry.tools[toolName]?.version || 0) + 1;

  registry.tools[toolName] = {
    intent,
    sensitivity,
    source:  'admin',
    version: newVersion,
  };

  registry.version += 1;
  registry.history.push({
    v:      registry.version,
    by:     adminEmail,
    at:     new Date().toISOString(),
    reason,
  });
}
