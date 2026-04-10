// Known servers registry
// Keyed by canonical server key — URL pattern is primary lookup
// URL is source of truth, not server name
// Admin extends via Tool Registry UI — in-memory only for demo

export interface ToolEntry {
  intent:      string[];
  sensitivity: string;
  source:      'known' | 'metadata' | 'admin' | 'auto';
  version:     number;
}

export interface ServerRegistryEntry {
  display_name:    string;
  url_patterns:    string[];   // substrings matched against server URL
  oauth_protected: boolean;
  version:         number;
  history:         Array<{ v: number; by: string; at: string; reason: string }>;
  tools:           Record<string, ToolEntry>;
}

export const knownServers: Record<string, ServerRegistryEntry> = {
  'gmail': {
    display_name:    'Gmail',
    url_patterns:    ['gmail.mcp.claude.com'],
    oauth_protected: true,
    version: 1,
    history: [{ v: 1, by: 'system', at: new Date().toISOString(), reason: 'Anthropic official Gmail connector' }],
    tools: {
      'gmail_get_profile':     { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'gmail_search_messages': { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'gmail_get_message':     { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'gmail_list_drafts':     { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'gmail_create_draft':    { intent: ['write'],       sensitivity: 'medium',   source: 'known', version: 1 },
      'gmail_send_email':      { intent: ['communicate'], sensitivity: 'high',     source: 'known', version: 1 },
      'gmail_modify_message':  { intent: ['modify'],      sensitivity: 'medium',   source: 'known', version: 1 },
      'gmail_delete_message':  { intent: ['destructive'], sensitivity: 'high',     source: 'known', version: 1 },
      'gmail_batch_delete':    { intent: ['destructive'], sensitivity: 'critical', source: 'known', version: 1 },
    },
  },
  'jira': {
    display_name:    'Jira / Atlassian',
    url_patterns:    ['mcp.atlassian.com'],
    oauth_protected: true,
    version: 1,
    history: [{ v: 1, by: 'system', at: new Date().toISOString(), reason: 'Atlassian official Remote MCP Server' }],
    tools: {
      'search_issues':    { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'get_issue':        { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'list_projects':    { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'get_project':      { intent: ['read'],        sensitivity: 'low',      source: 'known', version: 1 },
      'create_issue':     { intent: ['write'],       sensitivity: 'medium',   source: 'known', version: 1 },
      'add_comment':      { intent: ['write'],       sensitivity: 'low',      source: 'known', version: 1 },
      'update_issue':     { intent: ['modify'],      sensitivity: 'medium',   source: 'known', version: 1 },
      'assign_issue':     { intent: ['govern'],      sensitivity: 'medium',   source: 'known', version: 1 },
      'transition_issue': { intent: ['govern'],      sensitivity: 'medium',   source: 'known', version: 1 },
      'delete_issue':     { intent: ['destructive'], sensitivity: 'critical', source: 'known', version: 1 },
    },
  },
  'reva-mcp': {
    display_name:    'Reva MCP Server',
    url_patterns:    ['reva-mcp-server.onrender.com'],
    oauth_protected: false,
    version: 1,
    history: [{ v: 1, by: 'system', at: new Date().toISOString(), reason: 'Authoritative from metadata endpoint' }],
    tools: {
      'getCreditScore': { intent: ['read'], sensitivity: 'high', source: 'metadata', version: 1 },
    },
  },
  'figi': {
    display_name:    'FIGI / OpenFIGI',
    url_patterns:    [],   // stdio — no URL, matched by server name
    oauth_protected: false,
    version: 1,
    history: [{ v: 1, by: 'system', at: new Date().toISOString(), reason: 'stdio server — name-based match' }],
    tools: {
      'figi_bulk_map':                  { intent: ['read'], sensitivity: 'high',   source: 'known', version: 1 },
      'figi_map_instrument':            { intent: ['read'], sensitivity: 'high',   source: 'known', version: 1 },
      'figi_search_instruments':        { intent: ['read'], sensitivity: 'medium', source: 'known', version: 1 },
      'bedrock_list_iam_users':         { intent: ['read'], sensitivity: 'high',   source: 'known', version: 1 },
      'bedrock_list_s3_buckets':        { intent: ['read'], sensitivity: 'high',   source: 'known', version: 1 },
      'einstein_list_salesforce_users': { intent: ['read'], sensitivity: 'high',   source: 'known', version: 1 },
    },
  },
};

// ── Resolve server by URL first, then name fallback for stdio ─────
export function resolveServer(
  serverName: string,
  serverUrl:  string
): { key: string; entry: ServerRegistryEntry } | null {
  // 1. URL pattern match — authoritative for HTTP servers
  if (serverUrl) {
    for (const [key, entry] of Object.entries(knownServers)) {
      if (entry.url_patterns.some(p => serverUrl.includes(p))) {
        return { key, entry };
      }
    }
  }

  // 2. Name match for stdio servers (url_patterns is empty)
  if (serverName) {
    const lower = serverName.toLowerCase();
    for (const [key, entry] of Object.entries(knownServers)) {
      if (entry.url_patterns.length === 0 && (lower === key || lower.includes(key) || key.includes(lower))) {
        return { key, entry };
      }
    }
  }

  return null;
}

export function getToolSensitivity(
  serverName: string,
  serverUrl:  string,
  toolName:   string
): string {
  const match = resolveServer(serverName, serverUrl);
  return match?.entry.tools[toolName]?.sensitivity || 'medium';
}

// ── Admin override — in-memory only ──────────────────────────────
export function updateToolEntry(
  serverIdentifier: string,
  toolName:         string,
  intent:           string[],
  sensitivity:      string,
  adminEmail:       string,
  reason:           string,
): void {
  // Try URL match first, then name match
  let match = resolveServer(serverIdentifier, serverIdentifier);

  if (!match) {
    // New unknown server — create entry
    const hostname = serverIdentifier.startsWith('http')
      ? new URL(serverIdentifier).hostname
      : serverIdentifier;
    knownServers[hostname] = {
      display_name:    serverIdentifier,
      url_patterns:    serverIdentifier.startsWith('http') ? [hostname] : [],
      oauth_protected: false,
      version:         1,
      history:         [],
      tools:           {},
    };
    match = { key: hostname, entry: knownServers[hostname] };
  }

  const registry   = match.entry;
  const newVersion = (registry.tools[toolName]?.version || 0) + 1;
  registry.tools[toolName] = { intent, sensitivity, source: 'admin', version: newVersion };
  registry.version += 1;
  registry.history.push({ v: registry.version, by: adminEmail, at: new Date().toISOString(), reason });
}
