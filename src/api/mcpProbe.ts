// MCP Client Probe — dynamic tool discovery via MCP protocol
// Calls initialize → tools/list on each server URL
// No hardcoded tools — everything from live MCP responses

// URL lookup — maps claude.ai server display names to MCP endpoints
// This is routing only, no tool/sensitivity data
const SERVER_URL_MAP: Record<string, string> = {
  'claude.ai Gmail':             'https://gmailmcp.googleapis.com/mcp/v1',
  'claude.ai Google Calendar':   'https://calendarmcp.googleapis.com/mcp/v1',
  'claude.ai Google Drive':      'https://drivemcp.googleapis.com/mcp/v1',
  'claude.ai Atlassian Rovo':    'https://mcp.atlassian.com/v1/mcp',
  'claude.ai REVAMCP':           'https://reva-mcp-server.onrender.com/mcp',
  'claude.ai REVA-AIGovernance': 'https://reva-plugin.onrender.com/mcp',
};

export interface DiscoveredTool {
  name:        string;
  description: string;
  readOnly:    boolean;
  destructive: boolean;
  sensitivity: string;  // auto-classified from annotations
  inputSchema?: any;
}

export interface ProbeResult {
  server_name:  string;
  server_url:   string;
  status:       'discovered' | 'auth_required' | 'unreachable';
  tools:        DiscoveredTool[];
  probed_at:    string;
  latency_ms:   number;
}

// In-memory store — keyed by server_name
export const discoveredServers = new Map<string, ProbeResult>();

// Dynamic tool store — tools captured via PreToolUse (for auth-required servers)
export const dynamicTools = new Map<string, Map<string, { tool_name: string; call_count: number; last_called: string; sensitivity: string }>>();

function classifySensitivity(annotations: any): string {
  if (!annotations) return 'medium';
  if (annotations.destructiveHint === true) return 'critical';
  if (annotations.readOnlyHint === true) return 'low';
  return 'medium'; // write operations
}

function resolveServerUrl(serverName: string): string | null {
  // Direct match
  if (SERVER_URL_MAP[serverName]) return SERVER_URL_MAP[serverName];
  // Partial match
  for (const [key, url] of Object.entries(SERVER_URL_MAP)) {
    if (serverName.toLowerCase().includes(key.toLowerCase().replace('claude.ai ', ''))) return url;
  }
  return null;
}

async function mcpCall(url: string, method: string, id: number, params?: any): Promise<any> {
  const body: any = { jsonrpc: '2.0', id, method };
  if (params) body.params = params;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }

  return res.json();
}

export async function probeServer(serverName: string, serverUrl?: string): Promise<ProbeResult> {
  const url = serverUrl || resolveServerUrl(serverName);
  const start = Date.now();

  if (!url) {
    const result: ProbeResult = {
      server_name: serverName, server_url: '', status: 'unreachable',
      tools: [], probed_at: new Date().toISOString(), latency_ms: 0,
    };
    discoveredServers.set(serverName, result);
    return result;
  }

  try {
    // Step 1: initialize
    const initResp = await mcpCall(url, 'initialize', 1, {
      protocolVersion: '2025-03-26',
      clientInfo: { name: 'reva-plugin', version: '1.0.0' },
      capabilities: {},
    });

    if (initResp.error) {
      // Auth required
      const result: ProbeResult = {
        server_name: serverName, server_url: url, status: 'auth_required',
        tools: [], probed_at: new Date().toISOString(), latency_ms: Date.now() - start,
      };
      discoveredServers.set(serverName, result);
      console.log(`[MCPProbe] ${serverName}: auth_required (${result.latency_ms}ms)`);
      return result;
    }

    // Step 2: tools/list
    const toolsResp = await mcpCall(url, 'tools/list', 2);
    const rawTools = toolsResp?.result?.tools || [];

    const tools: DiscoveredTool[] = rawTools.map((t: any) => ({
      name:        t.name,
      description: (t.description || t.annotations?.title || '').slice(0, 200),
      readOnly:    t.annotations?.readOnlyHint === true,
      destructive: t.annotations?.destructiveHint === true,
      sensitivity: classifySensitivity(t.annotations),
      inputSchema: t.inputSchema,
    }));

    const result: ProbeResult = {
      server_name: serverName, server_url: url, status: 'discovered',
      tools, probed_at: new Date().toISOString(), latency_ms: Date.now() - start,
    };
    discoveredServers.set(serverName, result);
    console.log(`[MCPProbe] ${serverName}: discovered ${tools.length} tools (${result.latency_ms}ms)`);
    return result;

  } catch (err: any) {
    const status = err.message.includes('401') || err.message.includes('invalid_token') ? 'auth_required' : 'unreachable';
    const result: ProbeResult = {
      server_name: serverName, server_url: url, status,
      tools: [], probed_at: new Date().toISOString(), latency_ms: Date.now() - start,
    };
    discoveredServers.set(serverName, result);
    console.log(`[MCPProbe] ${serverName}: ${status} — ${err.message.slice(0, 100)}`);
    return result;
  }
}

// Probe all servers — fire-and-forget, non-blocking
export function probeAllServers(serverNames: string[]): void {
  for (const name of serverNames) {
    // Skip self
    if (name.includes('REVA-AIGovernance')) continue;
    probeServer(name).catch(err => console.error(`[MCPProbe] ${name} failed:`, err.message));
  }
}

// Record a tool call from PreToolUse — builds inventory for auth-required servers
export function recordDynamicTool(serverName: string, toolName: string): void {
  if (!dynamicTools.has(serverName)) dynamicTools.set(serverName, new Map());
  const serverTools = dynamicTools.get(serverName)!;
  const existing = serverTools.get(toolName);
  serverTools.set(toolName, {
    tool_name:   toolName,
    call_count:  (existing?.call_count || 0) + 1,
    last_called: new Date().toISOString(),
    sensitivity: existing?.sensitivity || 'medium',
  });
}

// Get combined tools for a server (probe results + dynamic capture)
export function getServerTools(serverName: string): { source: 'probe' | 'dynamic'; tools: any[] } {
  const probed = discoveredServers.get(serverName);
  if (probed && probed.status === 'discovered' && probed.tools.length > 0) {
    return { source: 'probe', tools: probed.tools };
  }
  const dynamic = dynamicTools.get(serverName);
  if (dynamic && dynamic.size > 0) {
    return { source: 'dynamic', tools: Array.from(dynamic.values()) };
  }
  return { source: 'dynamic', tools: [] };
}

// Add a custom server URL mapping at runtime
export function registerServerUrl(name: string, url: string): void {
  SERVER_URL_MAP[name] = url;
}
