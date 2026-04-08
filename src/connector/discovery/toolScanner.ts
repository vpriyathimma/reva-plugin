import axios from 'axios';
import { MCPServer } from './configReader';

export interface DiscoveredTool {
  server_name:       string;
  server_url:        string;
  server_type:       string;
  tool_name:         string;
  description:       string;
  input_schema:      any;
  preset_sensitivity?: string;
  hitl_required?:    boolean;
}

// ── Layer 1: RFC 9728 metadata endpoint (public, no auth) ─────────
// This is the preferred scan method — reads /.well-known/mcp-server-metadata
// Returns full tool list with sensitivity hints. No credentials needed.
async function scanMetadataEndpoint(server: MCPServer): Promise<DiscoveredTool[] | null> {
  try {
    const base    = server.url.replace(/\/mcp.*$/, '').replace(/\/$/, '');
    const metaUrl = `${base}/.well-known/mcp-server-metadata`;

    console.log(`[Scanner] Metadata scan: ${server.name} → ${metaUrl}`);

    const response = await axios.get(metaUrl, {
      timeout: 6000,
      headers: { 'Accept': 'application/json' },
    });

    const tools = response.data?.tools || [];
    if (!tools.length) {
      console.warn(`[Scanner] Metadata found but no tools listed for ${server.name}`);
      return null;
    }

    console.log(`[Scanner] Metadata scan success: ${server.name} → ${tools.length} tools`);

    return tools.map((t: any) => ({
      server_name:        server.name,
      server_url:         server.url,
      server_type:        response.data?.transport || 'http',
      tool_name:          t.name,
      description:        t.description || '',
      input_schema:       t.inputSchema || {},
      preset_sensitivity: t['x-reva-sensitivity'] || undefined,
      hitl_required:      t['x-reva-hitl-required'] || false,
    }));

  } catch (err: any) {
    console.warn(`[Scanner] No metadata endpoint for ${server.name}: ${err.message}`);
    return null;
  }
}

// ── Layer 2: Streamable HTTP POST tools/list ──────────────────────
// Used when no metadata endpoint exists. Works for modern MCP servers.
async function scanStreamableHttp(server: MCPServer): Promise<DiscoveredTool[] | null> {
  try {
    console.log(`[Scanner] HTTP scan: ${server.name}`);

    const response = await axios.post(
      server.url,
      { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
      {
        timeout: 8000,
        headers: {
          'Content-Type': 'application/json',
          'Accept':       'application/json',
        },
      }
    );

    const tools = response.data?.result?.tools || [];
    if (!tools.length) return null;

    console.log(`[Scanner] HTTP scan success: ${server.name} → ${tools.length} tools`);

    return tools.map((t: any) => ({
      server_name:  server.name,
      server_url:   server.url,
      server_type:  'http',
      tool_name:    t.name,
      description:  t.description || '',
      input_schema: t.inputSchema || {},
    }));

  } catch (err: any) {
    console.warn(`[Scanner] HTTP scan failed for ${server.name}: ${err.message}`);
    return null;
  }
}

// ── Layer 3: Stdio local server ───────────────────────────────────
// Cannot be scanned over network. Registered by name + command only.
// Classifier derives sensitivity from server name domain patterns.
function registerStdio(server: MCPServer): DiscoveredTool[] {
  console.log(`[Scanner] Stdio registered: ${server.name}`);
  return [{
    server_name:  server.name,
    server_url:   '',
    server_type:  'stdio',
    tool_name:    `${server.name}_local`,
    description:  `Local stdio server: ${server.command || server.name}`,
    input_schema: {},
  }];
}

// ── Fallback: server registered but unreachable ───────────────────
function registerUnreachable(server: MCPServer): DiscoveredTool[] {
  console.warn(`[Scanner] Unreachable: ${server.name} — registered without tools`);
  return [{
    server_name:  server.name,
    server_url:   server.url,
    server_type:  'unreachable',
    tool_name:    `${server.name}_service`,
    description:  `${server.name} — could not retrieve tools at scan time`,
    input_schema: {},
  }];
}

// ── Universal scanner: tries all methods in priority order ─────────
async function scanServer(server: MCPServer): Promise<DiscoveredTool[]> {
  // Stdio — never scannable over network
  if (server.type === 'stdio') return registerStdio(server);

  // Priority 1: metadata endpoint (public, no auth, preferred)
  const metadata = await scanMetadataEndpoint(server);
  if (metadata) return metadata;

  // Priority 2: streamable HTTP tools/list
  const http = await scanStreamableHttp(server);
  if (http) return http;

  // Priority 3: register as unreachable — classifier handles sensitivity
  return registerUnreachable(server);
}

export async function scanAllServers(servers: MCPServer[]): Promise<DiscoveredTool[]> {
  const results = await Promise.all(servers.map(scanServer));
  return results.flat();
}
