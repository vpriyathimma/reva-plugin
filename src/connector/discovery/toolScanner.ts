import axios from 'axios';
import { MCPServer } from './configReader';

export interface DiscoveredTool {
  server_name:  string;
  server_url:   string;
  server_type:  string;
  tool_name:    string;
  description:  string;
  input_schema: any;
}

// ── Streamable HTTP (modern MCP 2025-03-26 spec) ──────────────────
async function scanStreamableHttp(server: MCPServer): Promise<DiscoveredTool[]> {
  const response = await axios.post(
    server.url,
    { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
    {
      headers: {
        'Content-Type': 'application/json',
        'Accept':       'application/json, text/event-stream',
      },
      timeout: 8000,
    }
  );

  // Handle both direct JSON and SSE-wrapped response
  let tools = [];
  if (response.data?.result?.tools) {
    tools = response.data.result.tools;
  } else if (typeof response.data === 'string') {
    // Parse SSE data lines from response
    const lines = response.data.split('\n');
    for (const line of lines) {
      if (line.startsWith('data:')) {
        try {
          const parsed = JSON.parse(line.slice(5).trim());
          if (parsed?.result?.tools) {
            tools = parsed.result.tools;
            break;
          }
        } catch {}
      }
    }
  }

  if (!tools.length) throw new Error('No tools in HTTP response');

  return tools.map((t: any) => ({
    server_name:  server.name,
    server_url:   server.url,
    server_type:  'http',
    tool_name:    t.name,
    description:  t.description || '',
    input_schema: t.inputSchema || {},
  }));
}

// ── SSE two-channel protocol (legacy MCP / SecureBank) ────────────
// Protocol:
//   1. GET /mcp  → SSE stream, server sends endpoint event
//   2. POST to that endpoint with tools/list
//   3. Result arrives back on the SSE stream
async function scanSSE(server: MCPServer): Promise<DiscoveredTool[]> {
  const EventSource = require('eventsource');

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      es.close();
      reject(new Error('SSE scan timeout after 12s'));
    }, 12000);

    let messageEndpoint = '';
    let tools: DiscoveredTool[] = [];
    let toolsRequested = false;

    const es = new EventSource(server.url);

    const done = (result: DiscoveredTool[]) => {
      clearTimeout(timeout);
      es.close();
      resolve(result);
    };

    const fail = (msg: string) => {
      clearTimeout(timeout);
      es.close();
      reject(new Error(msg));
    };

    // Handle named 'endpoint' event — MCP sends this first
    es.addEventListener('endpoint', async (event: any) => {
      try {
        let endpoint = event.data?.trim();
        if (!endpoint) return;

        // Build full URL if relative
        if (!endpoint.startsWith('http')) {
          const base = new URL(server.url);
          endpoint = `${base.protocol}//${base.host}${endpoint}`;
        }

        messageEndpoint = endpoint;

        if (!toolsRequested) {
          toolsRequested = true;
          // POST tools/list to the session endpoint
          // Response comes back via SSE message event
          await axios.post(
            messageEndpoint,
            { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
            { headers: { 'Content-Type': 'application/json' }, timeout: 5000 }
          ).catch(() => {}); // POST response is 202 Accepted, actual result via SSE
        }
      } catch (e: any) {
        fail(`Endpoint handler error: ${e.message}`);
      }
    });

    // Handle message events — tools/list result arrives here
    es.onmessage = (event: any) => {
      try {
        const data = JSON.parse(event.data);

        // Check if this is the tools/list result
        if (data?.result?.tools) {
          tools = data.result.tools.map((t: any) => ({
            server_name:  server.name,
            server_url:   server.url,
            server_type:  'sse',
            tool_name:    t.name,
            description:  t.description || '',
            input_schema: t.inputSchema || {},
          }));
          done(tools);
          return;
        }

        // Some servers send endpoint in message event (not named event)
        if (typeof event.data === 'string' && event.data.includes('/mcp/')) {
          const endpoint = event.data.trim();
          if (!messageEndpoint && !toolsRequested) {
            messageEndpoint = endpoint.startsWith('http')
              ? endpoint
              : `${new URL(server.url).protocol}//${new URL(server.url).host}${endpoint}`;
            toolsRequested = true;
            axios.post(
              messageEndpoint,
              { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
              { headers: { 'Content-Type': 'application/json' }, timeout: 5000 }
            ).catch(() => {});
          }
        }
      } catch {}
    };

    es.onerror = (err: any) => {
      if (tools.length > 0) {
        done(tools);
      } else {
        fail('SSE connection error');
      }
    };
  });
}

// ── Stdio (local process) ─────────────────────────────────────────
function registerStdio(server: MCPServer): DiscoveredTool[] {
  return [{
    server_name:  server.name,
    server_url:   '',
    server_type:  'stdio',
    tool_name:    `${server.name}_local`,
    description:  `Local stdio server: ${server.command}`,
    input_schema: {},
  }];
}

// ── Fallback ──────────────────────────────────────────────────────
function fallback(server: MCPServer): DiscoveredTool[] {
  console.warn(`All scans failed for ${server.name} — registering as unreachable`);
  return [{
    server_name:  server.name,
    server_url:   server.url,
    server_type:  'unreachable',
    tool_name:    `${server.name}_service`,
    description:  `${server.name} — could not retrieve tools at scan time`,
    input_schema: {},
  }];
}

// ── Universal scanner ─────────────────────────────────────────────
async function scanServer(server: MCPServer): Promise<DiscoveredTool[]> {
  if (server.type === 'stdio') return registerStdio(server);

  // Try streamable HTTP first
  try {
    console.log(`[Scanner] HTTP scan: ${server.name}`);
    return await scanStreamableHttp(server);
  } catch (e1: any) {
    console.warn(`[Scanner] HTTP failed (${server.name}): ${e1.message}`);
  }

  // Try SSE two-channel
  try {
    console.log(`[Scanner] SSE scan: ${server.name}`);
    return await scanSSE(server);
  } catch (e2: any) {
    console.warn(`[Scanner] SSE failed (${server.name}): ${e2.message}`);
  }

  return fallback(server);
}

export async function scanAllServers(servers: MCPServer[]): Promise<DiscoveredTool[]> {
  const results = await Promise.all(servers.map(scanServer));
  return results.flat();
}
