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

// ── Streamable HTTP (modern MCP) ──────────────────────────────────
async function scanStreamableHttp(server: MCPServer): Promise<DiscoveredTool[]> {
  const response = await axios.post(
    server.url,
    { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
    {
      headers: {
        'Content-Type':  'application/json',
        'Accept':        'application/json',
      },
      timeout: 8000,
    }
  );

  const tools = response.data?.result?.tools || [];
  if (!tools.length) throw new Error('No tools returned');

  return tools.map((t: any) => ({
    server_name:  server.name,
    server_url:   server.url,
    server_type:  'http',
    tool_name:    t.name,
    description:  t.description || '',
    input_schema: t.inputSchema || {},
  }));
}

// ── SSE transport (legacy MCP / SecureBank style) ─────────────────
async function scanSSE(server: MCPServer): Promise<DiscoveredTool[]> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('SSE timeout')), 10000);

    let sessionUrl = '';
    let tools: DiscoveredTool[] = [];
    let messageUrl = '';

    // Step 1: Connect to SSE endpoint to get session
    const EventSource = require('eventsource');
    const es = new EventSource(server.url, {
      headers: { 'Accept': 'text/event-stream' },
    });

    es.onmessage = async (event: any) => {
      try {
        const data = JSON.parse(event.data);

        // MCP SSE sends endpoint info as first message
        if (data.endpoint || typeof event.data === 'string' && event.data.startsWith('/')) {
          messageUrl = data.endpoint || event.data;
          if (!messageUrl.startsWith('http')) {
            const base = new URL(server.url);
            messageUrl = `${base.protocol}//${base.host}${messageUrl}`;
          }

          // Step 2: Send tools/list to the session endpoint
          try {
            const res = await axios.post(
              messageUrl,
              { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
              { headers: { 'Content-Type': 'application/json' }, timeout: 5000 }
            );
            const toolList = res.data?.result?.tools || [];
            tools = toolList.map((t: any) => ({
              server_name:  server.name,
              server_url:   server.url,
              server_type:  'sse',
              tool_name:    t.name,
              description:  t.description || '',
              input_schema: t.inputSchema || {},
            }));
          } catch (e) {
            // Tools/list may come back via SSE stream
          }
          es.close();
          clearTimeout(timeout);
          resolve(tools.length ? tools : fallback(server, 'sse'));
        }

        // MCP SSE may also return tools directly in stream
        if (data.result?.tools) {
          tools = data.result.tools.map((t: any) => ({
            server_name:  server.name,
            server_url:   server.url,
            server_type:  'sse',
            tool_name:    t.name,
            description:  t.description || '',
            input_schema: t.inputSchema || {},
          }));
          es.close();
          clearTimeout(timeout);
          resolve(tools);
        }
      } catch {}
    };

    es.onerror = () => {
      es.close();
      clearTimeout(timeout);
      reject(new Error('SSE connection failed'));
    };
  });
}

// ── Fallback for unreachable servers ──────────────────────────────
function fallback(server: MCPServer, type: string): DiscoveredTool[] {
  console.warn(`Registering ${server.name} without tool scan`);
  return [{
    server_name:  server.name,
    server_url:   server.url,
    server_type:  type,
    tool_name:    `${server.name}_service`,
    description:  `${server.name} — tools unavailable at scan time`,
    input_schema: {},
  }];
}

// ── Stdio servers ─────────────────────────────────────────────────
function registerStdio(server: MCPServer): DiscoveredTool[] {
  console.log(`Registering stdio: ${server.name}`);
  return [{
    server_name:  server.name,
    server_url:   '',
    server_type:  'stdio',
    tool_name:    `${server.name}_local`,
    description:  `Local stdio: ${server.command}`,
    input_schema: {},
  }];
}

// ── Universal scanner — tries all transports ──────────────────────
async function scanServer(server: MCPServer): Promise<DiscoveredTool[]> {
  if (server.type === 'stdio') return registerStdio(server);

  // Try streamable HTTP first
  try {
    console.log(`Trying HTTP scan: ${server.name}`);
    return await scanStreamableHttp(server);
  } catch (e1: any) {
    console.warn(`HTTP failed for ${server.name}: ${e1.message} — trying SSE`);
  }

  // Fall back to SSE
  try {
    console.log(`Trying SSE scan: ${server.name}`);
    return await scanSSE(server);
  } catch (e2: any) {
    console.warn(`SSE failed for ${server.name}: ${e2.message}`);
  }

  return fallback(server, 'unknown');
}

export async function scanAllServers(servers: MCPServer[]): Promise<DiscoveredTool[]> {
  const results = await Promise.all(servers.map(scanServer));
  return results.flat();
}
