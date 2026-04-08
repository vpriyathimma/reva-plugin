import axios from 'axios';
import { MCPServer } from './configReader';

export interface DiscoveredTool {
  server_name: string;
  server_url:  string;
  tool_name:   string;
  description: string;
  input_schema: any;
}

export async function scanServerTools(server: MCPServer): Promise<DiscoveredTool[]> {
  try {
    const response = await axios.post(
      server.url,
      {
        jsonrpc: '2.0',
        id:      1,
        method:  'tools/list',
        params:  {},
      },
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000,
      }
    );

    const tools = response.data?.result?.tools || [];

    return tools.map((tool: any) => ({
      server_name:  server.name,
      server_url:   server.url,
      tool_name:    tool.name,
      description:  tool.description || '',
      input_schema: tool.inputSchema || {},
    }));

  } catch (err: any) {
    console.warn(`Could not scan tools for ${server.name}: ${err.message}`);
    // Return server with unknown tools rather than failing entire discovery
    return [{
      server_name:  server.name,
      server_url:   server.url,
      tool_name:    'unknown',
      description:  'Could not retrieve tools',
      input_schema: {},
    }];
  }
}

export async function scanAllServers(servers: MCPServer[]): Promise<DiscoveredTool[]> {
  const results = await Promise.all(servers.map(scanServerTools));
  return results.flat();
}
