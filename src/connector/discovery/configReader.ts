export type ServerType = 'http' | 'stdio';

export interface MCPServer {
  name:    string;
  url:     string;
  type:    ServerType;
  command?: string;
}

export interface DiscoveryPayload {
  servers:    MCPServer[];
  session_id: string;
  user_token: string;
}

export function parseDiscoveryPayload(body: any): DiscoveryPayload {
  if (!body || !Array.isArray(body.servers)) {
    throw new Error('Invalid discovery payload — servers array required');
  }

  const servers: MCPServer[] = body.servers
    .filter((s: any) => s.name)
    .map((s: any) => {
      const hasUrl = s.url && s.url.trim() !== '';
      return {
        name:    s.name.trim(),
        url:     s.url?.trim() || '',
        type:    hasUrl ? 'http' : 'stdio',
        command: s.command || '',
      };
    });

  return {
    servers,
    session_id: body.session_id || `session-${Date.now()}`,
    user_token: body.user_token || '',
  };
}

// Parse claude_desktop_config.json format directly
export function parseDesktopConfig(config: any): MCPServer[] {
  const mcpServers = config?.mcpServers || {};

  return Object.entries(mcpServers).map(([name, value]: [string, any]) => {
    const hasUrl = value.url && value.url.trim() !== '';
    return {
      name,
      url:     value.url?.trim() || '',
      type:    hasUrl ? 'http' : 'stdio',
      command: value.command ? `${value.command} ${(value.args || []).join(' ')}` : '',
    };
  });
}
