export interface MCPServer {
  name: string;
  url:  string;
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
    .filter((s: any) => s.name && s.url)
    .map((s: any) => ({ name: s.name.trim(), url: s.url.trim() }));

  return {
    servers,
    session_id: body.session_id || `session-${Date.now()}`,
    user_token: body.user_token || '',
  };
}
