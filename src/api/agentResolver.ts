// Resolves agent name from Okta using client ID (cid claim)
// Fetches from Okta API once per agent, caches in memory
// No hardcoding — single source of truth is Okta registry

const OKTA_DOMAIN    = process.env.OKTA_DOMAIN    || 'demo-ai-auth-raah.okta.com';
const OKTA_API_TOKEN = process.env.OKTA_API_TOKEN || '';

// In-memory cache — survives for lifetime of Render process
const agentNameCache = new Map<string, string>();

export async function resolveAgentName(clientId: string): Promise<string> {
  // Return from cache if available
  if (agentNameCache.has(clientId)) {
    return agentNameCache.get(clientId)!;
  }

  try {
    const res = await fetch(
      `https://${OKTA_DOMAIN}/api/v1/clients/${clientId}`,
      {
        headers: {
          Authorization: OKTA_API_TOKEN,
          Accept:        'application/json',
        },
      }
    );

    if (!res.ok) {
      console.warn(`[AgentResolver] Failed to resolve ${clientId}: HTTP ${res.status}`);
      return clientId; // fallback to clientId if Okta call fails
    }

    const data       = await res.json() as any;
    const agentName  = data.client_name || clientId;

    agentNameCache.set(clientId, agentName);
    console.log(`[AgentResolver] Resolved ${clientId} → ${agentName}`);

    return agentName;
  } catch (err: any) {
    console.error(`[AgentResolver] Error resolving ${clientId}: ${err.message}`);
    return clientId; // fallback to clientId
  }
}
