// Resolves agent name from client ID
// TODO: Replace with Okta API call when /api/v1/ai-agents endpoint is GA
// Okta AI Agents API is currently Early Access — no documented GET endpoint

const agentNameCache = new Map<string, string>();

// Known agents — update when Okta EA API becomes available
const KNOWN_AGENTS: Record<string, string> = {
  'wlp11ts2kssa3nS2f698': 'CoworkAICodingAgent',
};

export async function resolveAgentName(clientId: string): Promise<string> {
  if (!clientId) return 'CoworkAICodingAgent';
  if (agentNameCache.has(clientId)) return agentNameCache.get(clientId)!;

  const name = KNOWN_AGENTS[clientId] || clientId;
  agentNameCache.set(clientId, name);
  console.log(`[AgentResolver] ${clientId} → ${name}`);
  return name;
}
