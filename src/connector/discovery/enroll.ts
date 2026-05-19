import { ClassifiedTool } from './classifier';

export interface EnrolledSession {
  session_id:    string;
  user_email:    string;
  enrolled_at:   string;
  tools:         ClassifiedTool[];
  server_count:  number;
  tool_count:    number;
  locked:        boolean;
  // Agent details (from enriched SessionStart)
  agent_id?:     string;
  os_type?:      string;
  hostname?:     string;
  model?:        string;
  mcp_servers_discovered?: string[];
  project_name?: string;
  // SPIRE workload identity
  spiffe_id?:      string;
  spire_entry_id?: string;
  oauth_email?:    string;
}

// In-memory session store
export const sessionStore = new Map<string, EnrolledSession>();

// Decision log — enriched with full classification for dashboard
export interface DecisionLog {
  timestamp:   string;
  session_id:  string;
  user_email:  string;
  tool:        string;
  server:      string;
  sensitivity: string;
  effect:      'Permit' | 'Deny' | 'HITL';
  reason:      string;
  // Classification context (optional — backward compatible)
  intent?:           string;
  trust_score?:      number;
  scores?:           Record<string, any>;
  prompt?:           string;
  prompt_history?:   string[];
  agent_type?:       string;
  command_risk?:     string;
  file_zone?:        string;
  // Cedar result
  cedar_decision?:    string;
  cedar_policy_name?: string;
  cedar_latency_ms?:  number;
  cedar_decision_id?: string;
}

export const decisionLog: DecisionLog[] = [];

export function enrollSession(
  session_id: string,
  user_email: string,
  tools: ClassifiedTool[],
  extra?: { agent_id?: string; os_type?: string; hostname?: string; model?: string; mcp_servers_discovered?: string[]; project_name?: string; spiffe_id?: string; spire_entry_id?: string; oauth_email?: string }
): EnrolledSession {
  const uniqueServers = [...new Set(tools.map(t => t.server_name))];

  const session: EnrolledSession = {
    session_id,
    user_email,
    enrolled_at:  new Date().toISOString(),
    tools,
    server_count: uniqueServers.length,
    tool_count:   tools.length,
    locked:       true,
    agent_id:              extra?.agent_id,
    os_type:               extra?.os_type,
    hostname:              extra?.hostname,
    model:                 extra?.model,
    mcp_servers_discovered: extra?.mcp_servers_discovered,
    project_name:          extra?.project_name,
    spiffe_id:             extra?.spiffe_id,
    spire_entry_id:        extra?.spire_entry_id,
    oauth_email:           extra?.oauth_email,
  };

  sessionStore.set(session_id, session);
  console.log(`Session enrolled: ${session_id} | user: ${user_email} | tools: ${tools.length} | agent: ${extra?.agent_id || 'none'} | spiffe: ${extra?.spiffe_id || 'none'} | model: ${extra?.model || 'plan default'}`);
  return session;
}

export function getSession(session_id: string): EnrolledSession | undefined {
  return sessionStore.get(session_id);
}

export function logDecision(entry: DecisionLog) {
  decisionLog.push(entry);
  console.log(`[PDP] ${entry.effect} | ${entry.user_email} | ${entry.tool} | ${entry.reason}`);
}
