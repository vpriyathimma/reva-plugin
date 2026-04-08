import { ClassifiedTool } from './classifier';

export interface EnrolledSession {
  session_id:   string;
  user_email:   string;
  enrolled_at:  string;
  tools:        ClassifiedTool[];
  server_count: number;
  tool_count:   number;
  locked:       boolean;
}

// In-memory session store
export const sessionStore = new Map<string, EnrolledSession>();

// Decision log
export interface DecisionLog {
  timestamp:   string;
  session_id:  string;
  user_email:  string;
  tool:        string;
  server:      string;
  sensitivity: string;
  effect:      'Permit' | 'Deny' | 'HITL';
  reason:      string;
}

export const decisionLog: DecisionLog[] = [];

export function enrollSession(
  session_id: string,
  user_email: string,
  tools: ClassifiedTool[]
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
  };

  sessionStore.set(session_id, session);
  console.log(`Session enrolled: ${session_id} | user: ${user_email} | tools: ${tools.length}`);
  return session;
}

export function getSession(session_id: string): EnrolledSession | undefined {
  return sessionStore.get(session_id);
}

export function logDecision(entry: DecisionLog) {
  decisionLog.push(entry);
  console.log(`[PDP] ${entry.effect} | ${entry.user_email} | ${entry.tool} | ${entry.reason}`);
}
