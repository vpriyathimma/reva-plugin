// HITL callback — stores approval/denial, wires into hitlStore
// Called by background poller after Okta Verify response

import { hitlStore } from '../hooks/beforeToolCall';

export interface HITLRecord {
  session_id:   string;
  tool_name:    string;
  user_email:   string;
  status:       'pending' | 'approved' | 'denied' | 'timeout' | 'error';
  triggered_at: string;
  resolved_at?: string;
  poll_url?:    string;
}

// In-memory HITL audit log
export const hitlLog: HITLRecord[] = [];

export function recordHITLApproval(
  sessionId:  string,
  toolName:   string,
  userEmail:  string,
  pollUrl?:   string
): void {
  const hitlKey = `${sessionId}:${toolName}`;

  hitlStore.set(hitlKey, {
    acknowledged: true,
    approved_at:  new Date().toISOString(),
    tool_name:    toolName,
  });

  hitlLog.push({
    session_id:   sessionId,
    tool_name:    toolName,
    user_email:   userEmail,
    status:       'approved',
    triggered_at: new Date().toISOString(),
    resolved_at:  new Date().toISOString(),
    poll_url:     pollUrl,
  });

  console.log(`[HITL] Approved: ${userEmail} → ${toolName} | session: ${sessionId}`);
}

export function recordHITLDenial(
  sessionId:  string,
  toolName:   string,
  userEmail:  string,
  status:     'denied' | 'timeout' | 'error',
  pollUrl?:   string
): void {
  hitlLog.push({
    session_id:   sessionId,
    tool_name:    toolName,
    user_email:   userEmail,
    status,
    triggered_at: new Date().toISOString(),
    resolved_at:  new Date().toISOString(),
    poll_url:     pollUrl,
  });

  console.log(`[HITL] ${status}: ${userEmail} → ${toolName} | session: ${sessionId}`);
}

export function getHITLStatus(sessionId: string, toolName: string): HITLRecord | null {
  const key = `${sessionId}:${toolName}`;
  return [...hitlLog].reverse().find(r => `${r.session_id}:${r.tool_name}` === key) || null;
}
