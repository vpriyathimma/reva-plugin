// HITL Configuration — admin-configurable, Slack integration
// Stores config in memory (persists until Render restart)
// Slack: apply token → fetch channels → send approval messages → receive button clicks

export interface HITLConfig {
  enabled:                boolean;
  integration:            'slack' | 'okta' | 'webhook';
  slack_bot_token:        string;
  slack_channel:          string;
  slack_channel_id:       string;
  slack_connected:        boolean;
  approver_email:         string;
  approval_expiry_minutes: number;
}

// In-memory config — admin updates via dashboard
let config: HITLConfig = {
  enabled:                false,
  integration:            'slack',
  slack_bot_token:        '',
  slack_channel:          '',
  slack_channel_id:       '',
  slack_connected:        false,
  approver_email:         '',
  approval_expiry_minutes: 60,
};

// Approval store — tracks pending and completed approvals
export interface ApprovalRecord {
  id:              string;
  developer_email: string;
  developer_name:  string;
  action:          string;
  resource:        string;
  project:         string;
  branch:          string;
  ticket:          string;
  status:          'pending' | 'approved' | 'denied';
  requested_at:    string;
  resolved_at?:    string;
  resolved_by?:    string;
  expires_at:      string;
  slack_ts?:       string;
}

const approvalStore = new Map<string, ApprovalRecord>();

// ── Config CRUD ──

export function getHITLConfig(): HITLConfig {
  return { ...config };
}

export function updateHITLConfig(updates: Partial<HITLConfig>): HITLConfig {
  config = { ...config, ...updates };
  return { ...config };
}

// ── Approval CRUD ──

export function getApproval(id: string): ApprovalRecord | undefined {
  return approvalStore.get(id);
}

export function findApprovalForDeveloper(
  developerEmail: string,
  action: string,
  project: string
): ApprovalRecord | undefined {
  for (const record of approvalStore.values()) {
    if (
      record.developer_email === developerEmail &&
      record.action === action &&
      record.project === project &&
      record.status === 'approved' &&
      new Date(record.expires_at) > new Date()
    ) {
      return record;
    }
  }
  return undefined;
}

// ── Slack API ──

const SLACK_API = 'https://slack.com/api';

async function slackPost(method: string, token: string, body: any): Promise<any> {
  const resp = await fetch(`${SLACK_API}/${method}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type':  'application/json; charset=utf-8',
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
  return resp.json();
}

async function slackGet(method: string, token: string, params?: Record<string, string>): Promise<any> {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  const resp = await fetch(`${SLACK_API}/${method}${qs}`, {
    headers: { 'Authorization': `Bearer ${token}` },
    signal: AbortSignal.timeout(5000),
  });
  return resp.json();
}

// Test token validity
export async function testSlackToken(token: string): Promise<{ ok: boolean; team?: string; error?: string }> {
  try {
    const data = await slackGet('auth.test', token);
    if (data.ok) return { ok: true, team: data.team };
    return { ok: false, error: data.error };
  } catch (err: any) {
    return { ok: false, error: err.message };
  }
}

// Fetch channels
export async function fetchSlackChannels(token: string): Promise<{ id: string; name: string }[]> {
  try {
    const data = await slackGet('conversations.list', token, {
      types: 'public_channel',
      limit: '100',
      exclude_archived: 'true',
    });
    if (!data.ok) return [];
    return (data.channels || []).map((c: any) => ({ id: c.id, name: c.name }));
  } catch {
    return [];
  }
}

// Send test message
export async function sendSlackTestMessage(token: string, channel: string): Promise<{ ok: boolean; error?: string }> {
  try {
    const data = await slackPost('chat.postMessage', token, {
      channel,
      text: 'Reva Governance HITL — test connection successful',
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: ':white_check_mark: *Reva Governance — HITL Connected*\nThis channel will receive approval requests when developers trigger protected actions.',
          },
        },
      ],
    });
    return { ok: data.ok, error: data.error };
  } catch (err: any) {
    return { ok: false, error: err.message };
  }
}

// Send approval request
export async function sendSlackApprovalRequest(record: ApprovalRecord): Promise<{ ok: boolean; ts?: string; error?: string }> {
  if (!config.slack_bot_token || !config.slack_channel_id) {
    return { ok: false, error: 'Slack not configured' };
  }

  try {
    const data = await slackPost('chat.postMessage', config.slack_bot_token, {
      channel: config.slack_channel_id,
      text: `Approval required: ${record.developer_name} wants to ${record.action} on ${record.project}`,
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: ':lock: Approval required' },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Developer*\n${record.developer_name}\n${record.developer_email}` },
            { type: 'mrkdwn', text: `*Action*\n${record.action}` },
            { type: 'mrkdwn', text: `*Project*\n${record.project}` },
            { type: 'mrkdwn', text: `*Branch*\n${record.branch || '—'}` },
            { type: 'mrkdwn', text: `*Ticket*\n${record.ticket || '—'}` },
            { type: 'mrkdwn', text: `*Resource*\n\`${record.resource}\`` },
          ],
        },
        {
          type: 'actions',
          block_id: `hitl_${record.id}`,
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: 'Approve' },
              style: 'primary',
              action_id: 'hitl_approve',
              value: record.id,
            },
            {
              type: 'button',
              text: { type: 'plain_text', text: 'Deny' },
              style: 'danger',
              action_id: 'hitl_deny',
              value: record.id,
            },
          ],
        },
        {
          type: 'context',
          elements: [
            { type: 'mrkdwn', text: `Requested at ${new Date(record.requested_at).toLocaleTimeString()} — expires in ${config.approval_expiry_minutes} min` },
          ],
        },
      ],
    });

    return { ok: data.ok, ts: data.ts, error: data.error };
  } catch (err: any) {
    return { ok: false, error: err.message };
  }
}

// Update Slack message after approval/denial
async function updateSlackMessage(ts: string, record: ApprovalRecord): Promise<void> {
  if (!config.slack_bot_token || !config.slack_channel_id) return;

  const emoji = record.status === 'approved' ? ':white_check_mark:' : ':x:';
  const label = record.status === 'approved' ? 'Approved' : 'Denied';
  const color = record.status === 'approved' ? '#22c55e' : '#ef4444';

  try {
    await slackPost('chat.update', config.slack_bot_token, {
      channel: config.slack_channel_id,
      ts,
      text: `${label}: ${record.developer_name} — ${record.action} on ${record.project}`,
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: `${emoji} ${label}` },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Developer*\n${record.developer_name}` },
            { type: 'mrkdwn', text: `*Action*\n${record.action}` },
            { type: 'mrkdwn', text: `*Project*\n${record.project}` },
            { type: 'mrkdwn', text: `*Resolved by*\n${record.resolved_by || '—'}` },
          ],
        },
        {
          type: 'context',
          elements: [
            { type: 'mrkdwn', text: `${label} at ${new Date(record.resolved_at || '').toLocaleTimeString()}` },
          ],
        },
      ],
    });
  } catch { /* non-blocking */ }
}

// Handle Slack interactive button click
export async function handleSlackInteraction(payload: any): Promise<{ ok: boolean }> {
  const action = payload?.actions?.[0];
  if (!action) return { ok: false };

  const approvalId = action.value;
  const actionId   = action.action_id;
  const user       = payload.user?.name || payload.user?.real_name || 'unknown';

  const record = approvalStore.get(approvalId);
  if (!record) return { ok: false };

  if (record.status !== 'pending') return { ok: true };

  record.status      = actionId === 'hitl_approve' ? 'approved' : 'denied';
  record.resolved_at = new Date().toISOString();
  record.resolved_by = user;
  approvalStore.set(approvalId, record);

  console.log(`[HITL:Slack] ${record.status.toUpperCase()} by ${user} — ${record.developer_email} ${record.action} on ${record.project}`);

  // Update the Slack message to show resolved state
  if (record.slack_ts) {
    await updateSlackMessage(record.slack_ts, record);
  }

  return { ok: true };
}

// ── Trigger HITL ──

export async function triggerHITL(details: {
  developer_email: string;
  developer_name:  string;
  action:          string;
  resource:        string;
  project:         string;
  branch:          string;
  ticket:          string;
}): Promise<ApprovalRecord> {
  const id = `hitl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const now = new Date();
  const expires = new Date(now.getTime() + config.approval_expiry_minutes * 60 * 1000);

  const record: ApprovalRecord = {
    id,
    ...details,
    status:       'pending',
    requested_at: now.toISOString(),
    expires_at:   expires.toISOString(),
  };

  approvalStore.set(id, record);

  // Send Slack message
  if (config.integration === 'slack' && config.slack_connected) {
    const result = await sendSlackApprovalRequest(record);
    if (result.ok && result.ts) {
      record.slack_ts = result.ts;
      approvalStore.set(id, record);
    }
  }

  return record;
}

// Clean up expired approvals
setInterval(() => {
  const now = new Date();
  for (const [id, record] of approvalStore) {
    if (record.status === 'pending' && new Date(record.expires_at) < now) {
      record.status = 'denied';
      record.resolved_at = now.toISOString();
      record.resolved_by = 'system (expired)';
      approvalStore.set(id, record);
    }
  }
}, 60_000);

// ── API Routes ──

import { Router, Request, Response } from 'express';

export const hitlRouter = Router();

hitlRouter.get('/config/hitl', (_req: Request, res: Response) => {
  const cfg = getHITLConfig();
  res.json({ ...cfg, slack_bot_token: cfg.slack_bot_token ? '••••••' + cfg.slack_bot_token.slice(-8) : '' });
});

hitlRouter.post('/config/hitl', (req: Request, res: Response) => {
  const updates = req.body;
  if (updates.slack_bot_token && updates.slack_bot_token.startsWith('••••')) delete updates.slack_bot_token;
  const cfg = updateHITLConfig(updates);
  res.json({ ...cfg, slack_bot_token: cfg.slack_bot_token ? '••••••' + cfg.slack_bot_token.slice(-8) : '' });
});

hitlRouter.post('/hitl/slack/apply-token', async (req: Request, res: Response) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ ok: false, error: 'Token required' });
  const result = await testSlackToken(token);
  if (result.ok) {
    updateHITLConfig({ slack_bot_token: token, slack_connected: true });
    console.log(`[HITL] Slack token applied — workspace: ${result.team}`);
    res.json({ ok: true, team: result.team });
  } else {
    res.json({ ok: false, error: result.error });
  }
});

hitlRouter.get('/hitl/slack/channels', async (_req: Request, res: Response) => {
  const cfg = getHITLConfig();
  if (!cfg.slack_bot_token) return res.json({ ok: false, channels: [], error: 'No token' });
  const channels = await fetchSlackChannels(cfg.slack_bot_token);
  res.json({ ok: true, channels });
});

hitlRouter.post('/hitl/slack/test', async (req: Request, res: Response) => {
  const cfg = getHITLConfig();
  const channel = req.body.channel || cfg.slack_channel_id || cfg.slack_channel;
  if (!cfg.slack_bot_token || !channel) return res.status(400).json({ ok: false, error: 'Token and channel required' });
  const result = await sendSlackTestMessage(cfg.slack_bot_token, channel);
  if (result.ok) console.log(`[HITL] Test message sent to ${channel}`);
  res.json(result);
});

hitlRouter.post('/hitl/slack/interact', async (req: Request, res: Response) => {
  try {
    const rawPayload = req.body.payload || req.body;
    const payload = typeof rawPayload === 'string' ? JSON.parse(rawPayload) : rawPayload;
    await handleSlackInteraction(payload);
    res.status(200).send('');
  } catch (err: any) {
    console.error(`[HITL:Slack] Interaction error: ${err.message}`);
    res.status(200).send('');
  }
});
