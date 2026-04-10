// HITL trigger — sends Okta Verify push to user
// Called when a high-sensitivity tool requires human approval

const OKTA_DOMAIN   = process.env.OKTA_DOMAIN    || 'demo-ai-auth-raah.okta.com';
const OKTA_API_TOKEN = process.env.OKTA_API_TOKEN || '';

// ── Step 1: Resolve user ID from email ───────────────────────────
async function getUserId(email: string): Promise<string | null> {
  try {
    const res = await fetch(
      `https://${OKTA_DOMAIN}/api/v1/users/${encodeURIComponent(email)}`,
      { headers: { Authorization: OKTA_API_TOKEN, Accept: 'application/json' } }
    );
    if (!res.ok) {
      console.warn(`[HITL] User lookup failed for ${email}: HTTP ${res.status}`);
      return null;
    }
    const data = await res.json() as any;
    return data.id || null;
  } catch (err: any) {
    console.error(`[HITL] getUserId error: ${err.message}`);
    return null;
  }
}

// ── Step 2: Find active Okta Verify push factor ───────────────────
async function getPushFactorId(userId: string): Promise<string | null> {
  try {
    const res = await fetch(
      `https://${OKTA_DOMAIN}/api/v1/users/${userId}/factors`,
      { headers: { Authorization: OKTA_API_TOKEN, Accept: 'application/json' } }
    );
    if (!res.ok) {
      console.warn(`[HITL] Factors lookup failed: HTTP ${res.status}`);
      return null;
    }
    const factors = await res.json() as any[];
    const push = factors.find(f =>
      f.factorType === 'push' &&
      f.provider   === 'OKTA' &&
      f.status     === 'ACTIVE'
    );
    return push?.id || null;
  } catch (err: any) {
    console.error(`[HITL] getPushFactorId error: ${err.message}`);
    return null;
  }
}

// ── Step 3: Send push challenge ───────────────────────────────────
async function sendPushChallenge(userId: string, factorId: string): Promise<string | null> {
  try {
    const res = await fetch(
      `https://${OKTA_DOMAIN}/api/v1/users/${userId}/factors/${factorId}/verify`,
      {
        method:  'POST',
        headers: {
          Authorization:  OKTA_API_TOKEN,
          'Content-Type': 'application/json',
          Accept:         'application/json',
        },
        body: JSON.stringify({}),
      }
    );
    if (!res.ok) {
      const err = await res.text();
      console.warn(`[HITL] Push challenge failed: HTTP ${res.status} — ${err}`);
      return null;
    }
    const data = await res.json() as any;
    // Okta returns a transaction URL in _links.poll.href
    const pollHref = data?._links?.poll?.href || null;
    console.log(`[HITL] Push sent. Poll URL: ${pollHref}`);
    return pollHref;
  } catch (err: any) {
    console.error(`[HITL] sendPushChallenge error: ${err.message}`);
    return null;
  }
}

// ── Main trigger ──────────────────────────────────────────────────
export interface HITLTriggerResult {
  success:   boolean;
  poll_url:  string | null;
  user_id:   string | null;
  factor_id: string | null;
  error?:    string;
}

export async function triggerHITL(
  userEmail: string,
  toolName:  string,
  sessionId: string
): Promise<HITLTriggerResult> {
  console.log(`[HITL] Triggering push for ${userEmail} → ${toolName}`);

  const userId = await getUserId(userEmail);
  if (!userId) {
    return { success: false, poll_url: null, user_id: null, factor_id: null, error: `User ${userEmail} not found in Okta` };
  }

  const factorId = await getPushFactorId(userId);
  if (!factorId) {
    return { success: false, poll_url: null, user_id: userId, factor_id: null, error: 'No active Okta Verify push factor found' };
  }

  const pollUrl = await sendPushChallenge(userId, factorId);
  if (!pollUrl) {
    return { success: false, poll_url: null, user_id: userId, factor_id: factorId, error: 'Push challenge failed' };
  }

  return { success: true, poll_url: pollUrl, user_id: userId, factor_id: factorId };
}
