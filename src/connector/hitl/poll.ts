// HITL poll — checks Okta Verify push transaction status
// Polls until approved, denied, or timeout

const OKTA_API_TOKEN = process.env.OKTA_API_TOKEN || '';
const POLL_INTERVAL_MS = 3000;   // poll every 3 seconds
const POLL_TIMEOUT_MS  = 120000; // 2 minute timeout

export type HITLStatus = 'waiting' | 'approved' | 'denied' | 'timeout' | 'error';

export async function pollHITL(pollUrl: string): Promise<HITLStatus> {
  const start = Date.now();

  while (Date.now() - start < POLL_TIMEOUT_MS) {
    try {
      const res = await fetch(pollUrl, {
        headers: { Authorization: OKTA_API_TOKEN, Accept: 'application/json' },
      });

      if (!res.ok) {
        console.warn(`[HITL] Poll HTTP ${res.status}`);
        return 'error';
      }

      const data = await res.json() as any;
      const factorResult = data?.factorResult;

      console.log(`[HITL] Poll result: ${factorResult}`);

      if (factorResult === 'SUCCESS')  return 'approved';
      if (factorResult === 'REJECTED') return 'denied';
      if (factorResult === 'TIMEOUT')  return 'timeout';
      // factorResult === 'WAITING' → continue polling

    } catch (err: any) {
      console.error(`[HITL] Poll error: ${err.message}`);
      return 'error';
    }

    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
  }

  return 'timeout';
}
