import { Router } from 'express';
import { createSign, createPrivateKey } from 'crypto';
import { idTokenStore } from '../connector/oauth/callback';
import { verifyConnectorToken } from '../connector/oauth/token';

const router = Router();

const OKTA_DOMAIN      = process.env.OKTA_DOMAIN || 'demo-ai-auth-raah.okta.com';
const COWORK_AGENT_ID  = process.env.COWORK_AGENT_ID || '';
const COWORK_AGENT_KEY = process.env.COWORK_AGENT_PRIVATE_KEY || '';

function buildClientAssertion(audience: string): string {
  const privateKeyJwk = JSON.parse(COWORK_AGENT_KEY);
  const privateKey    = createPrivateKey({ key: privateKeyJwk, format: 'jwk' });
  const now           = Math.floor(Date.now() / 1000);

  const header  = Buffer.from(JSON.stringify({ alg: 'RS256', kid: privateKeyJwk.kid, typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: COWORK_AGENT_ID, sub: COWORK_AGENT_ID, aud: audience,
    iat: now, exp: now + 300, jti: Math.random().toString(36).slice(2),
  })).toString('base64url');

  const sign = createSign('RSA-SHA256');
  sign.update(`${header}.${payload}`);
  return `${header}.${payload}.${sign.sign(privateKey, 'base64url')}`;
}

async function exchangeForIDJAG(idToken: string): Promise<any> {
  const audience        = `https://${OKTA_DOMAIN}/oauth2/default`;
  const clientAssertion = buildClientAssertion(`https://${OKTA_DOMAIN}/oauth2/v1/token`);

  const params = new URLSearchParams({
    grant_type:            'urn:ietf:params:oauth:grant-type:token-exchange',
    requested_token_type:  'urn:ietf:params:oauth:token-type:id-jag',
    subject_token:         idToken,
    subject_token_type:    'urn:ietf:params:oauth:token-type:id_token',
    client_id:             COWORK_AGENT_ID,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion:      clientAssertion,
    audience,
    scope:                 'MCPTool:Read MCPTool:Write MCPTool:Communicate MCPTool:Modify MCPTool:Govern MCPTool:Destructive',
  });

  const res  = await fetch(`https://${OKTA_DOMAIN}/oauth2/v1/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  return { status: res.status, data: await res.json() };
}

async function exchangeForFinalAT(idJAG: string): Promise<any> {
  const clientAssertion = buildClientAssertion(`https://${OKTA_DOMAIN}/oauth2/default/v1/token`);

  const params = new URLSearchParams({
    grant_type:            'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion:             idJAG,
    client_id:             COWORK_AGENT_ID,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion:      clientAssertion,
  });

  const res  = await fetch(`https://${OKTA_DOMAIN}/oauth2/default/v1/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  return { status: res.status, data: await res.json() };
}

// ── GET /api/test/idjag — uses stored id_token from last login ────
router.get('/test/idjag', async (req, res) => {
  const auth  = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  const user  = verifyConnectorToken(token);

  if (!user) return res.status(401).json({ error: 'Invalid connector token' });

  const stored = idTokenStore.get(user.email);
  if (!stored) {
    return res.json({
      error: 'No id_token stored for this user',
      instructions: [
        '1. Login fresh: https://reva-plugin.onrender.com/oauth/authorize',
        '2. Copy connector_token from response',
        '3. Call this endpoint with Authorization: Bearer <connector_token>',
      ],
    });
  }

  if (!COWORK_AGENT_ID || !COWORK_AGENT_KEY) {
    return res.status(500).json({ error: 'COWORK_AGENT_ID or COWORK_AGENT_PRIVATE_KEY not set' });
  }

  try {
    console.log(`[IDJAG-TEST] Starting exchange for ${user.email}`);

    // Step 1: ID token → ID-JAG
    const step1 = await exchangeForIDJAG(stored.id_token);
    if (step1.status !== 200 || !step1.data.access_token) {
      return res.json({ step: 'Step 1 — ID token → ID-JAG', status: step1.status, error: step1.data });
    }

    const idJAG     = step1.data.access_token;
    const jagClaims = JSON.parse(Buffer.from(idJAG.split('.')[1], 'base64url').toString());
    console.log('[IDJAG-TEST] Step 1 success:', jagClaims);

    // Step 2: ID-JAG → final AT
    const step2 = await exchangeForFinalAT(idJAG);
    if (step2.status !== 200 || !step2.data.access_token) {
      return res.json({ step1_success: true, idjag_claims: jagClaims, step: 'Step 2 — ID-JAG → final AT', status: step2.status, error: step2.data });
    }

    const finalClaims = JSON.parse(Buffer.from(step2.data.access_token.split('.')[1], 'base64url').toString());
    console.log('[IDJAG-TEST] Step 2 success:', finalClaims);

    return res.json({
      success:        true,
      step1_idjag:    { scope: step1.data.scope, claims: jagClaims },
      step2_final_at: { scope: step2.data.scope, expires_in: step2.data.expires_in, claims: finalClaims },
      validation: {
        has_act_claim:    !!finalClaims.act,
        act_sub:          finalClaims.act?.sub || 'NOT PRESENT',
        human_sub:        finalClaims.sub,
        scopes:           finalClaims.scp,
        agent_id_matches: finalClaims.act?.sub === COWORK_AGENT_ID,
      },
    });

  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

export default router;
