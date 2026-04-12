import { Router } from 'express';

const router = Router();

const OKTA_DOMAIN     = process.env.OKTA_DOMAIN     || 'demo-ai-auth-raah.okta.com';
const OKTA_CLIENT_ID  = process.env.OKTA_CLIENT_ID  || '';
const PLUGIN_BASE_URL = process.env.PLUGIN_BASE_URL || 'https://reva-plugin.onrender.com';

// RFC 8414 — OAuth Authorization Server Metadata
// Cowork reads this to know where to send user for authentication
router.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer:                                PLUGIN_BASE_URL,
    authorization_endpoint:               `https://${OKTA_DOMAIN}/oauth2/v1/authorize`,
    token_endpoint:                        `${PLUGIN_BASE_URL}/oauth/token`,
    registration_endpoint:                 `${PLUGIN_BASE_URL}/oauth/register`,
    scopes_supported:                      ['openid', 'profile', 'email'],
    response_types_supported:              ['code'],
    grant_types_supported:                 ['authorization_code'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    code_challenge_methods_supported:      ['S256'],
  });
});

// Token endpoint — proxies to Okta org auth server
router.post('/oauth/token', async (req, res) => {
  try {
    const { code, redirect_uri, code_verifier, grant_type } = req.body;

    const params = new URLSearchParams({
      grant_type:    grant_type || 'authorization_code',
      code:          code       || '',
      redirect_uri:  redirect_uri || '',
      client_id:     OKTA_CLIENT_ID,
      client_secret: process.env.OKTA_CLIENT_SECRET || '',
    });

    if (code_verifier) params.set('code_verifier', code_verifier);

    const tokenRes = await fetch(
      `https://${OKTA_DOMAIN}/oauth2/v1/token`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body:    params.toString(),
      }
    );

    const data = await tokenRes.json();
    return res.status(tokenRes.status).json(data);

  } catch (err: any) {
    console.error('[OAuth/token] Error:', err.message);
    return res.status(500).json({ error: 'token_exchange_failed' });
  }
});

// Dynamic client registration — required by MCP OAuth spec
router.post('/oauth/register', (req, res) => {
  const { client_name, redirect_uris } = req.body;
  res.status(201).json({
    client_id:                  OKTA_CLIENT_ID,
    client_secret:              process.env.OKTA_CLIENT_SECRET || '',
    client_name:                client_name || 'Reva Governance Plugin',
    redirect_uris:              redirect_uris || [`${PLUGIN_BASE_URL}/oauth/callback`],
    grant_types:                ['authorization_code'],
    response_types:             ['code'],
    token_endpoint_auth_method: 'client_secret_post',
  });
});

export default router;
