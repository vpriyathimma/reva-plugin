import { Request, Response } from 'express';
import axios from 'axios';
import { issueConnectorToken } from './token';
import { stateStore } from './authorize';

// Store Okta id_token keyed by email — used for ID-JAG exchange
// In-memory only, expires with session
export const idTokenStore = new Map<string, {
  id_token:   string;
  stored_at:  string;
}>();

export async function callback(req: Request, res: Response) {
  const { code, state, error, error_description } = req.query;

  if (error) return res.status(400).json({ error, error_description });
  if (!code)  return res.status(400).json({ error: 'No authorization code received' });

  const stateContext = state ? stateStore.get(state as string) : null;
  if (state) stateStore.delete(state as string);

  try {
    // ── Use ORG auth server — required for ID token + ID-JAG exchange ──
    // Okta docs: "You must use the org authorization server and not the
    // custom authorization server for this step."
    const tokenUrl = `https://${process.env.OKTA_DOMAIN}/oauth2/v1/token`;

    const tokenParams = new URLSearchParams({
      grant_type:    'authorization_code',
      code:          code as string,
      redirect_uri:  process.env.OKTA_REDIRECT_URI!,
      client_id:     process.env.OKTA_CLIENT_ID!,
      client_secret: process.env.OKTA_CLIENT_SECRET!,
    });

    console.log('[callback] Token exchange at org auth server:', tokenUrl);

    const tokenResponse = await axios.post(tokenUrl, tokenParams.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    const { access_token, id_token } = tokenResponse.data;

    console.log('[callback] id_token present:', !!id_token);
    console.log('[callback] access_token present:', !!access_token);

    // Get user info
    const userInfo = await axios.get(
      `https://${process.env.OKTA_DOMAIN}/oauth2/v1/userinfo`,
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    const { email, name } = userInfo.data;

    // Store id_token for ID-JAG exchange
    if (id_token) {
      idTokenStore.set(email, {
        id_token,
        stored_at: new Date().toISOString(),
      });
      console.log(`[callback] Stored id_token for ${email}`);
    }

    const connectorPayload = {
      email,
      name,
      groups:            [],
      coworkClientId:    stateContext?.coworkClientId    || '',
      coworkRedirectUri: stateContext?.coworkRedirectUri || '',
      requestedScopes:   stateContext?.requestedScopes   || '',
      enrolledAt:        new Date().toISOString(),
    };

    const connectorToken = issueConnectorToken(connectorPayload);

    return res.json({
      status:          'connected',
      email,
      name,
      connector_token: connectorToken,
      enrolled_at:     connectorPayload.enrolledAt,
    });

  } catch (err: any) {
    const detail = err.response?.data || err.message;
    console.error('[callback] OAuth error:', JSON.stringify(detail));
    return res.status(500).json({ error: 'Authentication failed', detail });
  }
}
