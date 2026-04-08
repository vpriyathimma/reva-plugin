import { Request, Response } from 'express';
import axios from 'axios';
import { issueConnectorToken } from './token';
import { stateStore } from './authorize';

export async function callback(req: Request, res: Response) {
  const { code, state } = req.query;

  const stateContext = state ? stateStore.get(state as string) : null;
  if (state) stateStore.delete(state as string);

  try {
    // Exchange code — using default auth server
    const tokenResponse = await axios.post(
      `https://${process.env.OKTA_DOMAIN}/oauth2/default/v1/token`,
      new URLSearchParams({
        grant_type:    'authorization_code',
        code:          code as string,
        redirect_uri:  process.env.OKTA_REDIRECT_URI!,
        client_id:     process.env.OKTA_CLIENT_ID!,
        client_secret: process.env.OKTA_CLIENT_SECRET!,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token } = tokenResponse.data;

    // Get user info — using default auth server
    const userInfo = await axios.get(
      `https://${process.env.OKTA_DOMAIN}/oauth2/default/v1/userinfo`,
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    const { email, name, groups } = userInfo.data;

    const connectorPayload = {
      email,
      name,
      groups:            groups || [],
      coworkClientId:    stateContext?.coworkClientId || '',
      coworkRedirectUri: stateContext?.coworkRedirectUri || '',
      requestedScopes:   stateContext?.requestedScopes || '',
      enrolledAt:        new Date().toISOString(),
    };

    const connectorToken = issueConnectorToken(connectorPayload);

    if (stateContext?.coworkRedirectUri) {
      return res.redirect(
        `${stateContext.coworkRedirectUri}?token=${connectorToken}&state=${state}`
      );
    }

    return res.json({
      status:          'connected',
      email,
      name,
      connector_token: connectorToken,
      enrolled_at:     connectorPayload.enrolledAt,
    });

  } catch (err: any) {
    console.error('OAuth callback error:', err.response?.data || err.message);
    return res.status(500).json({ error: 'Authentication failed', detail: err.message });
  }
}
