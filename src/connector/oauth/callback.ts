import { Request, Response } from 'express';
import axios from 'axios';
import { issueConnectorToken } from './token';
import { stateStore } from './authorize';

export async function callback(req: Request, res: Response) {
  const { code, state, error, error_description } = req.query;

  // Handle Okta errors returned to callback
  if (error) {
    return res.status(400).json({ error, error_description });
  }

  if (!code) {
    return res.status(400).json({ error: 'No authorization code received' });
  }

  const stateContext = state ? stateStore.get(state as string) : null;
  if (state) stateStore.delete(state as string);

  try {
    const tokenUrl = `https://${process.env.OKTA_DOMAIN}/oauth2/default/v1/token`;

    const tokenParams = new URLSearchParams({
      grant_type:    'authorization_code',
      code:          code as string,
      redirect_uri:  process.env.OKTA_REDIRECT_URI!,
      client_id:     process.env.OKTA_CLIENT_ID!,
      client_secret: process.env.OKTA_CLIENT_SECRET!,
    });

    console.log('Token exchange URL:', tokenUrl);
    console.log('Redirect URI used:', process.env.OKTA_REDIRECT_URI);

    const tokenResponse = await axios.post(tokenUrl, tokenParams.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const { access_token } = tokenResponse.data;

    // Get user info
    const userInfo = await axios.get(
      `https://${process.env.OKTA_DOMAIN}/oauth2/default/v1/userinfo`,
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    const { email, name } = userInfo.data;

    const connectorPayload = {
      email,
      name,
      groups:            [],
      coworkClientId:    stateContext?.coworkClientId || '',
      coworkRedirectUri: stateContext?.coworkRedirectUri || '',
      requestedScopes:   stateContext?.requestedScopes || '',
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
    console.error('OAuth callback error:', JSON.stringify(detail));
    return res.status(500).json({ error: 'Authentication failed', detail });
  }
}
