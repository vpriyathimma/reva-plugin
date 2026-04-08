import { Request, Response } from 'express';
import axios from 'axios';
import { issueConnectorToken } from './token';

export async function callback(req: Request, res: Response) {
  const { code, state } = req.query;
  const session = req.session as any;

  // Validate state to prevent CSRF
  if (!state || state !== session.oauthState) {
    return res.status(400).json({ error: 'Invalid state parameter' });
  }

  try {
    // Exchange code with Okta for tokens
    const tokenResponse = await axios.post(
      `https://${process.env.OKTA_DOMAIN}/oauth2/v1/token`,
      new URLSearchParams({
        grant_type:   'authorization_code',
        code:         code as string,
        redirect_uri: process.env.OKTA_REDIRECT_URI!,
        client_id:    process.env.OKTA_CLIENT_ID!,
        client_secret: process.env.OKTA_CLIENT_SECRET!,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, id_token } = tokenResponse.data;

    // Get user info from Okta
    const userInfo = await axios.get(
      `https://${process.env.OKTA_DOMAIN}/oauth2/v1/userinfo`,
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    const { email, name, groups } = userInfo.data;

    // Bind user identity to cowork instance
    const connectorPayload = {
      email,
      name,
      groups: groups || [],
      coworkClientId:  session.coworkClientId,
      coworkRedirectUri: session.coworkRedirectUri,
      requestedScopes: session.requestedScopes,
      enrolledAt: new Date().toISOString(),
    };

    // Issue Reva connector token
    const connectorToken = issueConnectorToken(connectorPayload);

    // Store identity in session for discovery phase
    session.user = { email, name, groups };
    session.connectorToken = connectorToken;

    // If Cowork redirect URI provided, redirect back to Cowork
    if (session.coworkRedirectUri) {
      return res.redirect(
        `${session.coworkRedirectUri}?token=${connectorToken}&state=${session.oauthState}`
      );
    }

    // Direct install — return token as JSON
    return res.json({
      status:          'connected',
      email,
      name,
      connector_token: connectorToken,
      enrolled_at:     connectorPayload.enrolledAt,
    });

  } catch (err: any) {
    console.error('OAuth callback error:', err.response?.data || err.message);
    return res.status(500).json({ error: 'Authentication failed' });
  }
}
