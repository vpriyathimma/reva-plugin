import { Request, Response } from 'express';
import crypto from 'crypto';

export const stateStore = new Map<string, any>();

export function authorize(req: Request, res: Response) {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  stateStore.set(state, {
    coworkClientId:    req.query.client_id,
    coworkRedirectUri: req.query.redirect_uri,
    requestedScopes:   req.query.scope,
    createdAt:         Date.now(),
  });

  const params = new URLSearchParams({
    client_id:     process.env.OKTA_CLIENT_ID!,
    redirect_uri:  process.env.OKTA_REDIRECT_URI!,
    response_type: 'code',
    scope:         'openid profile email',
    state,
    nonce,
  });

  // Use ORG auth server — required so auth code can be exchanged
  // at org /token endpoint for ID token needed in ID-JAG exchange
  // Okta docs: "You must use the org authorization server for this step"
  const oktaAuthUrl = `https://${process.env.OKTA_DOMAIN}/oauth2/v1/authorize?${params.toString()}`;
  console.log('[authorize] Redirecting to org auth server:', oktaAuthUrl.split('?')[0]);
  res.redirect(oktaAuthUrl);
}
