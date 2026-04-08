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
    scope:         'openid profile email groups',
    state,
    nonce,
  });

  // Using default custom authorization server
  const oktaAuthUrl = `https://${process.env.OKTA_DOMAIN}/oauth2/default/v1/authorize?${params.toString()}`;
  res.redirect(oktaAuthUrl);
}
