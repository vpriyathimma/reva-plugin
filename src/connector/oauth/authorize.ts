import { Request, Response } from 'express';
import crypto from 'crypto';

export function authorize(req: Request, res: Response) {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  // Store state + cowork context in session for callback validation
  (req.session as any).oauthState = state;
  (req.session as any).coworkClientId = req.query.client_id;
  (req.session as any).coworkRedirectUri = req.query.redirect_uri;
  (req.session as any).requestedScopes = req.query.scope;

  const params = new URLSearchParams({
    client_id:     process.env.OKTA_CLIENT_ID!,
    redirect_uri:  process.env.OKTA_REDIRECT_URI!,
    response_type: 'code',
    scope:         'openid profile email groups',
    state,
    nonce,
  });

  const oktaAuthUrl = `https://${process.env.OKTA_DOMAIN}/oauth2/v1/authorize?${params.toString()}`;
  res.redirect(oktaAuthUrl);
}
