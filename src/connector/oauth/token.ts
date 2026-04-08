import jwt from 'jsonwebtoken';

export interface ConnectorTokenPayload {
  email:             string;
  name:              string;
  groups:            string[];
  coworkClientId:    string;
  coworkRedirectUri: string;
  requestedScopes:   string;
  enrolledAt:        string;
}

export function issueConnectorToken(payload: ConnectorTokenPayload): string {
  return jwt.sign(
    {
      iss:   'https://reva-plugin.onrender.com',
      sub:   payload.email,
      aud:   'reva-cowork-connector',
      email: payload.email,
      name:  payload.name,
      groups: payload.groups,
      cowork_client_id:   payload.coworkClientId,
      cowork_redirect_uri: payload.coworkRedirectUri,
      scopes:             payload.requestedScopes,
      enrolled_at:        payload.enrolledAt,
    },
    process.env.JWT_SIGNING_SECRET!,
    { expiresIn: '8h' }
  );
}

export function verifyConnectorToken(token: string): ConnectorTokenPayload | null {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SIGNING_SECRET!) as any;
    return {
      email:             decoded.email,
      name:              decoded.name,
      groups:            decoded.groups,
      coworkClientId:    decoded.cowork_client_id,
      coworkRedirectUri: decoded.cowork_redirect_uri,
      requestedScopes:   decoded.scopes,
      enrolledAt:        decoded.enrolled_at,
    };
  } catch {
    return null;
  }
}
