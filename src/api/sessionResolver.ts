// Session Resolver — resolves developer identity from OS user + oauthEmail
// No hardcoded access gating — Cedar PDP makes all access decisions
// This module only resolves WHO the developer is, not WHETHER they're allowed

export interface SessionIdentity {
  os_user:      string;
  project_name: string;
  display_name: string;
  allowed_projects: string[];
  resolved_via?: string;  // 'os_user' | 'oauth_email'
}

// HITL email map — OS username → Okta email for Verify push
export const HITL_EMAIL_MAP: Record<string, string> = {
  saisrungaram: 'sai.srungaram@reva.ai',
  yashprakash:  'yash.prakash@reva.ai',
};

export function resolveHITLEmail(osUser: string): string {
  return HITL_EMAIL_MAP[osUser] || osUser;
}

// Developer profile — maps OS username → Cedar Developer entity attributes
export interface DeveloperProfile {
  user_role:       string;
  employment_type: string;
  department:      string;
}

const DEVELOPER_PROFILE: Record<string, DeveloperProfile> = {
  saisrungaram: {
    user_role:       'senior_engineer',
    employment_type: 'employee',
    department:      'engineering',
  },
  yashprakash: {
    user_role:       'engineer',
    employment_type: 'contractor',
    department:      'engineering',
  },
};

export function resolveDeveloperProfile(osUser: string): DeveloperProfile {
  return DEVELOPER_PROFILE[osUser] || {
    user_role:       'developer',
    employment_type: 'unknown',
    department:      'unknown',
  };
}

// Resolve session identity — always allows, Cedar makes access decisions
export function resolveSession(os_user: string, cwd: string, oauthEmail?: string): {
  allowed: boolean;
  identity: SessionIdentity;
  reason: string;
} {
  const project_name = cwd.split('/').pop() || '';
  const display_name = oauthEmail || os_user;

  return {
    allowed: true,
    identity: {
      os_user,
      project_name,
      display_name,
      allowed_projects: [],
      resolved_via: oauthEmail ? 'oauth_email' : 'os_user',
    },
    reason: `Session registered: ${display_name} (os_user: ${os_user}) in ${project_name || 'home directory'}`,
  };
}
