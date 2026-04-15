// Session Resolver — maps OS user + project_name to access decision
// Admin defines the access matrix here
// No email mapping — only OS user and project name

export interface SessionIdentity {
  os_user:      string;
  project_name: string;
  display_name: string;
  allowed_projects: string[];
}

// HITL email map — OS username → Okta email for Verify push
export const HITL_EMAIL_MAP: Record<string, string> = {
  saisrungaram: 'sai.srungaram@reva.ai',
  yashprakash:  'yash.prakash@reva.ai',
};

export function resolveHITLEmail(osUser: string): string {
  return HITL_EMAIL_MAP[osUser] || osUser;
}

// Access matrix — admin controlled
// os_user → allowed project names
const ACCESS_MATRIX: Record<string, { display_name: string; allowed_projects: string[] }> = {
  saisrungaram: {
    display_name:     'Sai (Admin)',
    allowed_projects: ['claude-demo-project', 'claude-stage-project', 'reva-cowork-plugin'],
  },
  mike: {
    display_name:     'Mike',
    allowed_projects: ['claude-stage-project'],
  },
  kevin: {
    display_name:     'Kevin',
    allowed_projects: [],
  },
};

export function resolveSession(os_user: string, cwd: string): {
  allowed: boolean;
  identity: SessionIdentity;
  reason: string;
} {
  const project_name = cwd.split('/').pop() || '';
  const entry        = ACCESS_MATRIX[os_user];

  if (!entry) {
    return {
      allowed:  false,
      identity: { os_user, project_name, display_name: os_user, allowed_projects: [] },
      reason:   `OS user '${os_user}' is not registered in Reva access matrix`,
    };
  }

  const allowed = entry.allowed_projects.includes(project_name);

  return {
    allowed,
    identity: {
      os_user,
      project_name,
      display_name:     entry.display_name,
      allowed_projects: entry.allowed_projects,
    },
    reason: allowed
      ? `Access granted: ${entry.display_name} is allowed to access ${project_name}`
      : `Access denied: ${entry.display_name} is not allowed to access ${project_name}. Allowed projects: [${entry.allowed_projects.join(', ') || 'none'}]`,
  };
}
