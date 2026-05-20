// PIP — Policy Information Point
// Queries Jira + GitHub at SessionStart, caches per session
// Results flow into Cedar context at every beforeToolCall

export interface JiraContext {
  jira_ticket_exists:    boolean;
  jira_ticket_id:        string;
  jira_summary:          string;
  jira_assignee:         string;
  jira_assignee_email:   string;
  jira_status:           string;
  jira_component:        string;
  jira_labels:           string[];
  jira_sprint:           string;
  jira_appsec_review:    boolean;
  jira_error?:           string;
}

export interface GitHubContext {
  github_repo:             string;
  github_repo_owner:       string;
  github_branch:           string;
  github_branch_protected: boolean;
  github_default_branch:   string;
  github_visibility:       string;  // 'public' | 'private'
  github_error?:           string;
}

export interface PIPContext {
  jira:   JiraContext;
  github: GitHubContext;
  // Identity fields (stored alongside PIP for consistent lookup)
  oauth_email?:     string;
  connection_type?: string;
}

// ── Store PIP results per developer (os_user key — consistent across hooks) ──
const pipStore = new Map<string, PIPContext>();

export function getPIPContext(key: string): PIPContext | undefined {
  return pipStore.get(key);
}

export function setPIPContext(key: string, ctx: PIPContext): void {
  pipStore.set(key, ctx);
}

// ── Jira Query ──
const JIRA_BASE_URL = (process.env.JIRA_BASE_URL || '').replace(/\/+$/, '');
const JIRA_EMAIL    = process.env.JIRA_EMAIL || '';
const JIRA_TOKEN    = process.env.JIRA_API_TOKEN || '';

export async function queryJira(ticketId: string): Promise<JiraContext> {
  const empty: JiraContext = {
    jira_ticket_exists:  false,
    jira_ticket_id:      ticketId || '',
    jira_summary:        '',
    jira_assignee:       '',
    jira_assignee_email: '',
    jira_status:         '',
    jira_component:      '',
    jira_labels:         [],
    jira_sprint:         '',
    jira_appsec_review:  false,
  };

  if (!ticketId || !JIRA_BASE_URL || !JIRA_EMAIL || !JIRA_TOKEN) {
    empty.jira_error = !ticketId ? 'no_ticket_id' : 'jira_not_configured';
    return empty;
  }

  try {
    const auth = Buffer.from(`${JIRA_EMAIL}:${JIRA_TOKEN}`).toString('base64');
    const resp = await fetch(
      `${JIRA_BASE_URL}/rest/api/3/issue/${ticketId}?fields=summary,assignee,status,components,labels,sprint,customfield_10020`,
      {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Accept': 'application/json',
        },
        signal: AbortSignal.timeout(5000),
      }
    );

    if (!resp.ok) {
      console.warn(`[PIP:Jira] HTTP ${resp.status} for ${ticketId}`);
      return { ...empty, jira_error: `http_${resp.status}` };
    }

    const data = await resp.json() as any;
    const fields = data.fields || {};

    // Extract sprint from customfield_10020 (Jira Software sprint field)
    const sprints = fields.customfield_10020 || [];
    const activeSprint = Array.isArray(sprints)
      ? sprints.find((s: any) => s.state === 'active')
      : null;

    // Check for AppSec/security labels
    const labels: string[] = fields.labels || [];
    const appsecReview = labels.some((l: string) =>
      /appsec|security[_-]?review|sec[_-]?approved/i.test(l)
    );

    // Components
    const components = (fields.components || []).map((c: any) => c.name).join(', ');

    const result: JiraContext = {
      jira_ticket_exists:  true,
      jira_ticket_id:      ticketId,
      jira_summary:        fields.summary || '',
      jira_assignee:       fields.assignee?.displayName || '',
      jira_assignee_email: fields.assignee?.emailAddress || '',
      jira_status:         fields.status?.name || '',
      jira_component:      components,
      jira_labels:         labels,
      jira_sprint:         activeSprint?.name || '',
      jira_appsec_review:  appsecReview,
    };

    // Jira Cloud v3 often hides email — fetch via user API if missing
    if (!result.jira_assignee_email && fields.assignee?.accountId) {
      try {
        const userResp = await fetch(
          `${JIRA_BASE_URL}/rest/api/3/user?accountId=${fields.assignee.accountId}`,
          {
            headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' },
            signal: AbortSignal.timeout(3000),
          }
        );
        if (userResp.ok) {
          const userData = await userResp.json() as any;
          result.jira_assignee_email = userData.emailAddress || '';
        }
      } catch { /* non-blocking */ }
    }

    console.log(`[PIP:Jira] ${ticketId}: assignee=${result.jira_assignee}, email=${result.jira_assignee_email || 'NOT_AVAILABLE'}, status=${result.jira_status}, component=${result.jira_component}, appsec=${result.jira_appsec_review}`);
    return result;
  } catch (err: any) {
    console.warn(`[PIP:Jira] Failed for ${ticketId}: ${err.message}`);
    return { ...empty, jira_error: err.message };
  }
}

// ── GitHub Query ──
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';

function parseGitRemoteUrl(remoteUrl: string): { owner: string; repo: string } | null {
  // Handle: https://github.com/owner/repo.git, git@github.com:owner/repo.git
  const m = remoteUrl.match(/github\.com[:/]([^/]+)\/([^/.]+)/);
  if (m) return { owner: m[1], repo: m[2] };
  return null;
}

export async function queryGitHub(remoteUrl: string, branch: string): Promise<GitHubContext> {
  const empty: GitHubContext = {
    github_repo:             '',
    github_repo_owner:       '',
    github_branch:           branch || '',
    github_branch_protected: false,
    github_default_branch:   '',
    github_visibility:       '',
  };

  const parsed = parseGitRemoteUrl(remoteUrl || '');
  if (!parsed || !GITHUB_TOKEN) {
    empty.github_error = !parsed ? 'invalid_remote_url' : 'github_not_configured';
    return empty;
  }

  const { owner, repo } = parsed;
  empty.github_repo = `${owner}/${repo}`;
  empty.github_repo_owner = owner;

  try {
    // Repo details
    const repoResp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      signal: AbortSignal.timeout(5000),
    });

    if (repoResp.ok) {
      const repoData = await repoResp.json() as any;
      empty.github_default_branch = repoData.default_branch || 'main';
      empty.github_visibility = repoData.visibility || 'private';
    }

    // Branch protection — check if branch is protected
    // Protected branches: main, master, release/*, production, or GitHub-configured
    const conventionProtected = /^(main|master|production|release\/.*)$/.test(branch || '');

    if (branch && !conventionProtected) {
      // Check GitHub branch protection API
      try {
        const branchResp = await fetch(
          `https://api.github.com/repos/${owner}/${repo}/branches/${branch}/protection`,
          {
            headers: {
              'Authorization': `Bearer ${GITHUB_TOKEN}`,
              'Accept': 'application/vnd.github+json',
              'X-GitHub-Api-Version': '2022-11-28',
            },
            signal: AbortSignal.timeout(5000),
          }
        );
        // 200 = protected, 404 = not protected
        empty.github_branch_protected = branchResp.ok;
      } catch {
        empty.github_branch_protected = false;
      }
    } else {
      empty.github_branch_protected = conventionProtected;
    }

    const result: GitHubContext = { ...empty };
    console.log(`[PIP:GitHub] ${owner}/${repo}@${branch}: protected=${result.github_branch_protected}, visibility=${result.github_visibility}, default=${result.github_default_branch}`);
    return result;
  } catch (err: any) {
    console.warn(`[PIP:GitHub] Failed: ${err.message}`);
    return { ...empty, github_error: err.message };
  }
}

// ── Combined enrichment ──
export async function enrichSession(
  osUser: string,
  ticketId: string,
  remoteUrl: string,
  branch: string,
  identityFields?: { oauth_email?: string; connection_type?: string }
): Promise<PIPContext> {
  const [jira, github] = await Promise.all([
    queryJira(ticketId),
    queryGitHub(remoteUrl, branch),
  ]);

  const ctx: PIPContext = {
    jira,
    github,
    oauth_email:     identityFields?.oauth_email,
    connection_type: identityFields?.connection_type,
  };
  setPIPContext(osUser, ctx);

  console.log(`[PIP] Developer ${osUser} enriched: jira=${jira.jira_ticket_exists ? jira.jira_ticket_id : 'none'}, github=${github.github_repo || 'none'}, branch_protected=${github.github_branch_protected}`);
  return ctx;
}
