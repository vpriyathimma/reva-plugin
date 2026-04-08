import { DiscoveredTool } from './toolScanner';

export type Sensitivity = 'low' | 'medium' | 'high' | 'critical';

export interface ClassifiedTool extends DiscoveredTool {
  sensitivity:        Sensitivity;
  sensitivity_reason: string;
}

// ── Layer 1: Domain classifier ────────────────────────────────────
type Domain =
  | 'email'
  | 'project_management'
  | 'code_repository'
  | 'cloud_infrastructure'
  | 'financial_data'
  | 'database'
  | 'messaging'
  | 'crm'
  | 'calendar'
  | 'file_storage'
  | 'identity'
  | 'unknown';

const DOMAIN_PATTERNS: Array<{ patterns: string[]; domain: Domain }> = [
  { patterns: ['gmail', 'outlook', 'mail', 'email', 'smtp', 'imap'],                          domain: 'email' },
  { patterns: ['jira', 'linear', 'asana', 'trello', 'monday', 'clickup', 'notion', 'height'], domain: 'project_management' },
  { patterns: ['github', 'gitlab', 'bitbucket', 'git'],                                        domain: 'code_repository' },
  { patterns: ['aws', 'gcp', 'azure', 'bedrock', 's3', 'lambda', 'ec2', 'iam', 'cloud'],      domain: 'cloud_infrastructure' },
  { patterns: ['figi', 'bloomberg', 'credit', 'finance', 'bank', 'payment', 'reva-mcp'],       domain: 'financial_data' },
  { patterns: ['postgres', 'mysql', 'mongo', 'redis', 'database', 'sql', 'db'],               domain: 'database' },
  { patterns: ['slack', 'teams', 'discord', 'telegram', 'chat'],                              domain: 'messaging' },
  { patterns: ['salesforce', 'hubspot', 'crm', 'zendesk', 'intercom'],                        domain: 'crm' },
  { patterns: ['gcal', 'calendar', 'google-calendar', 'outlook-calendar'],                    domain: 'calendar' },
  { patterns: ['drive', 'dropbox', 'box', 'onedrive', 'gdrive', 'sharepoint', 'storage'],     domain: 'file_storage' },
  { patterns: ['okta', 'auth0', 'ldap', 'active-directory', 'identity', 'iam'],               domain: 'identity' },
];

function classifyDomain(serverName: string, serverUrl: string): Domain {
  const combined = `${serverName} ${serverUrl}`.toLowerCase();
  for (const { patterns, domain } of DOMAIN_PATTERNS) {
    if (patterns.some(p => combined.includes(p))) return domain;
  }
  return 'unknown';
}

// ── Domain-only sensitivity (for stdio — no tool list available) ──
const DOMAIN_ONLY_SENSITIVITY: Record<Domain, Sensitivity> = {
  email:                'medium',
  project_management:   'low',
  code_repository:      'high',
  cloud_infrastructure: 'high',
  financial_data:       'high',
  database:             'high',
  messaging:            'medium',
  crm:                  'medium',
  calendar:             'low',
  file_storage:         'medium',
  identity:             'critical',
  unknown:              'medium',
};

// ── Layer 2: Action classifier ────────────────────────────────────
type Action =
  | 'read'
  | 'write'
  | 'modify'
  | 'destroy'
  | 'distribute'
  | 'execute'
  | 'govern'
  | 'unknown';

const ACTION_PATTERNS: Array<{ patterns: string[]; action: Action }> = [
  { patterns: ['delete', 'remove', 'drop', 'purge', 'destroy', 'truncate', 'archive'],                         action: 'destroy' },
  { patterns: ['execute', 'run', 'invoke', 'deploy', 'trigger', 'launch', 'start', 'stop', 'restart'],         action: 'execute' },
  { patterns: ['send', 'publish', 'post', 'share', 'forward', 'broadcast', 'notify', 'email', 'message'],      action: 'distribute' },
  { patterns: ['approve', 'authorize', 'assign', 'close', 'reject', 'escalate', 'resolve', 'transition'],      action: 'govern' },
  { patterns: ['update', 'edit', 'modify', 'patch', 'change', 'set', 'put', 'replace', 'rename', 'move'],      action: 'modify' },
  { patterns: ['create', 'add', 'insert', 'draft', 'new', 'write', 'upload', 'push', 'commit', 'merge'],       action: 'write' },
  { patterns: ['get', 'read', 'list', 'fetch', 'search', 'find', 'view', 'download', 'export', 'query', 'lookup', 'check', 'score', 'report', 'analyze', 'audit'], action: 'read' },
];

function classifyAction(toolName: string, description: string): Action {
  const combined = `${toolName} ${description}`.toLowerCase();
  for (const { patterns, action } of ACTION_PATTERNS) {
    if (patterns.some(p => combined.includes(p))) return action;
  }
  return 'unknown';
}

// ── Layer 3: Domain × Action sensitivity matrix ───────────────────
type SensitivityMatrix = Record<Domain, Record<Action, Sensitivity>>;

const MATRIX: SensitivityMatrix = {
  email: {
    read: 'low', write: 'medium', modify: 'medium', destroy: 'high',
    distribute: 'high', execute: 'high', govern: 'medium', unknown: 'medium',
  },
  project_management: {
    read: 'low', write: 'low', modify: 'low', destroy: 'medium',
    distribute: 'low', execute: 'medium', govern: 'medium', unknown: 'low',
  },
  code_repository: {
    read: 'medium', write: 'high', modify: 'high', destroy: 'critical',
    distribute: 'medium', execute: 'critical', govern: 'high', unknown: 'medium',
  },
  cloud_infrastructure: {
    read: 'high', write: 'high', modify: 'high', destroy: 'critical',
    distribute: 'critical', execute: 'critical', govern: 'high', unknown: 'high',
  },
  financial_data: {
    read: 'high', write: 'high', modify: 'high', destroy: 'critical',
    distribute: 'critical', execute: 'critical', govern: 'critical', unknown: 'high',
  },
  database: {
    read: 'high', write: 'critical', modify: 'critical', destroy: 'critical',
    distribute: 'high', execute: 'critical', govern: 'high', unknown: 'high',
  },
  messaging: {
    read: 'low', write: 'medium', modify: 'medium', destroy: 'medium',
    distribute: 'high', execute: 'medium', govern: 'medium', unknown: 'low',
  },
  crm: {
    read: 'medium', write: 'medium', modify: 'medium', destroy: 'high',
    distribute: 'high', execute: 'high', govern: 'high', unknown: 'medium',
  },
  calendar: {
    read: 'low', write: 'low', modify: 'low', destroy: 'low',
    distribute: 'medium', execute: 'low', govern: 'low', unknown: 'low',
  },
  file_storage: {
    read: 'medium', write: 'medium', modify: 'medium', destroy: 'high',
    distribute: 'high', execute: 'high', govern: 'medium', unknown: 'medium',
  },
  identity: {
    read: 'high', write: 'critical', modify: 'critical', destroy: 'critical',
    distribute: 'critical', execute: 'critical', govern: 'critical', unknown: 'high',
  },
  unknown: {
    read: 'medium', write: 'high', modify: 'high', destroy: 'critical',
    distribute: 'high', execute: 'critical', govern: 'high', unknown: 'medium',
  },
};

// ── Main classifier ───────────────────────────────────────────────
function classifyTool(tool: DiscoveredTool): { sensitivity: Sensitivity; reason: string } {
  // Override: server-declared sensitivity from metadata endpoint
  if (tool.preset_sensitivity) {
    return {
      sensitivity: tool.preset_sensitivity as Sensitivity,
      reason:      `Server-declared via x-reva-sensitivity (authoritative)`,
    };
  }

  // Unreachable servers
  if (tool.server_type === 'unreachable') {
    return {
      sensitivity: 'medium',
      reason:      'Server unreachable at scan time — defaulting to medium pending rescan',
    };
  }

  const domain = classifyDomain(tool.server_name, tool.server_url);

  // Stdio: tool list not available — use domain-only sensitivity
  if (tool.server_type === 'stdio') {
    const sensitivity = DOMAIN_ONLY_SENSITIVITY[domain];
    return {
      sensitivity,
      reason: `Domain: ${domain} (stdio — individual tools not scannable) → ${sensitivity}`,
    };
  }

  // HTTP servers: full domain × action matrix
  const action = classifyAction(tool.tool_name, tool.description);
  const sensitivity = MATRIX[domain][action];

  return {
    sensitivity,
    reason: `Domain: ${domain} · Action: ${action} → ${sensitivity}`,
  };
}

export function classifyTools(tools: DiscoveredTool[]): ClassifiedTool[] {
  return tools.map(tool => {
    const { sensitivity, reason } = classifyTool(tool);
    return { ...tool, sensitivity, sensitivity_reason: reason };
  });
}
