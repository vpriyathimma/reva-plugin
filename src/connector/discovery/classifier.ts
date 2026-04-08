import { DiscoveredTool } from './toolScanner';

export type Sensitivity = 'low' | 'medium' | 'high' | 'critical';

export interface ClassifiedTool extends DiscoveredTool {
  sensitivity: Sensitivity;
}

const CRITICAL_PATTERNS = [
  'delete', 'drop', 'truncate', 'destroy', 'remove',
  'execute', 'run_query', 'sql', 'admin', 'root',
  'production', 'deploy', 'shutdown',
];

const HIGH_PATTERNS = [
  'write', 'create', 'update', 'send', 'post',
  'upload', 'modify', 'edit', 'publish', 'commit',
  'push', 'merge', 'approve', 'transfer',
];

const MEDIUM_PATTERNS = [
  'list', 'search', 'get', 'fetch', 'read',
  'download', 'export', 'view', 'access',
];

function classifySensitivity(tool: DiscoveredTool): Sensitivity {
  const name = tool.tool_name.toLowerCase();
  const desc = tool.description.toLowerCase();
  const combined = `${name} ${desc}`;

  if (CRITICAL_PATTERNS.some(p => combined.includes(p))) return 'critical';
  if (HIGH_PATTERNS.some(p => combined.includes(p)))    return 'high';
  if (MEDIUM_PATTERNS.some(p => combined.includes(p)))  return 'medium';
  return 'low';
}

export function classifyTools(tools: DiscoveredTool[]): ClassifiedTool[] {
  return tools.map(tool => ({
    ...tool,
    sensitivity: classifySensitivity(tool),
  }));
}
