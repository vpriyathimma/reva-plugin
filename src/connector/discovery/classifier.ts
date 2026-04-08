import { DiscoveredTool } from './toolScanner';

export type Sensitivity = 'low' | 'medium' | 'high' | 'critical';

export interface ClassifiedTool extends DiscoveredTool {
  sensitivity:  Sensitivity;
  sensitivity_reason: string;
}

// Pattern sets with explanations
const CRITICAL = [
  { pattern: 'delete',      reason: 'Destructive delete operation' },
  { pattern: 'drop',        reason: 'Destructive drop operation' },
  { pattern: 'truncate',    reason: 'Destructive truncate operation' },
  { pattern: 'execute_sql', reason: 'Raw SQL execution' },
  { pattern: 'run_query',   reason: 'Raw query execution' },
  { pattern: 'admin',       reason: 'Administrative operation' },
  { pattern: 'deploy',      reason: 'Deployment operation' },
  { pattern: 'shutdown',    reason: 'System shutdown operation' },
  { pattern: 'destroy',     reason: 'Destructive operation' },
  { pattern: 'approve_loan', reason: 'Financial approval operation' },
  { pattern: 'transfer',    reason: 'Financial transfer operation' },
];

const HIGH = [
  { pattern: 'send',        reason: 'Sends data externally' },
  { pattern: 'write',       reason: 'Write operation' },
  { pattern: 'create',      reason: 'Create operation' },
  { pattern: 'update',      reason: 'Update operation' },
  { pattern: 'post',        reason: 'Post/publish operation' },
  { pattern: 'upload',      reason: 'Upload operation' },
  { pattern: 'modify',      reason: 'Modification operation' },
  { pattern: 'publish',     reason: 'Publish operation' },
  { pattern: 'commit',      reason: 'Commit operation' },
  { pattern: 'merge',       reason: 'Merge operation' },
  { pattern: 'issue_token', reason: 'Token issuance operation' },
  { pattern: 'enrich',      reason: 'Token enrichment operation' },
];

const MEDIUM = [
  { pattern: 'read',        reason: 'Read operation' },
  { pattern: 'get',         reason: 'Data retrieval' },
  { pattern: 'fetch',       reason: 'Data fetch' },
  { pattern: 'list',        reason: 'List operation' },
  { pattern: 'search',      reason: 'Search operation' },
  { pattern: 'download',    reason: 'Download operation' },
  { pattern: 'export',      reason: 'Export operation' },
  { pattern: 'view',        reason: 'View operation' },
  { pattern: 'lookup',      reason: 'Lookup operation' },
  { pattern: 'map',         reason: 'Mapping operation' },
];

function deriveSensitivity(tool: DiscoveredTool): { sensitivity: Sensitivity; reason: string } {
  const name    = tool.tool_name.toLowerCase();
  const desc    = tool.description.toLowerCase();
  const schema  = JSON.stringify(tool.input_schema || {}).toLowerCase();
  const combined = `${name} ${desc} ${schema}`;

  // Check critical first
  for (const c of CRITICAL) {
    if (combined.includes(c.pattern)) {
      return { sensitivity: 'critical', reason: c.reason };
    }
  }

  // Check high
  for (const h of HIGH) {
    if (combined.includes(h.pattern)) {
      return { sensitivity: 'high', reason: h.reason };
    }
  }

  // Check medium
  for (const m of MEDIUM) {
    if (combined.includes(m.pattern)) {
      return { sensitivity: 'medium', reason: m.reason };
    }
  }

  // Unknown tools from unreachable servers — treat as medium until confirmed
  if (tool.tool_name.includes('unknown') || tool.tool_name.includes('service')) {
    return { sensitivity: 'medium', reason: 'Unknown tool — defaulting to medium pending scan' };
  }

  return { sensitivity: 'low', reason: 'No sensitive patterns detected' };
}

export function classifyTools(tools: DiscoveredTool[]): ClassifiedTool[] {
  return tools.map(tool => {
    const { sensitivity, reason } = deriveSensitivity(tool);
    return { ...tool, sensitivity, sensitivity_reason: reason };
  });
}
