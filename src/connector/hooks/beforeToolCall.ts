import { Request, Response }     from 'express';
import { classifyToolCall }      from '../../api/intentClassifier';
import { logDecision }           from '../discovery/enroll';
import { sessionIntentStore }    from './beforePrompt';
import { sessionStore }          from '../discovery/enroll';
import { claudeSessionUserStore, spiffeIdStore, hostnameStore } from './onSessionStart';
import { getPIPContext } from '../../api/pip';
import { getHITLConfig as getHITLConfigFn, findApprovalForDeveloper as findApprovalForDeveloperFn, findPendingApproval as findPendingApprovalFn, triggerHITL as triggerHITLFn } from '../../api/hitlConfig';
import { isSessionTerminated } from '../../api/sessionControl';
import { isPrivilegedCommand, validateSVID } from '../../api/svid';
import { recordDynamicTool, discoveredServers } from '../../api/mcpProbe';
import { triggerHITL }           from '../hitl/trigger';
import { pollHITL }              from '../hitl/poll';
import { recordHITLApproval, recordHITLDenial } from '../hitl/callback';
import { resolveAgentName }      from '../../api/agentResolver';
import { evaluateCedar, buildCallToolPayload, buildFileOperationPayload, buildMCPToolPayload, getOrCreateSessionTrace } from '../../api/pdpEvaluate';

// HITL user mapping — OS username → Okta email
const HITL_MAP: Record<string, string> = {
  saisrungaram: 'sai.srungaram@reva.ai',
  yashprakash:  'yash.prakash@reva.ai',
};

function resolveHITLEmail(osUser: string): string {
  return HITL_MAP[osUser] || osUser;
}

// ── Specific denial messages based on PIP context ──
function getDenyReason(pipCtx: any, cedarPayload: any): string {
  const ctx = cedarPayload?.context || {};

  // Layer 1: Identity
  if (ctx.git_email && ctx.oauth_email && ctx.git_email !== ctx.oauth_email) {
    return `Identity mismatch — your git identity (${ctx.git_email}) doesn't match your authenticated identity (${ctx.oauth_email}). Update your git config: git config user.email "${ctx.oauth_email}"`;
  }

  // Layer 1: SSH-only repo
  if (ctx.project_name && ctx.connection_type === 'local' && pipCtx?.github?.github_repo) {
    // Check if this repo requires SSH (we know reva-auth-service does)
    // This will be caught by CC-FORBID-004 but we provide a clear message
  }

  // Layer 3: Risk — injection
  if (ctx.injection_score >= 50) {
    return `Security alert — prompt injection detected (score: ${ctx.injection_score}). This action is permanently blocked.`;
  }

  // Layer 3: Risk — trust collapse
  if (ctx.trust_score < 15) {
    return `Security alert — trust score critically low (${ctx.trust_score}). Multiple risk signals detected. All actions blocked.`;
  }

  // Layer 3: Risk — escalation
  if (ctx.escalation_score >= 60) {
    return `Privilege escalation detected (score: ${ctx.escalation_score}). This action is blocked.`;
  }

  // Layer 2: Protected branch
  if (ctx.github_branch_protected === true) {
    return `Protected branch — changes to protected branches require approval. Create a feature branch from your Jira ticket.`;
  }

  // Layer 2: No Jira ticket
  if (pipCtx?.jira?.jira_ticket_exists === false || ctx.jira_ticket_exists === false) {
    return `No Jira ticket found for this branch. Create a ticket and use a branch with the ticket ID (e.g., feature/SCRUM-123-description).`;
  }

  // Layer 2: Wrong developer
  if (ctx.jira_assignee && ctx.jira_assignee_email && ctx.oauth_email && ctx.jira_assignee_email !== ctx.oauth_email) {
    return `Ticket ${ctx.jira_ticket_id} is assigned to ${ctx.jira_assignee}, not you. Get the ticket reassigned or work on your assigned tickets.`;
  }

  // Layer 2: Wrong developer (email not available, use display name)
  if (ctx.jira_assignee && ctx.jira_ticket_exists === true && !ctx.jira_assignee_email) {
    return `Ticket ${ctx.jira_ticket_id} is assigned to ${ctx.jira_assignee}. Assignee email could not be verified. Contact your Jira administrator.`;
  }

  // Layer 2: Wrong status
  if (ctx.jira_status && ctx.jira_status !== 'In Progress' && ctx.jira_ticket_exists === true) {
    return `Ticket ${ctx.jira_ticket_id} is in "${ctx.jira_status}" status. Move it to "In Progress" before making code changes.`;
  }

  // Layer 3: Subagent write
  if (ctx.agent_type === 'subagent') {
    return `Spawned agents are restricted to read-only. Only the main developer agent can modify files.`;
  }

  // Default
  return 'Blocked by governance policy — no matching authorization for this action.';
}

// Track active MCP servers discovered via PreToolUse
export const activeMcpServers = new Map<string, Set<string>>(); // session_id → Set of server names

// Subagent context store — tracks active subagent window per session
// SpawnAgent fires → subagent_active = true
// Next SpawnAgent or UserPromptSubmit → subagent_active = false (new turn)
interface SubagentContext {
  active:      boolean;
  started_at:  string;
  spawn_count: number; // how many agents spawned this turn
}
export const subagentContextStore = new Map<string, SubagentContext>();

function markSubagentActive(session_id: string): void {
  const existing = subagentContextStore.get(session_id);
  subagentContextStore.set(session_id, {
    active:      true,
    started_at:  new Date().toISOString(),
    spawn_count: (existing?.spawn_count || 0) + 1,
  });
  console.log(`[Subagent] Context active for session=${session_id} spawn_count=${(existing?.spawn_count || 0) + 1}`);
}

function isSubagentActive(session_id: string): boolean {
  return subagentContextStore.get(session_id)?.active || false;
}

function trackMcpServer(session_id: string, tool_name: string): void {
  if (!tool_name.startsWith('mcp__')) return;
  const parts = tool_name.split('__');
  if (parts.length < 2) return;
  const server_name = parts[1];
  if (!activeMcpServers.has(session_id)) {
    activeMcpServers.set(session_id, new Set());
  }
  activeMcpServers.get(session_id)!.add(server_name);
}

export const hitlStore = new Map<string, {
  acknowledged: boolean;
  approved_at:  string;
  tool_name:    string;
  blocked?:     boolean; // permanently blocked after timeout/denial
}>();

const hitlInFlight = new Map<string, boolean>();

// Scope mapping — tool sensitivity → MCPTool scope
const SENSITIVITY_SCOPE: Record<string, string> = {
  low:      'MCPTool:Read',
  medium:   'MCPTool:Write',
  high:     'MCPTool:Communicate',
  critical: 'MCPTool:Destructive',
};

export async function handleToolCall(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization || '';
    const token      = authHeader.replace('Bearer ', '');
    // Allow unauthenticated hook calls from Claude Code plugin

    const {
      session_id    = `session-${Date.now()}`,
      tool_name     = '',
      server_name   = '',
      server_url    = '',
      user_email_body = (req as any).user?.email || '',
      agent_cid     = '',
      client_source = 'claude-code',
    } = req.body;

    // Resolve OS user — X-OS-User header is most reliable (set by hooks.json allowedEnvVars)
    const osUserFromHeader  = (req.headers['x-os-user'] as string) || '';
    const projectFromHeader = (req.headers['x-project-dir'] as string) || '';
    const osUserFromSession = claudeSessionUserStore.get(session_id);
    const enrolledSession   = sessionStore.get(session_id);
    const user_email = osUserFromHeader || osUserFromSession || enrolledSession?.user_email || user_email_body || 'claude-code-hook@reva.ai';

    // ── Terminate Session — checked first, blocks everything ──
    const pipCtxTerm = getPIPContext(user_email);
    const termHostname = hostnameStore.get(user_email) || req.body?.hostname || enrolledSession?.hostname || 'unknown';
    const termEmail = pipCtxTerm?.oauth_email || user_email;
    const terminateKey = `${termEmail}::${termHostname}`;
    if (isSessionTerminated(terminateKey)) {
      console.log(`[SESSION] Blocked: ${terminateKey} — session terminated by administrator`);
      return res.json({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: 'Session terminated by administrator. Start a new session to continue.',
        },
        reva: { effect: 'Deny', reason: 'Session terminated by administrator' },
      });
    }

    // Derive project name dynamically — NEVER hardcode
    const filePath = req.body?.tool_input?.file_path || req.body?.tool_input?.path || '';
    const derivedProject = projectFromHeader
      ? projectFromHeader.split('/').pop() || 'unknown'
      : enrolledSession?.project_name
        || (filePath.includes('/') ? (filePath.split('/')[3] || 'unknown') : 'unknown');

    const sessionIntent   = sessionIntentStore.get(session_id);
    const promptIntent    = sessionIntent?.intent         || 'unknown';
    const priorIntents    = sessionIntent?.prior_intents  || '';
    const query           = sessionIntent?.prompt         || '';
    const promptHistory   = sessionIntent?.prompt_history || [];
    const baseSensitivity = (() => {
      // Check MCP probe results for auto-classified sensitivity
      const probed = discoveredServers.get(server_name) || discoveredServers.get(`claude.ai ${server_name}`);
      const probedTool = probed?.tools?.find(t => t.name === tool_name || tool_name.includes(t.name));
      return probedTool?.sensitivity || 'medium';
    })();

    // Record dynamic tool for inventory (especially for auth-required servers)
    if (tool_name.startsWith('mcp__')) {
      const parts = tool_name.split('__');
      recordDynamicTool(parts[1] || server_name, parts[2] || tool_name);
    }

    // Track MCP server usage dynamically
    trackMcpServer(session_id, tool_name);

    // Detect if this is a Claude Code native tool call (not MCP)
    const claudeCodeTools = ['Read', 'Write', 'Edit', 'MultiEdit', 'Bash', 'Glob', 'Grep', 'Task', 'Agent', 'TaskCreate', 'TaskUpdate', 'WorktreeTool'];
    const isClaudeCodeTool = claudeCodeTools.some(t => tool_name === t || tool_name.toLowerCase() === t.toLowerCase());

    // Phase 3 — Subagent context tracking
    // When SpawnAgent fires → mark subagent context active
    const isSpawnAgent = tool_name === 'Agent' || tool_name === 'Task' || tool_name === 'TaskCreate' || tool_name === 'TaskUpdate';
    if (isSpawnAgent) {
      markSubagentActive(session_id);
    }

    // Derive agent_type from subagent context store
    // If subagent is active AND this is NOT the SpawnAgent call itself → it is a subagent action
    const derivedAgentType = (!isSpawnAgent && isSubagentActive(session_id)) ? 'subagent' : 'main';

    const result = classifyToolCall(tool_name, server_name, baseSensitivity, session_id, promptIntent);

    // HITL key includes command hash so each unique command requires its own approval
    const rawCommand   = req.body?.tool_input?.command || '';
    const commandHash  = rawCommand
      ? require('crypto').createHash('md5').update(rawCommand.slice(0, 100)).digest('hex').slice(0, 8)
      : '';
    const hitlKey      = commandHash
      ? `${session_id}:${tool_name}:${commandHash}`
      : `${session_id}:${tool_name}`;
    let hitlAcknowledged = hitlStore.get(hitlKey)?.acknowledged || false;
    const hitlPermanentlyBlocked = hitlStore.get(hitlKey)?.blocked || false;

    // If permanently blocked — return hard deny immediately without triggering HITL again
    if (hitlPermanentlyBlocked) {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: `Reva Governance: This action was previously rejected or timed out. Permanently blocked for this session. Do not retry.`,
          additionalContext:        `Reva Governance: Permanently blocked — HITL was not approved.`,
        },
      });
    }

    // Resolve agent name from Okta (cached)
    const agentName = agent_cid ? await resolveAgentName(agent_cid) : 'CoworkAICodingAgent';

    // Ensure session trace ID
    getOrCreateSessionTrace(session_id);

    // Scope from sensitivity
    const toolScope = SENSITIVITY_SCOPE[result.sensitivity] || 'MCPTool:Read';

    // ── Cedar PDP evaluation ──────────────────────────────────────
    // Route MCP tools to buildMCPToolPayload
    const isMCPTool = tool_name.startsWith('mcp__');
    const mcpParts  = tool_name.startsWith('mcp__') ? tool_name.split('__') : [];
    const mcpServer = mcpParts[1] || 'claude-code';
    const mcpTool   = mcpParts[2] || tool_name;

    // Resolve SPIFFE ID for this session — developer only, not spawned agents
    const spiffeId = derivedAgentType !== 'subagent' ? spiffeIdStore.get(session_id) : undefined;

    // Resolve PIP context (Jira + GitHub) — cached from SessionStart, keyed by os_user
    const pipCtx = getPIPContext(user_email);

    const cedarPayload = (client_source === 'claude-code' && isMCPTool)
      ? buildMCPToolPayload({
          osUser:          user_email,
          projectName:     projectFromHeader ? projectFromHeader.split('/').pop() || 'unknown' : 'unknown',
          toolName:        mcpTool,
          serverName:      mcpServer,
          agentType:       derivedAgentType,
          sessionId:       session_id,
          hitlAcknowledged,
          scores:          { ...result.scores, trust_score: result.trust_score },
          prompt:          query,
          prompt_history:  promptHistory,
          spiffeId,
          pipCtx,
        })
      : client_source === 'claude-code'
      ? buildFileOperationPayload({
          osUser:          user_email,
          projectName:     projectFromHeader ? projectFromHeader.split('/').pop() || derivedProject : server_name || derivedProject,
          toolName:        tool_name,
          filePath:        req.body?.tool_input?.file_path  // Edit, Write, MultiEdit
                            || req.body?.tool_input?.path        // Read
                            || req.body?.tool_input?.new_path    // MultiEdit rename
                            || req.body?.tool_input?.pattern     // Glob
                            || req.body?.tool_input?.regex       // Grep
                            || '',
          command:         req.body?.tool_input?.command || '',
          agentType:       derivedAgentType,
          sessionId:       session_id,
          spawnCount:      subagentContextStore.get(session_id)?.spawn_count || 1,
          hitlAcknowledged,
          scores:          { ...result.scores, trust_score: result.trust_score },
          prompt:          query,
          prompt_history:  promptHistory,
          spiffeId,
          pipCtx,
        })
      : buildCallToolPayload({
          agentName,
          agentId:         agent_cid,
          toolName:        tool_name,
          serverName:      server_name,
          humanSub:        user_email,
          clientSource:    client_source,
          sessionId:       session_id,
          sensitivity:     result.sensitivity,
          toolScope,
          scores:          { ...result.scores, trust_score: result.trust_score },
          hitlAcknowledged,
          intent:          result.intent,
          priorIntents,
          query,
          queryHistory:    priorIntents,
        });

    const cedarAction = (cedarPayload as any)?.action?.name || '';
    const isWriteAction = ['EditFile', 'WriteFile'].includes(cedarAction);
    const bashCommand = req.body?.tool_input?.command || '';

    // ── SVID: check for privileged commands (git push, merge, PR) ──
    const privileged = isPrivilegedCommand(bashCommand);
    const hitlConfig = getHITLConfigFn();
    const branchProtected = pipCtx?.github?.github_branch_protected === true;

    if (privileged.privileged && branchProtected && cedarAction === 'RunBash') {
      console.log(`[SVID] Privileged command detected: ${privileged.type} on protected branch, HITL enabled=${hitlConfig.enabled}`);
      const developerEmail = pipCtx?.oauth_email || user_email;
      const svid = validateSVID(developerEmail, derivedProject);

      if (svid) {
        // Valid SVID — set details for Cedar context and decision logs
        const ttlRemaining = Math.max(0, Math.floor((new Date(svid.expires_at).getTime() - Date.now()) / 1000));
        (cedarPayload as any).context.svid_active = true;
        (cedarPayload as any).context.svid_status = 'active';
        (cedarPayload as any).context.svid_ttl_remaining = ttlRemaining;
        (cedarPayload as any).context.svid_id = svid.id;
        console.log(`[SVID] Valid credential: ${svid.id} for ${developerEmail} — ${privileged.type} on ${derivedProject}, TTL ${ttlRemaining}s`);
      } else {
        // No valid SVID — trigger HITL for approval + SVID issuance
        if (hitlConfig.enabled) {
          const existingPending = findPendingApprovalFn(developerEmail, derivedProject);

          if (!existingPending) {
            console.log(`[SVID] No credential — triggering HITL for ${privileged.type} by ${developerEmail} on ${derivedProject}`);
            const spiffeId = spiffeIdStore.get(session_id) || '';
            await triggerHITLFn({
              developer_email: developerEmail,
              developer_name:  pipCtx?.git_name || user_email,
              action:          `${privileged.type} (SVID required)`,
              resource:        bashCommand,
              project:         derivedProject,
              branch:          pipCtx?.github?.github_branch || '',
              ticket:          pipCtx?.jira?.jira_ticket_id || '',
              spiffe_id:       spiffeId,
            });
          }

          logDecision({
            timestamp: new Date().toISOString(), session_id, user_email, tool: tool_name,
            server: server_name, sensitivity: result.sensitivity, effect: 'Deny',
            reason: `SVID required for ${privileged.type} — sent for approval`,
            intent: promptIntent, trust_score: result.trust_score, scores: result.scores,
            prompt: query.slice(0, 200), prompt_history: promptHistory, agent_type: derivedAgentType,
          });

          return res.json({
            hookSpecificOutput: {
              hookEventName: 'PreToolUse',
              permissionDecision: 'deny',
              permissionDecisionReason: `Short-lived credential required for ${privileged.type} on protected branch. Approval sent to ${hitlConfig.slack_channel || 'approver'}. Retry after approval.`,
            },
            reva: { effect: 'Deny', reason: `SVID required — ${privileged.type} on protected branch` },
          });
        }

        // HITL not enabled — log and deny with SVID context
        console.log(`[SVID] Privileged command '${privileged.type}' on protected branch but HITL not enabled — denying`);
        (cedarPayload as any).context.svid_active = false;
        (cedarPayload as any).context.svid_status = 'none';
        (cedarPayload as any).context.svid_ttl_remaining = 0;
        (cedarPayload as any).context.svid_id = '';
      }
    }

    // ── HITL: check if protected branch + write action + HITL enabled ──

    if (hitlConfig.enabled && branchProtected && isWriteAction) {
      // Check if already approved
      const existingApproval = findApprovalForDeveloperFn(
        pipCtx?.oauth_email || user_email,
        cedarAction,
        derivedProject
      );

      if (existingApproval) {
        // Approval found — set consent for Cedar
        hitlAcknowledged = true;
        console.log(`[HITL] Existing approval found for ${user_email} — ${cedarAction} on ${derivedProject}`);
      } else {
        // Check if there's already a pending approval — don't send duplicate
        const pendingKey = `${pipCtx?.oauth_email || user_email}:${derivedProject}:protected_branch`;
        const existingPending = findPendingApprovalFn(pipCtx?.oauth_email || user_email, derivedProject);

        if (existingPending) {
          console.log(`[HITL] Pending approval already exists for ${user_email} — skipping duplicate`);
        } else {
          console.log(`[HITL] Protected branch — triggering Slack approval for ${user_email} ${cedarAction} on ${derivedProject}`);
          await triggerHITLFn({
            developer_email: pipCtx?.oauth_email || user_email,
            developer_name:  pipCtx?.git_name || user_email,
            action:          cedarAction,
            resource:        (cedarPayload as any)?.resource?.id || '',
            project:         derivedProject,
            branch:          pipCtx?.github?.github_branch || '',
            ticket:          pipCtx?.jira?.jira_ticket_id || '',
          });
        }

        logDecision({
          timestamp: new Date().toISOString(), session_id, user_email, tool: tool_name,
          server: server_name, sensitivity: result.sensitivity, effect: 'Deny',
          reason: `Approval required — sent to Slack. Retry after approval.`,
          intent: promptIntent, trust_score: result.trust_score, scores: result.scores,
          prompt: query.slice(0, 200), prompt_history: promptHistory, agent_type: derivedAgentType,
        });

        return res.json({
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason: `Protected branch — approval required. Sent to ${hitlConfig.slack_channel || 'approver'}. Continue other tasks and retry after approval.`,
          },
          reva: { effect: 'Deny', reason: 'HITL — awaiting Slack approval' },
        });
      }
    }

    // Update hitlAcknowledged in payload if approval was found
    if (hitlAcknowledged && (cedarPayload as any)?.context) {
      (cedarPayload as any).context.approver_consent = true;
    }

    const cedarResult = await evaluateCedar(cedarPayload);

    let effect: 'Permit' | 'Deny' | 'HITL' = 'Permit';
    let reason  = 'Tool call permitted';

    if (cedarResult.decision === 'deny') {
      effect = 'Deny';
      // Generate specific denial message from PIP context
      reason = getDenyReason(pipCtx, cedarPayload);
    }

    logDecision({
      timestamp:   new Date().toISOString(),
      session_id,
      user_email,
      tool:        tool_name,
      server:      server_name,
      sensitivity: result.sensitivity,
      effect,
      reason,
      intent:            promptIntent,
      trust_score:       result.trust_score,
      scores:            result.scores,
      prompt:            query.slice(0, 200),
      prompt_history:    promptHistory,
      agent_type:        derivedAgentType,
      command_risk:      (cedarPayload as any)?.context?.command_risk || '',
      file_zone:         (cedarPayload as any)?.context?.file_zone   || '',
      cedar_decision:    cedarResult.decision,
      cedar_policy_name: cedarResult.policy_name,
      cedar_latency_ms:  cedarResult.latency_ms,
      cedar_decision_id: cedarResult.decision_id,
    });

    // HITL: currently disabled — Cedar deny = hard deny, no HITL trigger
    // Kept for future use when specific Cedar policies signal HITL requirement
    if ((effect as string) === 'HITL' && !hitlInFlight.get(hitlKey)) {
      hitlInFlight.set(hitlKey, true);
      try {
        console.log(`[HITL] Triggering synchronous push for ${user_email} → ${tool_name}`);
        const triggerResult = await triggerHITL(resolveHITLEmail(user_email), tool_name, session_id);

        if (!triggerResult.success || !triggerResult.poll_url) {
          recordHITLDenial(session_id, tool_name, user_email, 'error');
          hitlInFlight.delete(hitlKey);
          // Fail open with warning if HITL trigger fails
          return res.json({
            hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny',
              permissionDecisionReason: 'HITL trigger failed — Okta Verify unavailable' },
            reva: { effect: 'Deny', reason: 'HITL trigger failed', cedar: cedarResult },
          });
        }

        // Poll synchronously — Claude Code waits for this response
        const status = await pollHITL(triggerResult.poll_url);

        if (status === 'approved') {
          // Re-evaluate Cedar with hitlAcknowledged: true
          recordHITLApproval(session_id, tool_name, user_email, triggerResult.poll_url);
          hitlStore.set(hitlKey, { acknowledged: true, approved_at: new Date().toISOString(), tool_name });

          // Rebuild payload with hitlAcknowledged: true and re-evaluate
          const approvedPayload = (client_source === 'claude-code' && isMCPTool)
            ? buildMCPToolPayload({ osUser: user_email, projectName: derivedProject, toolName: mcpTool, serverName: mcpServer, agentType: derivedAgentType, sessionId: session_id, hitlAcknowledged: true, scores: { ...result.scores, trust_score: result.trust_score }, prompt: query, prompt_history: promptHistory, spiffeId, pipCtx })
            : buildFileOperationPayload({ osUser: user_email, projectName: derivedProject, toolName: tool_name, filePath: req.body?.tool_input?.file_path || req.body?.tool_input?.path || req.body?.tool_input?.pattern || req.body?.tool_input?.regex || '', command: req.body?.tool_input?.command || '', agentType: derivedAgentType, sessionId: session_id, hitlAcknowledged: true, scores: { ...result.scores, trust_score: result.trust_score }, prompt: query, prompt_history: promptHistory, spiffeId, pipCtx });

          const approvedCedar = await evaluateCedar(approvedPayload);

          // CRITICAL: If Cedar STILL denies after HITL approval, enforce the deny
          if (approvedCedar.decision === 'deny') {
            console.warn(`[HITL] Cedar re-eval STILL denied after approval — enforcing deny for ${tool_name}`);
            logDecision({ timestamp: new Date().toISOString(), session_id, user_email, tool: tool_name, server: server_name, sensitivity: result.sensitivity, effect: 'Deny', reason: 'HITL approved but Cedar denied — no matching permit policy', intent: promptIntent, trust_score: result.trust_score, scores: result.scores, prompt: query.slice(0, 200), prompt_history: promptHistory, agent_type: derivedAgentType, cedar_decision: approvedCedar.decision, cedar_policy_name: approvedCedar.policy_name, cedar_latency_ms: approvedCedar.latency_ms });
            hitlInFlight.delete(hitlKey);
            return res.json({
              hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny',
                permissionDecisionReason: 'Blocked by Reva Governance Policy — no matching authorization' },
              reva: { effect: 'Deny', reason: 'Cedar denied after HITL approval', cedar: approvedCedar },
            });
          }

          logDecision({ timestamp: new Date().toISOString(), session_id, user_email, tool: tool_name, server: server_name, sensitivity: result.sensitivity, effect: 'Permit', reason: 'HITL approved — Cedar re-evaluated and permitted', intent: promptIntent, trust_score: result.trust_score, scores: result.scores, prompt: query.slice(0, 200), prompt_history: promptHistory, agent_type: derivedAgentType, cedar_decision: approvedCedar.decision, cedar_policy_name: approvedCedar.policy_name, cedar_latency_ms: approvedCedar.latency_ms });

          hitlInFlight.delete(hitlKey);
          return res.json({
            hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
            reva: { effect: 'Permit', reason: `HITL approved by ${resolveHITLEmail(user_email)}`, hitlAcknowledged: true, cedar: approvedCedar },
          });

        } else {
          // Denied or timed out
          const denyStatus = status === 'waiting' ? 'timeout' : status as 'denied' | 'timeout' | 'error';
          recordHITLDenial(session_id, tool_name, user_email, denyStatus, triggerResult.poll_url);
          hitlInFlight.delete(hitlKey);

          logDecision({ timestamp: new Date().toISOString(), session_id, user_email, tool: tool_name, server: server_name, sensitivity: result.sensitivity, effect: 'Deny', reason: `HITL ${denyStatus} by ${resolveHITLEmail(user_email)}`, intent: promptIntent, trust_score: result.trust_score, scores: result.scores, prompt: query.slice(0, 200), prompt_history: promptHistory, agent_type: derivedAgentType, cedar_decision: cedarResult.decision, cedar_policy_name: cedarResult.policy_name, cedar_latency_ms: cedarResult.latency_ms });

          return res.json({
            hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny',
              permissionDecisionReason: `HITL ${denyStatus} — tool call blocked` },
            reva: { effect: 'Deny', reason: `HITL ${denyStatus}`, cedar: cedarResult },
          });
        }

      } catch (err: any) {
        console.error(`[HITL] Synchronous error: ${err.message}`);
        hitlInFlight.delete(hitlKey);
        return res.json({
          hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny',
            permissionDecisionReason: 'HITL error — tool call blocked' },
          reva: { effect: 'Deny', reason: 'HITL error' },
        });
      }
    }

    if (effect === 'Deny') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: reason,
        },
        reva: { effect, reason, trust_score: result.trust_score, sensitivity: result.sensitivity, hitlAcknowledged, cedar: cedarResult },
      });
    }

    if ((effect as string) === 'HITL') {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: `⏳ Waiting for Okta Verify approval from ${resolveHITLEmail(user_email)} — please approve or reject on your phone. Tool: ${tool_name} | Command: ${rawCommand.slice(0, 60) || 'n/a'} | Session: ${session_id.slice(0, 8)}`,
          additionalContext:        `Reva governance: HITL approval required. Okta Verify push sent to ${resolveHITLEmail(user_email)}.`,
        },
        reva: { effect: 'HITL', reason, hitl_required: true, hitl_key: hitlKey, trust_score: result.trust_score, sensitivity: result.sensitivity, hitlAcknowledged, cedar: cedarResult },
      });
    }

    return res.json({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
      reva: { effect: 'Permit', reason, trust_score: result.trust_score, sensitivity: result.sensitivity, cedar: cedarResult },
    });

  } catch (err: any) {
    console.error('beforeToolCall error:', err.message);
    // Fail-closed during subagent context — never fail open for subagents
    const session_id_safe = req.body?.session_id || '';
    const isSubagentCtx   = subagentContextStore.get(session_id_safe)?.active || false;
    if (isSubagentCtx) {
      return res.json({
        hookSpecificOutput: {
          hookEventName:            'PreToolUse',
          permissionDecision:       'deny',
          permissionDecisionReason: 'Blocked by Reva Governance Policy',
        },
      });
    }
    return res.json({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } });
  }
}
