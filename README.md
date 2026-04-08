# Reva Cowork Plugin

Reva authorization connector for Claude Cowork.
Discovers installed connectors and MCP servers, enforces Cedar policies on every prompt and tool call.

## Services
- Connector + Dashboard: https://reva-plugin.onrender.com

## Setup
See config/env.example for required environment variables.

## Build phases
- Phase 1: Repo + infrastructure (current)
- Phase 2: OAuth (Okta)
- Phase 3: Discovery + session lock
- Phase 4: Cedar schema + policies
- Phase 5: PDP hooks
- Phase 6: HITL
- Phase 7: Dashboard
