# ThreatLocker MCP Server

A Model Context Protocol (MCP) server that provides AI assistants with access to the ThreatLocker Portal API. Manage computers, approval requests, audit logs, and organizations through natural language interactions.

## Features

- **Stateless Architecture**: No session state required, fresh connections per request
- **Decision-Tree Navigation**: Navigate domains with `threatlocker_navigate`
- **Gateway Mode**: Multi-tenant support via HTTP headers
- **Elicitation Support**: Interactive prompts for missing parameters
- **Comprehensive Error Handling**: Detailed error messages and logging
- **Docker Support**: Production-ready containerization

## Tools

### Navigation
- `threatlocker_navigate` - Navigate to a domain to see available tools
- `threatlocker_status` - Check API connection status and available domains

### Computers
- `threatlocker_computers_list` - List computers with filters (search, group, pagination)
- `threatlocker_computers_get` - Get detailed computer information
- `threatlocker_computers_get_checkins` - Get computer checkin history

### Computer Groups
- `threatlocker_computer_groups_list` - List computer groups with filters
- `threatlocker_computer_groups_dropdown` - Get computer groups for dropdown selection

### Approval Requests
- `threatlocker_approvals_list` - List approval requests with status filters
- `threatlocker_approvals_get` - Get detailed approval request information
- `threatlocker_approvals_pending_count` - Get count of pending approvals
- `threatlocker_approvals_get_permit_application` - Get permit application details

### Audit Log
- `threatlocker_audit_search` - Search audit log entries with filters
- `threatlocker_audit_get` - Get one audit log entry by `eActionLogId` from a search row (deprecated alias: `actionLogId`)
- `threatlocker_audit_file_history` - Get audit history for a file. Requires `fullPath` and either `hostname` or `computerId`

### Organizations
- `threatlocker_organizations_list_children` - List child organizations
- `threatlocker_organizations_get_auth_key` - Get organization auth key
- `threatlocker_organizations_for_move_computers` - Get organizations for computer moves

## Configuration

### Environment Variables

#### Stdio Mode (Direct API Access)
```bash
THREATLOCKER_API_KEY=your_api_key_here
THREATLOCKER_ORGANIZATION_ID=your_org_id_here
MCP_TRANSPORT=stdio
```

#### Gateway Mode (Multi-tenant)
```bash
AUTH_MODE=gateway
MCP_TRANSPORT=http
MCP_HTTP_PORT=8080
# Required. The HTTP server exits non-zero if this is empty.
CONDUIT_S2S_SECRET=gateway-provisioned-secret
# Optional. Unset binds 127.0.0.1. The container image sets 0.0.0.0.
# MCP_HTTP_HOST=127.0.0.1
```

`CONDUIT_S2S_SECRET` is required for the HTTP transport. The process logs an error and exits non-zero when it is unset. For local development only, `MCP_ALLOW_INSECURE_DEV=1` starts the server anyway and logs a loud warning; do not set that flag in production. The secret is never written to the logs.

When `MCP_HTTP_HOST` is unset, the server binds `127.0.0.1`. The Dockerfile sets `MCP_HTTP_HOST=0.0.0.0` so the process listens inside the container; publish that port on localhost.

#### Gateway Mode Headers
When running in gateway mode, include these headers with each request:
- `X-Gateway-S2S`: Service-to-service proof from the gateway (`t=<unix>,v1=<hmac>`). Requests without a valid header are rejected with 401 when `CONDUIT_S2S_SECRET` is set.
- `X-Threatlocker-Api-Key`: Your ThreatLocker API key (required). A request without it is rejected with 401 and does not fall back to `THREATLOCKER_API_KEY`.
- `X-Threatlocker-Organization-Id`: Your organization ID (optional; the API defaults to the key's primary organization)

`/health` and `/healthz` stay unauthenticated and do not read credentials. The stdio transport does not use `CONDUIT_S2S_SECRET`.

### Logging
```bash
LOG_LEVEL=debug|info|warn|error  # Default: info
```

## Local Development

1. Clone the repository:
```bash
git clone https://github.com/WYRE-AI/threatlocker-mcp.git
cd threatlocker-mcp
```

2. Install dependencies:
```bash
npm install
```

3. Set environment variables:
```bash
cp .env.example .env
# Edit .env with your ThreatLocker credentials
```

4. Build and run:
```bash
npm run build
npm start

# Or for development with hot reload:
npm run dev
```

5. Test the server:
```bash
# Stdio mode
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | npm start

# HTTP mode. CONDUIT_S2S_SECRET is required unless you set
# MCP_ALLOW_INSECURE_DEV=1 (local development only; logs a loud warning).
# The server binds 127.0.0.1 unless MCP_HTTP_HOST is set.
MCP_TRANSPORT=http AUTH_MODE=gateway CONDUIT_S2S_SECRET=dev-secret npm run start:http
curl http://127.0.0.1:8080/health
```

## Docker

### Using Docker Compose

```bash
# Required. Compose will not start if this is unset or empty.
export CONDUIT_S2S_SECRET=gateway-provisioned-secret

# Pull and run latest image. The published port is 127.0.0.1:8080.
docker compose up -d

# Or build locally
docker compose -f docker-compose.dev.yml up --build
```

### Using Docker directly

```bash
# Gateway mode (recommended). The container listens on 0.0.0.0 inside
# the network namespace; publish it on localhost only. The process
# exits if CONDUIT_S2S_SECRET is empty.
docker run -d \
  --name threatlocker-mcp \
  -p 127.0.0.1:8080:8080 \
  -e AUTH_MODE=gateway \
  -e CONDUIT_S2S_SECRET=gateway-provisioned-secret \
  ghcr.io/wyre-ai/threatlocker-mcp:latest

# Stdio mode
docker run -d \
  --name threatlocker-mcp \
  -e THREATLOCKER_API_KEY=your_key \
  -e THREATLOCKER_ORGANIZATION_ID=your_org_id \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/wyre-ai/threatlocker-mcp:latest
```

## Architecture

### Directory Structure
```
src/
├── domains/           # Domain-specific handlers
│   ├── computers.ts
│   ├── computer_groups.ts
│   ├── approval_requests.ts
│   ├── audit_log.ts
│   ├── organizations.ts
│   ├── navigation.ts
│   └── index.ts
├── utils/             # Utilities
│   ├── client.ts      # ThreatLocker API client
│   ├── logger.ts      # Structured logging
│   ├── types.ts       # TypeScript types
│   ├── server-ref.ts  # Server reference for elicitation
│   └── elicitation.ts # Interactive prompts
├── server.ts          # MCP server creation
├── index.ts           # Stdio transport entry
└── http.ts            # HTTP transport entry
```

### Design Patterns
- **Domain Handlers**: Each API area has its own handler with `getTools()` and `handleCall()`
- **Lazy Loading**: Domain handlers are imported on-demand
- **Fresh Connections**: New server instance per HTTP request for stateless operation
- **Credential Invalidation**: Client is reset when credentials change
- **Elicitation Framework**: Interactive prompts for missing parameters

## License

Apache-2.0 - see [LICENSE](LICENSE) for details.