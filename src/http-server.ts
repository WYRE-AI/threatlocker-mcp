import { createServer as createHttpServer, type Server } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpServer } from './server.js';
import { runWithCredentials } from './utils/client.js';
import { logger } from './utils/logger.js';
import { verifyS2sHeader, S2S_HEADER } from './s2s-verify.js';

const INSECURE_DEV_FLAG = 'MCP_ALLOW_INSECURE_DEV';

/** Gateway-provisioned service-to-service secret. Empty means "not configured". */
export function readS2sSecret(): string {
  return (process.env.CONDUIT_S2S_SECRET ?? '').trim();
}

/**
 * Fail closed: do not listen on HTTP unless the service-to-service secret
 * is configured. MCP_ALLOW_INSECURE_DEV=1 is the only override, and it is
 * local-development only. Never log the secret value.
 */
export function assertS2sSecretConfigured(): void {
  if (readS2sSecret()) return;

  if (process.env[INSECURE_DEV_FLAG] === '1') {
    const warning =
      'SECURITY WARNING: CONDUIT_S2S_SECRET is unset. HTTP transport is starting WITHOUT service-to-service authentication because MCP_ALLOW_INSECURE_DEV=1. This is for local development only and must not be used in production.';
    logger.warn(warning);
    // logger.warn is dropped when LOG_LEVEL=error. Repeat on stderr so the
    // insecure-dev override cannot be silenced by log level.
    console.error(warning);
    return;
  }

  logger.error(
    'Refusing to start HTTP transport: CONDUIT_S2S_SECRET is empty. Set CONDUIT_S2S_SECRET to the gateway-provisioned service-to-service secret. For local development only, set MCP_ALLOW_INSECURE_DEV=1.',
  );
  process.exit(1);
}

function headerString(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

export function startHttpServer(): Server {
  assertS2sSecretConfigured();

  const port = parseInt(process.env.MCP_HTTP_PORT || '8080', 10);
  const host = process.env.MCP_HTTP_HOST || '127.0.0.1';
  const isGatewayMode = process.env.AUTH_MODE === 'gateway';

  const httpServer = createHttpServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    // Shallow liveness probe — always 200 when the process is up.
    // Unauthenticated, and it must not read credentials: gateway mode has
    // none at process scope, and reading them would also reveal whether
    // env credentials are configured.
    if (url.pathname === '/health' || url.pathname === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        transport: 'http',
        timestamp: new Date().toISOString(),
      }));
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health', '/healthz'] }));
      return;
    }

    // Conduit service-to-service auth (gateway#377 parity): rejected
    // BEFORE any credential extraction. S2S proves the gateway, not the
    // vendor tenant. An empty secret only reaches this point when
    // MCP_ALLOW_INSECURE_DEV=1, in which case there is nothing to verify.
    const secret = readS2sSecret();
    if (secret && !verifyS2sHeader(headerString(req.headers[S2S_HEADER]), secret)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.',
        })
      );
      return;
    }

    const handle = async () => {
      // SECURITY-CRITICAL invariant: this transport MUST stay stateless
      // (sessionIdGenerator: undefined + enableJsonResponse: true). Per-request
      // tenant credentials are carried in an AsyncLocalStorage context opened by
      // runWithCredentials() below. A stateless request->single-response flow
      // keeps the tool call inside that context. Switching to a stateful/SSE
      // transport (sessionIdGenerator set, persistent stream) would let a
      // long-lived connection serve later messages under a stale/foreign
      // credential context — re-review tenant isolation before changing this.
      const server = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });

      res.on('close', () => {
        transport.close();
        server.close();
      });

      await server.connect(transport);
      await transport.handleRequest(req, res);
    };

    if (isGatewayMode) {
      // Credentials must arrive on every request. Falling through would
      // resolve THREATLOCKER_API_KEY from the process environment, which is
      // not request-scoped and would let anyone who can reach the port use
      // the container's vendor credentials.
      const apiKey = headerString(req.headers['x-threatlocker-api-key']);
      // Optional — the ThreatLocker API defaults to the key's primary org
      // when the OrganizationId header is omitted.
      const organizationId = headerString(req.headers['x-threatlocker-organization-id']);
      // Portal instance letter (portal.<instance>.threatlocker.com) — keys are
      // instance-specific; absent triggers auto-detection in getClient().
      const instance = headerString(req.headers['x-threatlocker-instance']);
      if (!apiKey || apiKey.trim() === '') {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32001,
              message:
                'Unauthorized: missing required gateway credential header x-threatlocker-api-key',
            },
            id: null,
          })
        );
        return;
      }
      await runWithCredentials(
        { apiKey, organizationId: organizationId || undefined, instance },
        handle,
      );
      return;
    }

    await handle();
  });

  httpServer.listen(port, host, () => {
    logger.info(`HTTP streaming server listening on ${host}:${port}`);
  });
  return httpServer;
}
