import { createHmac } from 'node:crypto';
import { once } from 'node:events';
import { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { startHttpServer } from '../http-server.js';
import * as client from '../utils/client.js';
import { logger } from '../utils/logger.js';

const ENV_KEYS = [
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'MCP_HTTP_HOST',
  'MCP_HTTP_PORT',
  'AUTH_MODE',
  'MCP_TRANSPORT',
  'THREATLOCKER_API_KEY',
  'THREATLOCKER_ORGANIZATION_ID',
  'THREATLOCKER_INSTANCE',
] as const;

const ORIGINAL_ENV: Record<string, string | undefined> = {};
for (const key of ENV_KEYS) ORIGINAL_ENV[key] = process.env[key];

const SECRET = 'test-s2s-secret-do-not-log';
const ENV_API_KEY = 'env-vendor-key-must-not-be-used';

function throwOnExit(code?: string | number | null): never {
  throw new Error(`exit:${code}`);
}

function restoreEnv(): void {
  for (const key of ENV_KEYS) {
    if (ORIGINAL_ENV[key] === undefined) delete process.env[key];
    else process.env[key] = ORIGINAL_ENV[key];
  }
}

function mintHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac('sha256', secret).update(message).digest('hex');
  return `${message},v1=${hex}`;
}

async function listening(server: Server): Promise<void> {
  if (server.listening) return;
  await once(server, 'listening');
}

function portOf(server: Server): number {
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('expected a TCP address');
  }
  return (address as AddressInfo).port;
}

async function closeServer(server: Server | undefined): Promise<void> {
  if (!server || !server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

const servers: Server[] = [];

afterEach(async () => {
  while (servers.length) {
    await closeServer(servers.pop());
  }
  restoreEnv();
  vi.restoreAllMocks();
});

function useHttpEnv(overrides: Record<string, string | undefined> = {}): void {
  process.env.MCP_HTTP_HOST = '127.0.0.1';
  process.env.MCP_HTTP_PORT = '0';
  process.env.AUTH_MODE = 'gateway';
  delete process.env.MCP_ALLOW_INSECURE_DEV;
  delete process.env.THREATLOCKER_API_KEY;
  delete process.env.THREATLOCKER_ORGANIZATION_ID;
  delete process.env.THREATLOCKER_INSTANCE;
  delete process.env.CONDUIT_S2S_SECRET;
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

describe('HTTP startup fail-closed', () => {
  it('refuses to start when CONDUIT_S2S_SECRET is unset', () => {
    useHttpEnv();
    const errorSpy = vi.spyOn(logger, 'error').mockImplementation(() => {});
    const listenSpy = vi.spyOn(Server.prototype, 'listen');
    vi.spyOn(process, 'exit').mockImplementation(throwOnExit);

    expect(() => startHttpServer()).toThrow('exit:1');
    expect(listenSpy).not.toHaveBeenCalled();
    const message = errorSpy.mock.calls.map((call) => String(call[0])).join('\n');
    expect(message).toMatch(/Refusing to start/);
    expect(message).toMatch(/CONDUIT_S2S_SECRET/);
    expect(message).not.toContain(SECRET);
  });

  it('refuses to start when CONDUIT_S2S_SECRET is empty or whitespace', () => {
    for (const secret of ['', '   ']) {
      useHttpEnv({ CONDUIT_S2S_SECRET: secret });
      vi.spyOn(logger, 'error').mockImplementation(() => {});
      vi.spyOn(process, 'exit').mockImplementation(throwOnExit);

      expect(() => startHttpServer()).toThrow('exit:1');
      vi.restoreAllMocks();
    }
  });

  it('allows startup with a loud warning when MCP_ALLOW_INSECURE_DEV=1', async () => {
    useHttpEnv({ MCP_ALLOW_INSECURE_DEV: '1' });
    const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const stderr: string[] = [];
    vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      stderr.push(args.map(String).join(' '));
    });
    const exitSpy = vi.spyOn(process, 'exit');

    const server = startHttpServer();
    servers.push(server);
    await listening(server);

    expect(exitSpy).not.toHaveBeenCalled();
    const warning = warnSpy.mock.calls.map((call) => String(call[0])).join('\n');
    expect(warning).toMatch(/SECURITY WARNING/);
    expect(warning).toMatch(/CONDUIT_S2S_SECRET/);
    expect(warning).toMatch(/MCP_ALLOW_INSECURE_DEV/);
    expect(stderr.join('\n')).toMatch(/SECURITY WARNING/);
    expect(warning).not.toContain(SECRET);
  });

  it('does not treat MCP_ALLOW_INSECURE_DEV values other than 1 as the override', () => {
    useHttpEnv({ MCP_ALLOW_INSECURE_DEV: 'true' });
    vi.spyOn(logger, 'error').mockImplementation(() => {});
    vi.spyOn(process, 'exit').mockImplementation(throwOnExit);

    expect(() => startHttpServer()).toThrow('exit:1');
  });

  it('binds 127.0.0.1 when MCP_HTTP_HOST is unset and does not log the secret', async () => {
    useHttpEnv({ CONDUIT_S2S_SECRET: SECRET });
    delete process.env.MCP_HTTP_HOST;
    const infoSpy = vi.spyOn(logger, 'info').mockImplementation(() => {});
    const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const errorSpy = vi.spyOn(logger, 'error').mockImplementation(() => {});

    const server = startHttpServer();
    servers.push(server);
    await listening(server);

    const address = server.address();
    expect(address).toMatchObject({ address: '127.0.0.1' });
    const logged = JSON.stringify([
      ...infoSpy.mock.calls,
      ...warnSpy.mock.calls,
      ...errorSpy.mock.calls,
    ]);
    expect(logged).not.toContain(SECRET);
  });
});

describe('HTTP request auth', () => {
  async function start(overrides: Record<string, string | undefined> = {}): Promise<{ server: Server; port: number }> {
    useHttpEnv({ CONDUIT_S2S_SECRET: SECRET, ...overrides });
    const server = startHttpServer();
    servers.push(server);
    await listening(server);
    return { server, port: portOf(server) };
  }

  function mcpHeaders(extra: Record<string, string> = {}): Record<string, string> {
    return {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...extra,
    };
  }

  const initializeBody = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'http-auth-test', version: '1.0.0' },
    },
  });

  it('returns 401 when the S2S header is missing', async () => {
    const { port } = await start();
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: mcpHeaders({ 'x-threatlocker-api-key': 'header-key' }),
      body: initializeBody,
    });
    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.error).toMatch(/X-Gateway-S2S/);
  });

  it('returns 401 when the S2S header is invalid', async () => {
    const { port } = await start();
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: mcpHeaders({
        'x-gateway-s2s': mintHeader('wrong-secret'),
        'x-threatlocker-api-key': 'header-key',
      }),
      body: initializeBody,
    });
    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.error).toMatch(/X-Gateway-S2S/);
  });

  it('returns 401 in gateway mode when credential headers are missing and does not use env credentials', async () => {
    const credsSpy = vi.spyOn(client, 'getCredentials');
    const { port } = await start({ THREATLOCKER_API_KEY: ENV_API_KEY, THREATLOCKER_ORGANIZATION_ID: 'env-org' });
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: mcpHeaders({ 'x-gateway-s2s': mintHeader(SECRET) }),
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'threatlocker_status', arguments: {} },
      }),
    });
    expect(response.status).toBe(401);
    const text = await response.text();
    expect(text).toMatch(/x-threatlocker-api-key/);
    expect(text).not.toContain(ENV_API_KEY);
    expect(text).not.toMatch(/Configured/);
    expect(credsSpy).not.toHaveBeenCalled();
  });

  it('accepts a valid S2S header plus credential headers', async () => {
    const { port } = await start();
    const headers = mcpHeaders({
      'x-gateway-s2s': mintHeader(SECRET),
      'x-threatlocker-api-key': 'header-api-key',
      'x-threatlocker-organization-id': 'header-org',
    });

    const initialized = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers,
      body: initializeBody,
    });
    expect(initialized.status).toBe(200);
    const initBody = await initialized.json();
    expect(initBody.result?.serverInfo?.name).toBe('threatlocker-mcp');

    // Env credentials are unset, so "Configured" can only come from the headers.
    const status = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'threatlocker_status', arguments: {} },
      }),
    });
    expect(status.status).toBe(200);
    const statusBody = await status.json();
    const text = JSON.stringify(statusBody);
    expect(text).toMatch(/Configured \(API connection available\)/);
    expect(text).not.toContain('header-api-key');
    expect(text).not.toContain(SECRET);
  });

  it('serves /health without authentication and without reading credentials', async () => {
    const credsSpy = vi.spyOn(client, 'getCredentials');
    const { port } = await start({ THREATLOCKER_API_KEY: ENV_API_KEY });
    const response = await fetch(`http://127.0.0.1:${port}/health`);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe('ok');
    expect(body.transport).toBe('http');
    expect(body.credentials).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain(ENV_API_KEY);
    expect(credsSpy).not.toHaveBeenCalled();
  });
});
