import { ThreatLockerClient } from '@wyre-ai/node-threatlocker';
import { AsyncLocalStorage } from 'node:async_hooks';
import { logger } from './logger.js';
import { detectInstance } from './instance-detect.js';

export interface Credentials {
  apiKey: string;
  /**
   * Optional — the ThreatLocker API defaults to the key's primary
   * organization when the OrganizationId header is omitted, so a key alone
   * is a complete credential.
   */
  organizationId?: string;
  /**
   * ThreatLocker portal instance letter — the letter in the tenant's portal
   * URL (portal.<instance>.threatlocker.com). API keys only exist on the
   * instance they were created on; using the wrong instance yields HTTP 440.
   * Auto-detected by probing all instances when absent.
   */
  instance?: string;
}

// Hostname-safety guard: the instance is user-supplied (gateway header /
// env var) and is interpolated into a hostname.
const INSTANCE_RE = /^[a-z]{1,10}$/;

// Request-scoped credential store. In gateway mode the HTTP layer runs each
// request inside runWithCredentials({apiKey, ...}); getCredentials() reads
// it. Falls back to process.env for stdio/single-tenant mode.
const credStore = new AsyncLocalStorage<Credentials>();

export function runWithCredentials<T>(creds: Credentials, fn: () => T): T {
  return credStore.run(creds, fn);
}

export function getCredentials(): Credentials | null {
  const scoped = credStore.getStore();
  if (scoped?.apiKey) {
    // Normalize a blank organizationId to "unset" — the API treats absence
    // as "the key's primary org". Never fall through to env here: in gateway
    // mode env belongs to no tenant, and mixing tiers risks cross-tenant creds.
    return { ...scoped, organizationId: scoped.organizationId || undefined };
  }

  const apiKey = process.env.THREATLOCKER_API_KEY;
  if (!apiKey) {
    logger.warn('Missing credentials', { hasApiKey: false });
    return null;
  }
  return {
    apiKey,
    organizationId: process.env.THREATLOCKER_ORGANIZATION_ID || undefined,
    instance: process.env.THREATLOCKER_INSTANCE,
  };
}

// Constructs a client from the request-scoped (or env) credentials. The client
// is cheap and holds no shared mutable state, so we build one per call — never
// a process-global singleton.
export async function getClient(): Promise<any> {
  const creds = getCredentials();
  if (!creds) {
    throw new Error(
      'No ThreatLocker API credentials configured. Set THREATLOCKER_API_KEY ' +
        '(THREATLOCKER_ORGANIZATION_ID is optional — the API defaults to the ' +
        "key's primary organization).",
    );
  }
  let instance = creds.instance?.toLowerCase();
  if (instance && !INSTANCE_RE.test(instance)) {
    // Fail loudly instead of silently falling back — a wrong-instance client
    // produces confusing HTTP 440s on every call.
    throw new Error(`Invalid ThreatLocker portal instance "${creds.instance}".`);
  }
  if (!instance) {
    // No instance supplied — find the key's home instance by probing.
    instance = await detectInstance(creds.apiKey);
  }
  logger.info('Created ThreatLocker API client', { instance });
  return new ThreatLockerClient({
    apiKey: creds.apiKey,
    ...(creds.organizationId ? { organizationId: creds.organizationId } : {}),
    baseUrl: `https://portalapi.${instance}.threatlocker.com/portalapi`,
  });
}
