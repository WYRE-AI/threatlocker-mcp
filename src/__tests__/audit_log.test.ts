import { describe, it, expect, vi, beforeEach } from 'vitest';
import { auditLogHandler } from '../domains/audit_log.js';
import { getClient } from '../utils/client.js';

vi.mock('../utils/client.js', () => ({
  getClient: vi.fn(),
}));

function mockClient(overrides: Record<string, unknown>) {
  const client = { auditLog: overrides };
  (getClient as ReturnType<typeof vi.fn>).mockResolvedValue(client);
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('auditLogHandler.getTools', () => {
  it('exposes exactly the three audit-log tools', () => {
    const names = auditLogHandler.getTools().map((t) => t.name);
    expect(names).toEqual([
      'threatlocker_audit_search',
      'threatlocker_audit_get',
      'threatlocker_audit_file_history',
    ]);
  });
});

describe('threatlocker_audit_search', () => {
  it('passes searchText and dates through unchanged when searchText is supplied', async () => {
    const search = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ search });

    await auditLogHandler.handleCall('threatlocker_audit_search', {
      searchText: 'chrome.exe',
      pageNumber: 3,
      pageSize: 25,
      childOrganizations: false,
    });

    expect(search).toHaveBeenCalledWith({
      searchText: 'chrome.exe',
      startDate: undefined,
      endDate: undefined,
      pageNumber: 3,
      pageSize: 25,
      childOrganizations: false,
    });
  });

  it('passes an explicit date range through unchanged, without eliciting', async () => {
    const search = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ search });

    await auditLogHandler.handleCall('threatlocker_audit_search', {
      startDate: '2026-01-01T00:00:00.000Z',
      endDate: '2026-01-02T00:00:00.000Z',
    });

    expect(search).toHaveBeenCalledWith(
      expect.objectContaining({
        startDate: '2026-01-01T00:00:00.000Z',
        endDate: '2026-01-02T00:00:00.000Z',
      }),
    );
  });

  it('elicits a date range when neither searchText nor a date range is given, and (with no MCP server ref registered in tests) elicitation short-circuits to null so no range is computed', async () => {
    const search = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ search });

    await auditLogHandler.handleCall('threatlocker_audit_search', {});

    expect(search).toHaveBeenCalledTimes(1);
    const params = search.mock.calls[0][0];
    expect(params.searchText).toBeUndefined();
    // elicitSelection() returns null (no `server` ref in test env), and the
    // handler only computes a range for its literal 'Last 24h'/'Last 7d'/
    // 'Last 30d' matches — a null choice leaves both dates undefined, same
    // as its documented 'Custom' path.
    expect(params.startDate).toBeUndefined();
    expect(params.endDate).toBeUndefined();
  });

  it('returns the raw search results as JSON', async () => {
    const search = vi.fn().mockResolvedValue({ items: [{ id: 'a1' }], total: 1 });
    mockClient({ search });

    const result = await auditLogHandler.handleCall('threatlocker_audit_search', {
      searchText: 'x',
    });

    expect(result.content[0].text).toBe(
      JSON.stringify({ items: [{ id: 'a1' }], total: 1 }, null, 2),
    );
  });
});

describe('threatlocker_audit_get', () => {
  it('forwards the actionLogId and returns the mapped response', async () => {
    const get = vi.fn().mockResolvedValue({ id: 'al-1' });
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      actionLogId: 'al-1',
    });

    expect(get).toHaveBeenCalledWith('al-1');
    expect(result.content[0].text).toBe(JSON.stringify({ id: 'al-1' }, null, 2));
  });
});

describe('threatlocker_audit_file_history', () => {
  it('forwards the fullPath to getFileHistory (the method that actually exists on the SDK)', async () => {
    const getFileHistory = vi.fn().mockResolvedValue({ events: [] });
    mockClient({ getFileHistory });

    const result = await auditLogHandler.handleCall('threatlocker_audit_file_history', {
      fullPath: 'C:\\Program Files\\App\\app.exe',
    });

    expect(getFileHistory).toHaveBeenCalledWith('C:\\Program Files\\App\\app.exe');
    expect(result.content[0].text).toBe(JSON.stringify({ events: [] }, null, 2));
  });
});

describe('unknown tool', () => {
  it('returns an isError result and does not touch the client', async () => {
    const search = vi.fn();
    mockClient({ search });

    const result = await auditLogHandler.handleCall('threatlocker_audit_bogus', {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe('Unknown tool: threatlocker_audit_bogus');
    expect(search).not.toHaveBeenCalled();
  });
});
