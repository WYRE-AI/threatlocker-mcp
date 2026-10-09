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
  const tool = () => auditLogHandler.getTools().find((t) => t.name === 'threatlocker_audit_get');

  it('describes eActionLogId as the search-row id and keeps actionLogId as a deprecated alias', () => {
    const schema = tool()?.inputSchema as {
      description?: string;
      anyOf?: Array<{ required: string[] }>;
      properties?: Record<string, { type?: string; description?: string; deprecated?: boolean; minimum?: number; maximum?: number }>;
    };
    const description = tool()?.description ?? '';

    expect(description).toMatch(/eActionLogId/);
    expect(description).toMatch(/threatlocker_audit_search/);
    expect(schema.anyOf).toEqual([{ required: ['eActionLogId'] }, { required: ['actionLogId'] }]);
    expect(schema.properties?.eActionLogId?.type).toBe('string');
    expect(schema.properties?.eActionLogId?.description).toMatch(/threatlocker_audit_search/);
    expect(schema.properties?.sourceTableId).toMatchObject({
      type: 'integer',
      minimum: 1,
      maximum: 4,
    });
    expect(schema.properties?.actionLogId?.deprecated).toBe(true);
    expect(schema.properties?.actionLogId?.description).toMatch(/deprecated alias/i);
  });

  it('passes eActionLogId and sourceTableId to auditLog.get', async () => {
    const get = vi.fn().mockResolvedValue({ eActionLogId: 'opaque-id' });
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: '  opaque-id  ',
      sourceTableId: 1,
    });

    expect(get).toHaveBeenCalledWith('opaque-id', { sourceTableId: 1 });
    expect(result.content[0].text).toBe(JSON.stringify({ eActionLogId: 'opaque-id' }, null, 2));
    expect(result.isError).toBeUndefined();
  });

  it('omits sourceTableId when the caller does not set it', async () => {
    const get = vi.fn().mockResolvedValue({ eActionLogId: 'opaque-id' });
    mockClient({ get });

    await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
    });

    expect(get).toHaveBeenCalledWith('opaque-id', { sourceTableId: undefined });
  });

  it('stringifies the deprecated actionLogId alias when eActionLogId is absent', async () => {
    const get = vi.fn().mockResolvedValue({ eActionLogId: 'al-1' });
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      actionLogId: '  al-1  ',
    });

    expect(get).toHaveBeenCalledWith('al-1', { sourceTableId: undefined });
    expect(result.content[0].text).toBe(JSON.stringify({ eActionLogId: 'al-1' }, null, 2));
  });

  it('rejects a numeric actionLogId alias before calling get', async () => {
    const get = vi.fn();
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      actionLogId: 48291,
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/eActionLogId/);
    expect(result.content[0].text).toMatch(/numeric/);
    expect(get).not.toHaveBeenCalled();
  });

  it('rejects a digit-only eActionLogId before calling get', async () => {
    const get = vi.fn();
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: '  48291  ',
    });

    expect(result.isError).toBe(true);
    expect(get).not.toHaveBeenCalled();
  });

  it('prefers eActionLogId when both ids are sent', async () => {
    const get = vi.fn().mockResolvedValue({});
    mockClient({ get });

    await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
      actionLogId: '48291',
      sourceTableId: 4,
    });

    expect(get).toHaveBeenCalledWith('opaque-id', { sourceTableId: 4 });
  });

  it('rejects a call with neither id and does not call get', async () => {
    const get = vi.fn();
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/eActionLogId/);
    expect(get).not.toHaveBeenCalled();
  });

  it('rejects a sourceTableId outside 1-4 and does not call get', async () => {
    const get = vi.fn();
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
      sourceTableId: 5,
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/sourceTableId/);
    expect(get).not.toHaveBeenCalled();
  });
});

describe('threatlocker_audit_file_history', () => {
  const tool = () =>
    auditLogHandler.getTools().find((t) => t.name === 'threatlocker_audit_file_history');

  it('requires fullPath plus hostname or computerId', () => {
    const schema = tool()?.inputSchema as {
      required?: string[];
      anyOf?: Array<{ required: string[] }>;
      properties?: Record<string, { description?: string }>;
    };

    expect(schema.required).toEqual(['fullPath']);
    expect(schema.anyOf).toEqual([{ required: ['hostname'] }, { required: ['computerId'] }]);
    expect(schema.properties?.hostname?.description).toMatch(/hostname/i);
    expect(schema.properties?.computerId?.description).toMatch(/GUID/);
    expect(schema.properties).toHaveProperty('sourceTableId');
    expect(schema.properties).toHaveProperty('pageNumber');
    expect(schema.properties).toHaveProperty('pageSize');
  });

  it('calls getFileHistory with { fullPath, hostname }', async () => {
    const getFileHistory = vi.fn().mockResolvedValue({ events: [] });
    mockClient({ getFileHistory });

    const result = await auditLogHandler.handleCall('threatlocker_audit_file_history', {
      fullPath: '  C:\\Program Files\\App\\app.exe  ',
      hostname: '  WORKSTATION-1  ',
    });

    expect(getFileHistory).toHaveBeenCalledWith({
      fullPath: 'C:\\Program Files\\App\\app.exe',
      hostname: 'WORKSTATION-1',
    });
    expect(result.content[0].text).toBe(JSON.stringify({ events: [] }, null, 2));
    expect(result.isError).toBeUndefined();
  });

  it('calls getFileHistory with { fullPath, computerId } when hostname is omitted', async () => {
    const getFileHistory = vi.fn().mockResolvedValue([]);
    mockClient({ getFileHistory });

    await auditLogHandler.handleCall('threatlocker_audit_file_history', {
      fullPath: 'C:\\Windows\\System32\\cmd.exe',
      computerId: '3f1c2a90-7b04-4e1d-9c55-0a1b2c3d4e5f',
    });

    expect(getFileHistory).toHaveBeenCalledWith({
      fullPath: 'C:\\Windows\\System32\\cmd.exe',
      computerId: '3f1c2a90-7b04-4e1d-9c55-0a1b2c3d4e5f',
    });
  });

  it('forwards both identifiers and optional paging fields when set', async () => {
    const getFileHistory = vi.fn().mockResolvedValue([]);
    mockClient({ getFileHistory });

    await auditLogHandler.handleCall('threatlocker_audit_file_history', {
      fullPath: 'C:\\App\\app.exe',
      hostname: 'HOST',
      computerId: '3f1c2a90-7b04-4e1d-9c55-0a1b2c3d4e5f',
      sourceTableId: 2,
      pageNumber: 3,
      pageSize: 25,
    });

    expect(getFileHistory).toHaveBeenCalledWith({
      fullPath: 'C:\\App\\app.exe',
      hostname: 'HOST',
      computerId: '3f1c2a90-7b04-4e1d-9c55-0a1b2c3d4e5f',
      sourceTableId: 2,
      pageNumber: 3,
      pageSize: 25,
    });
  });

  it('rejects fullPath alone and does not call getFileHistory', async () => {
    const getFileHistory = vi.fn();
    mockClient({ getFileHistory });

    const result = await auditLogHandler.handleCall('threatlocker_audit_file_history', {
      fullPath: 'C:\\Program Files\\App\\app.exe',
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/hostname or computerId/);
    expect(getFileHistory).not.toHaveBeenCalled();
  });

  it('rejects a blank hostname when computerId is missing', async () => {
    const getFileHistory = vi.fn();
    mockClient({ getFileHistory });

    const result = await auditLogHandler.handleCall('threatlocker_audit_file_history', {
      fullPath: 'C:\\App\\app.exe',
      hostname: '   ',
    });

    expect(result.isError).toBe(true);
    expect(getFileHistory).not.toHaveBeenCalled();
  });

  it('drops a blank hostname and still sends computerId', async () => {
    const getFileHistory = vi.fn().mockResolvedValue([]);
    mockClient({ getFileHistory });

    await auditLogHandler.handleCall('threatlocker_audit_file_history', {
      fullPath: 'C:\\App\\app.exe',
      hostname: '   ',
      computerId: '3f1c2a90-7b04-4e1d-9c55-0a1b2c3d4e5f',
    });

    expect(getFileHistory).toHaveBeenCalledWith({
      fullPath: 'C:\\App\\app.exe',
      computerId: '3f1c2a90-7b04-4e1d-9c55-0a1b2c3d4e5f',
    });
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
