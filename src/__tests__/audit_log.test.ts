import { describe, it, expect, vi, beforeEach } from 'vitest';
import { auditLogHandler, coerceSourceTableId, normalizeAuditSearchResult } from '../domains/audit_log.js';
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

describe('threatlocker_audit_search action filters', () => {
  const range = { startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-01-08T00:00:00.000Z' };

  it('passes actionId, actionType and groupBys to the SDK for a deny breakdown', async () => {
    const search = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ search });

    await auditLogHandler.handleCall('threatlocker_audit_search', {
      ...range,
      actionId: 2,
      actionType: 'Execute',
      groupBys: [6, 9],
    });

    expect(search).toHaveBeenCalledWith(
      expect.objectContaining({ actionId: 2, actionType: 'execute', groupBys: [6, 9] }),
    );
  });

  it('passes onlyTrueDenies with actionId 99', async () => {
    const search = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ search });

    await auditLogHandler.handleCall('threatlocker_audit_search', { ...range, actionId: 99, onlyTrueDenies: true });

    expect(search).toHaveBeenCalledWith(expect.objectContaining({ actionId: 99, onlyTrueDenies: true }));
  });

  it('does not add filter keys when they are not set', async () => {
    const search = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ search });

    await auditLogHandler.handleCall('threatlocker_audit_search', range);

    const params = search.mock.calls[0][0];
    for (const key of ['actionId', 'actionType', 'groupBys', 'onlyTrueDenies', 'simulateDeny']) {
      expect(params).not.toHaveProperty(key);
    }
  });

  it.each([
    [{ actionId: 4 }, /actionId/],
    [{ actionType: 'blocked' }, /actionType/],
    [{ onlyTrueDenies: true, simulateDeny: true }, /not both/],
    [{ onlyTrueDenies: true, actionId: 2 }, /99/],
    [{ groupBys: [] }, /groupBys/],
    [{ groupBys: [1, 2, 3] }, /groupBys/],
    [{ groupBys: ['6'] }, /groupBys/],
  ])('rejects %o without calling the API', async (bad, pattern) => {
    const search = vi.fn();
    mockClient({ search });

    const result = await auditLogHandler.handleCall('threatlocker_audit_search', { ...range, ...bad });

    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toMatch(pattern);
    expect(search).not.toHaveBeenCalled();
  });

  it('declares the filters on the tool schema', () => {
    const tool = auditLogHandler.getTools().find((t) => t.name === 'threatlocker_audit_search');
    const props = tool?.inputSchema.properties as Record<string, { enum?: unknown[] }>;
    expect(props.actionId.enum).toEqual([1, 2, 3, 6, 99]);
    expect(props.actionType.enum).toContain('execute');
    expect(props).toHaveProperty('groupBys');
    expect(props).toHaveProperty('onlyTrueDenies');
    expect(props).toHaveProperty('simulateDeny');
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

  it('passes a trimmed hostname filter through to auditLog.search', async () => {
    const search = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ search });

    await auditLogHandler.handleCall('threatlocker_audit_search', {
      searchText: '*setup.msi',
      hostname: '  WS-01  ',
      startDate: '2026-01-01T00:00:00Z',
      endDate: '2026-01-01T01:00:00Z',
      childOrganizations: true,
    });

    expect(search).toHaveBeenCalledWith({
      searchText: '*setup.msi',
      hostname: 'WS-01',
      startDate: '2026-01-01T00:00:00Z',
      endDate: '2026-01-01T01:00:00Z',
      pageNumber: undefined,
      pageSize: undefined,
      childOrganizations: true,
    });
  });

  it('does not send a blank hostname', async () => {
    const search = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ search });

    await auditLogHandler.handleCall('threatlocker_audit_search', {
      searchText: '*setup.msi',
      hostname: '   ',
    });

    expect(search.mock.calls[0][0]).not.toHaveProperty('hostname');
  });

  it('describes searchText as a full-path filter with wildcards and exposes hostname', () => {
    const tool = auditLogHandler.getTools().find((t) => t.name === 'threatlocker_audit_search');
    const props = (tool?.inputSchema as { properties: Record<string, { description?: string }> }).properties;

    expect(props.searchText.description).toMatch(/fullPath/);
    expect(props.searchText.description).toMatch(/wildcard/);
    expect(props.hostname.description).toMatch(/hostname/i);
    expect(tool?.description).toMatch(/not free text/);
  });

  it('returns the search results as JSON, copying sourceTableId aliases onto each row', async () => {
    const search = vi.fn().mockResolvedValue({
      items: [
        { eActionLogId: 'row-1', SourceTableId: '2', OrganizationId: 'org-a' },
        { eActionLogId: 'row-2', actionType: 'Execute' },
      ],
      total: 2,
    });
    mockClient({ search });

    const result = await auditLogHandler.handleCall('threatlocker_audit_search', {
      searchText: 'x',
    });

    expect(JSON.parse(result.content[0].text)).toEqual({
      items: [
        {
          eActionLogId: 'row-1',
          SourceTableId: '2',
          OrganizationId: 'org-a',
          sourceTableId: 2,
          organizationId: 'org-a',
        },
        { eActionLogId: 'row-2', actionType: 'Execute' },
      ],
      total: 2,
    });
  });

  it('does not invent sourceTableId when the upstream row has no alias', async () => {
    const search = vi.fn().mockResolvedValue({
      items: [{ eActionLogId: 'row-1', organizationId: 'org-a' }],
    });
    mockClient({ search });

    const result = await auditLogHandler.handleCall('threatlocker_audit_search', {
      searchText: 'x',
    });

    const items = JSON.parse(result.content[0].text).items;
    expect(items[0]).toEqual({ eActionLogId: 'row-1', organizationId: 'org-a' });
    expect(items[0]).not.toHaveProperty('sourceTableId');
  });
});

describe('normalizeAuditSearchResult / coerceSourceTableId', () => {
  it('coerces numeric, numeric-string, and known table names', () => {
    expect(coerceSourceTableId(1)).toBe(1);
    expect(coerceSourceTableId('  4  ')).toBe(4);
    expect(coerceSourceTableId('DenyActionLog')).toBe(2);
    expect(coerceSourceTableId('baseline')).toBe(3);
    expect(coerceSourceTableId(0)).toBeUndefined();
    expect(coerceSourceTableId('5')).toBeUndefined();
  });

  it('maps a bare array and PascalCase aliases, and leaves unknown rows alone', () => {
    expect(
      normalizeAuditSearchResult([
        { eActionLogId: 'a', sourceTable: 'ActionLog' },
        { eActionLogId: 'b' },
      ]),
    ).toEqual([
      { eActionLogId: 'a', sourceTable: 'ActionLog', sourceTableId: 1 },
      { eActionLogId: 'b' },
    ]);
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

  it('probes sourceTableId 1-4 when the caller does not set it, and returns the first success', async () => {
    const get = vi
      .fn()
      .mockRejectedValueOnce(Object.assign(new Error('Server error: 500'), { statusCode: 500 }))
      .mockResolvedValueOnce({ eActionLogId: 'opaque-id', sourceTableId: 2 });
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
      organizationId: 'org-guid',
    });

    expect(get).toHaveBeenCalledTimes(2);
    expect(get).toHaveBeenNthCalledWith(1, 'opaque-id', { sourceTableId: 1, organizationId: 'org-guid' });
    expect(get).toHaveBeenNthCalledWith(2, 'opaque-id', { sourceTableId: 2, organizationId: 'org-guid' });
    expect(result.isError).toBeUndefined();
    expect(JSON.parse(result.content[0].text)).toEqual({ eActionLogId: 'opaque-id', sourceTableId: 2 });
  });

  it('does not probe further after a non-500 error', async () => {
    const err = new Error('Authentication failed');
    const get = vi.fn().mockRejectedValue(err);
    mockClient({ get });

    await expect(
      auditLogHandler.handleCall('threatlocker_audit_get', { eActionLogId: 'opaque-id' }),
    ).rejects.toBe(err);
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith('opaque-id', { sourceTableId: 1 });
  });

  it('stringifies the deprecated actionLogId alias when eActionLogId is absent', async () => {
    const get = vi.fn().mockResolvedValue({ eActionLogId: 'al-1' });
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      actionLogId: '  al-1  ',
    });

    expect(get).toHaveBeenCalledWith('al-1', { sourceTableId: 1 });
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

  it('forwards a trimmed organizationId in the options', async () => {
    const get = vi.fn().mockResolvedValue({});
    mockClient({ get });

    await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
      sourceTableId: 2,
      organizationId: '  org-guid  ',
    });

    expect(get).toHaveBeenCalledWith('opaque-id', { sourceTableId: 2, organizationId: 'org-guid' });
  });

  it('accepts a numeric-string sourceTableId', async () => {
    const get = vi.fn().mockResolvedValue({});
    mockClient({ get });

    await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
      sourceTableId: '3',
    });

    expect(get).toHaveBeenCalledWith('opaque-id', { sourceTableId: 3 });
  });

  it.each([5, '5', 'abc', 1.5])('rejects sourceTableId %j', async (sourceTableId) => {
    const get = vi.fn();
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
      sourceTableId,
    });

    expect(result.isError).toBe(true);
    expect(get).not.toHaveBeenCalled();
  });

  it.each([42, '   ', {}])('rejects invalid organizationId %j', async (organizationId) => {
    const get = vi.fn();
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
      organizationId,
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/organizationId/);
    expect(get).not.toHaveBeenCalled();
  });

  it('maps HTTP 500 to an actionable error naming the missing fields after probing tables 1-4', async () => {
    const get = vi.fn().mockRejectedValue(new Error('Server error: 500 after 4 attempts'));
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
    });

    expect(result.isError).toBe(true);
    expect(get).toHaveBeenCalledTimes(4);
    expect(get.mock.calls.map((call) => call[1].sourceTableId)).toEqual([1, 2, 3, 4]);
    const text = result.content[0].text;
    expect(text).toMatch(/HTTP 500/);
    expect(text).toMatch(/Missing from this call: sourceTableId, organizationId/);
    expect(text).toMatch(/Already probed ActionLogGetByIdV2 with sourceTableId 1, 2, 3, 4/);
    expect(text).toMatch(/threatlocker_audit_search/);
    expect(text).toMatch(/Do not retry/);
  });

  it('maps an error with statusCode 500 and lists only the missing field', async () => {
    const get = vi.fn().mockRejectedValue(Object.assign(new Error('boom'), { statusCode: 500 }));
    mockClient({ get });

    const result = await auditLogHandler.handleCall('threatlocker_audit_get', {
      eActionLogId: 'opaque-id',
      sourceTableId: 1,
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/Missing from this call: organizationId\./);
  });

  it('rethrows non-500 errors', async () => {
    const err = new Error('Authentication failed');
    const get = vi.fn().mockRejectedValue(err);
    mockClient({ get });

    await expect(
      auditLogHandler.handleCall('threatlocker_audit_get', { eActionLogId: 'opaque-id' }),
    ).rejects.toBe(err);
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

  it('exposes organizationId for computers in child organizations', () => {
    const schema = tool()?.inputSchema as { properties?: Record<string, { description?: string }> };
    expect(schema.properties?.organizationId?.description).toMatch(/child organization/);
    expect(tool()?.description).toMatch(/organizationId/);
  });

  it('forwards a trimmed organizationId to getFileHistory', async () => {
    const getFileHistory = vi.fn().mockResolvedValue([]);
    mockClient({ getFileHistory });

    await auditLogHandler.handleCall('threatlocker_audit_file_history', {
      fullPath: 'C:\\Temp\\setup.msi',
      computerId: '3f1c2a90-7b04-4e1d-9c55-0a1b2c3d4e5f',
      organizationId: '  0b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8  ',
    });

    expect(getFileHistory).toHaveBeenCalledWith({
      fullPath: 'C:\\Temp\\setup.msi',
      computerId: '3f1c2a90-7b04-4e1d-9c55-0a1b2c3d4e5f',
      organizationId: '0b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8',
    });
  });

  it('drops a blank organizationId', async () => {
    const getFileHistory = vi.fn().mockResolvedValue([]);
    mockClient({ getFileHistory });

    await auditLogHandler.handleCall('threatlocker_audit_file_history', {
      fullPath: 'C:\\App\\app.exe',
      hostname: 'HOST',
      organizationId: '   ',
    });

    expect(getFileHistory).toHaveBeenCalledWith({ fullPath: 'C:\\App\\app.exe', hostname: 'HOST' });
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
