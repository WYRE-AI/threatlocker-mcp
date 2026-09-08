import { describe, it, expect, vi, beforeEach } from 'vitest';
import { approvalRequestsHandler } from '../domains/approval_requests.js';
import { getClient } from '../utils/client.js';

vi.mock('../utils/client.js', () => ({
  getClient: vi.fn(),
}));

function mockClient(overrides: Record<string, unknown>) {
  const client = { approvalRequests: overrides };
  (getClient as ReturnType<typeof vi.fn>).mockResolvedValue(client);
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('approvalRequestsHandler.getTools', () => {
  it('exposes exactly the four approval-request tools', () => {
    const names = approvalRequestsHandler.getTools().map((t) => t.name);
    expect(names).toEqual([
      'threatlocker_approvals_list',
      'threatlocker_approvals_get',
      'threatlocker_approvals_pending_count',
      'threatlocker_approvals_get_permit_application',
    ]);
  });
});

describe('threatlocker_approvals_list', () => {
  it('defaults status to Pending when no status/elicitation is available and passes filters through', async () => {
    const list = vi.fn().mockResolvedValue({ items: [], total: 0 });
    mockClient({ list });

    const result = await approvalRequestsHandler.handleCall('threatlocker_approvals_list', {
      pageNumber: 2,
      pageSize: 10,
      searchText: 'chrome.exe',
      childOrganizations: true,
    });

    expect(list).toHaveBeenCalledWith({
      status: 'Pending',
      pageNumber: 2,
      pageSize: 10,
      searchText: 'chrome.exe',
      childOrganizations: true,
    });
    expect(result.content[0].text).toBe(JSON.stringify({ items: [], total: 0 }, null, 2));
    expect(result.isError).toBeUndefined();
  });

  it('passes an explicit status straight through unchanged', async () => {
    const list = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ list });

    await approvalRequestsHandler.handleCall('threatlocker_approvals_list', { status: 'Denied' });

    expect(list).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'Denied' }),
    );
  });

  it('translates status "All" into an undefined status filter (no status param sent to the API)', async () => {
    const list = vi.fn().mockResolvedValue({ items: [] });
    mockClient({ list });

    await approvalRequestsHandler.handleCall('threatlocker_approvals_list', { status: 'All' });

    expect(list).toHaveBeenCalledWith(
      expect.objectContaining({ status: undefined }),
    );
  });
});

describe('threatlocker_approvals_get', () => {
  it('forwards the approvalRequestId and returns the mapped response', async () => {
    const get = vi.fn().mockResolvedValue({ id: 'ar-1', status: 'Pending' });
    mockClient({ get });

    const result = await approvalRequestsHandler.handleCall('threatlocker_approvals_get', {
      approvalRequestId: 'ar-1',
    });

    expect(get).toHaveBeenCalledWith('ar-1');
    expect(result.content[0].text).toBe(JSON.stringify({ id: 'ar-1', status: 'Pending' }, null, 2));
  });
});

describe('threatlocker_approvals_pending_count', () => {
  it('calls getPendingCount (the method that actually exists on the SDK) with no arguments', async () => {
    const getPendingCount = vi.fn().mockResolvedValue({ count: 7 });
    mockClient({ getPendingCount });

    const result = await approvalRequestsHandler.handleCall('threatlocker_approvals_pending_count', {});

    expect(getPendingCount).toHaveBeenCalledWith();
    expect(result.content[0].text).toBe(JSON.stringify({ count: 7 }, null, 2));
  });
});

describe('threatlocker_approvals_get_permit_application', () => {
  it('forwards the approvalRequestId to getPermitApplication', async () => {
    const getPermitApplication = vi.fn().mockResolvedValue({ applicationName: 'chrome.exe' });
    mockClient({ getPermitApplication });

    const result = await approvalRequestsHandler.handleCall(
      'threatlocker_approvals_get_permit_application',
      { approvalRequestId: 'ar-2' },
    );

    expect(getPermitApplication).toHaveBeenCalledWith('ar-2');
    expect(result.content[0].text).toBe(JSON.stringify({ applicationName: 'chrome.exe' }, null, 2));
  });
});

describe('unknown tool', () => {
  it('returns an isError result and does not touch the client', async () => {
    const list = vi.fn();
    mockClient({ list });

    const result = await approvalRequestsHandler.handleCall('threatlocker_approvals_bogus', {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe('Unknown tool: threatlocker_approvals_bogus');
    expect(list).not.toHaveBeenCalled();
  });
});
