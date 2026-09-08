import { describe, it, expect, vi, beforeEach } from 'vitest';
import { computersHandler } from '../domains/computers.js';
import { getClient } from '../utils/client.js';

vi.mock('../utils/client.js', () => ({
  getClient: vi.fn(),
}));

function mockClient(overrides: Record<string, unknown>) {
  const client = { computers: overrides };
  (getClient as ReturnType<typeof vi.fn>).mockResolvedValue(client);
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('computersHandler.getTools', () => {
  it('exposes exactly the three computer tools', () => {
    const names = computersHandler.getTools().map((t) => t.name);
    expect(names).toEqual([
      'threatlocker_computers_list',
      'threatlocker_computers_get',
      'threatlocker_computers_get_checkins',
    ]);
  });
});

describe('threatlocker_computers_list', () => {
  it('skips elicitation and forwards searchText when it is supplied', async () => {
    const list = vi.fn().mockResolvedValue({ computers: [] });
    mockClient({ list });

    await computersHandler.handleCall('threatlocker_computers_list', {
      searchText: 'DESKTOP-1',
      pageNumber: 1,
      pageSize: 20,
      childOrganizations: true,
    });

    expect(list).toHaveBeenCalledWith({
      searchText: 'DESKTOP-1',
      computerGroup: undefined,
      pageNumber: 1,
      pageSize: 20,
      childOrganizations: true,
    });
  });

  it('skips elicitation when computerGroup filter is supplied, even without searchText', async () => {
    const list = vi.fn().mockResolvedValue({ computers: [] });
    mockClient({ list });

    await computersHandler.handleCall('threatlocker_computers_list', {
      computerGroup: 'Servers',
    });

    expect(list).toHaveBeenCalledWith(
      expect.objectContaining({ searchText: undefined, computerGroup: 'Servers' }),
    );
  });

  it('elicits when neither searchText nor computerGroup is given, and (no server ref in test env) leaves searchText undefined', async () => {
    const list = vi.fn().mockResolvedValue({ computers: [] });
    mockClient({ list });

    await computersHandler.handleCall('threatlocker_computers_list', {});

    expect(list).toHaveBeenCalledWith(
      expect.objectContaining({ searchText: undefined, computerGroup: undefined }),
    );
  });

  it('returns the raw list response as JSON', async () => {
    const list = vi.fn().mockResolvedValue({ computers: [{ id: 'c1' }], total: 1 });
    mockClient({ list });

    const result = await computersHandler.handleCall('threatlocker_computers_list', {
      searchText: 'x',
    });

    expect(result.content[0].text).toBe(
      JSON.stringify({ computers: [{ id: 'c1' }], total: 1 }, null, 2),
    );
  });
});

describe('threatlocker_computers_get', () => {
  it('forwards the computerId and returns the mapped response', async () => {
    const get = vi.fn().mockResolvedValue({ id: 'c1', name: 'DESKTOP-1' });
    mockClient({ get });

    const result = await computersHandler.handleCall('threatlocker_computers_get', {
      computerId: 'c1',
    });

    expect(get).toHaveBeenCalledWith('c1');
    expect(result.content[0].text).toBe(JSON.stringify({ id: 'c1', name: 'DESKTOP-1' }, null, 2));
  });
});

describe('threatlocker_computers_get_checkins', () => {
  it('calls getCheckins with a single params object (its real, single-argument signature)', async () => {
    const getCheckins = vi.fn().mockResolvedValue({ checkins: [] });
    mockClient({ getCheckins });

    await computersHandler.handleCall('threatlocker_computers_get_checkins', {
      computerId: 'c1',
      pageNumber: 2,
      pageSize: 5,
    });

    // The previous two-argument call, getCheckins(computerId, {pageNumber,
    // pageSize}), silently dropped computerId — the SDK method only takes
    // one params object, so computerId never reached the API and every
    // checkin lookup 400'd as a bad request.
    expect(getCheckins).toHaveBeenCalledWith({ computerId: 'c1', pageNumber: 2, pageSize: 5 });
  });

  it('returns the raw checkins response as JSON', async () => {
    const getCheckins = vi.fn().mockResolvedValue({ checkins: [{ id: 'chk1' }] });
    mockClient({ getCheckins });

    const result = await computersHandler.handleCall('threatlocker_computers_get_checkins', {
      computerId: 'c1',
    });

    expect(result.content[0].text).toBe(
      JSON.stringify({ checkins: [{ id: 'chk1' }] }, null, 2),
    );
  });
});

describe('unknown tool', () => {
  it('returns an isError result and does not touch the client', async () => {
    const list = vi.fn();
    mockClient({ list });

    const result = await computersHandler.handleCall('threatlocker_computers_bogus', {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe('Unknown tool: threatlocker_computers_bogus');
    expect(list).not.toHaveBeenCalled();
  });
});
