import { describe, it, expect, vi, beforeEach } from 'vitest';
import { computerGroupsHandler } from '../domains/computer_groups.js';
import { getClient } from '../utils/client.js';

vi.mock('../utils/client.js', () => ({
  getClient: vi.fn(),
}));

function mockClient(overrides: Record<string, unknown>) {
  const client = { computerGroups: overrides };
  (getClient as ReturnType<typeof vi.fn>).mockResolvedValue(client);
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('computerGroupsHandler.getTools', () => {
  it('exposes exactly the two computer-group tools', () => {
    const names = computerGroupsHandler.getTools().map((t) => t.name);
    expect(names).toEqual([
      'threatlocker_computer_groups_list',
      'threatlocker_computer_groups_dropdown',
    ]);
  });
});

describe('threatlocker_computer_groups_list', () => {
  it('forwards all filters to computerGroups.list and returns the mapped response', async () => {
    const list = vi.fn().mockResolvedValue({ groups: [{ id: 'g1' }] });
    mockClient({ list });

    const result = await computerGroupsHandler.handleCall('threatlocker_computer_groups_list', {
      osType: 'Windows',
      includeAllComputers: true,
      includeGlobal: false,
    });

    expect(list).toHaveBeenCalledWith({
      osType: 'Windows',
      includeAllComputers: true,
      includeGlobal: false,
    });
    expect(result.content[0].text).toBe(JSON.stringify({ groups: [{ id: 'g1' }] }, null, 2));
  });

  it('passes undefined filters through when no args are given', async () => {
    const list = vi.fn().mockResolvedValue({ groups: [] });
    mockClient({ list });

    await computerGroupsHandler.handleCall('threatlocker_computer_groups_list', {});

    expect(list).toHaveBeenCalledWith({
      osType: undefined,
      includeAllComputers: undefined,
      includeGlobal: undefined,
    });
  });
});

describe('threatlocker_computer_groups_dropdown', () => {
  it('calls getDropdown (the method that actually exists on the SDK) with no arguments', async () => {
    const getDropdown = vi.fn().mockResolvedValue([{ id: 'g1', name: 'All Computers' }]);
    mockClient({ getDropdown });

    const result = await computerGroupsHandler.handleCall('threatlocker_computer_groups_dropdown', {});

    expect(getDropdown).toHaveBeenCalledWith();
    expect(result.content[0].text).toBe(
      JSON.stringify([{ id: 'g1', name: 'All Computers' }], null, 2),
    );
  });
});

describe('unknown tool', () => {
  it('returns an isError result and does not touch the client', async () => {
    const list = vi.fn();
    mockClient({ list });

    const result = await computerGroupsHandler.handleCall('threatlocker_computer_groups_bogus', {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe('Unknown tool: threatlocker_computer_groups_bogus');
    expect(list).not.toHaveBeenCalled();
  });
});
