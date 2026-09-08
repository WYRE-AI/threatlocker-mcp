import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { DomainHandler, CallToolResult } from '../utils/types.js';
import { getClient } from '../utils/client.js';
import { logger } from '../utils/logger.js';

function getTools(): Tool[] {
  return [
    {
      name: 'threatlocker_computer_groups_list',
      description: 'List computer groups with optional filters.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          osType: { type: 'string', description: 'Operating system type filter' },
          includeAllComputers: { type: 'boolean', description: 'Include "All Computers" group' },
          includeGlobal: { type: 'boolean', description: 'Include global groups' },
        },
      },
    },
    {
      name: 'threatlocker_computer_groups_dropdown',
      description: 'Get computer groups in dropdown format.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
      },
    },
  ];
}

async function handleCall(toolName: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const client = await getClient();

  switch (toolName) {
    case 'threatlocker_computer_groups_list': {
      const params = {
        osType: args.osType as string | undefined,
        includeAllComputers: args.includeAllComputers as boolean | undefined,
        includeGlobal: args.includeGlobal as boolean | undefined,
      };
      logger.info('API call: computerGroups.list', params);
      const result = await client.computerGroups.list(params);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case 'threatlocker_computer_groups_dropdown': {
      logger.info('API call: computerGroups.getDropdown');
      const dropdown = await client.computerGroups.getDropdown();
      return { content: [{ type: 'text', text: JSON.stringify(dropdown, null, 2) }] };
    }
    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${toolName}` }], isError: true };
  }
}

export const computerGroupsHandler: DomainHandler = { getTools, handleCall };