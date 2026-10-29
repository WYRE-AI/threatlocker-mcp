import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { DomainHandler, CallToolResult } from '../utils/types.js';
import { getClient } from '../utils/client.js';
import { logger } from '../utils/logger.js';

function getTools(): Tool[] {
  return [
    {
      name: 'threatlocker_organizations_list_children',
      description: 'List child organizations with optional filters.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          searchText: { type: 'string', description: 'Search text filter' },
          pageNumber: { type: 'number', description: 'Page number (default 1)' },
          pageSize: { type: 'number', description: 'Page size (default 50)' },
        },
      },
    },
    {
      name: 'threatlocker_organizations_get_auth_key',
      description:
        'Get the installation auth key for the organization the configured credentials are scoped to. ' +
        'The returned value is a sensitive installation key; do not log or share it.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
      },
    },
    {
      name: 'threatlocker_organizations_for_move_computers',
      description: 'Get organizations available for moving computers.',
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
    case 'threatlocker_organizations_list_children': {
      const params = {
        searchText: args.searchText as string | undefined,
        pageNumber: args.pageNumber as number | undefined,
        pageSize: args.pageSize as number | undefined,
      };
      logger.info('API call: organizations.listChildren', params);
      const result = await client.organizations.listChildren(params);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case 'threatlocker_organizations_get_auth_key': {
      // Never log the key itself. The org is determined solely by the request-scoped client
      // (tenant credentials); tool args must never select it.
      logger.info('API call: organizations.getAuthKey');
      const authKey: unknown = await client.organizations.getAuthKey();
      if (typeof authKey === 'string') {
        return { content: [{ type: 'text', text: JSON.stringify({ authKey }, null, 2) }] };
      }
      if (authKey && typeof authKey === 'object' && Object.keys(authKey).length === 0) {
        return {
          content: [{ type: 'text', text: 'ThreatLocker returned no auth key in a JSON body for this organization. Check that the API user can view installation auth keys.' }],
          isError: true,
        };
      }
      return { content: [{ type: 'text', text: JSON.stringify(authKey, null, 2) }] };
    }
    case 'threatlocker_organizations_for_move_computers': {
      logger.info('API call: organizations.listForMoveComputers');
      const organizations = await client.organizations.listForMoveComputers();
      return { content: [{ type: 'text', text: JSON.stringify(organizations, null, 2) }] };
    }
    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${toolName}` }], isError: true };
  }
}

export const organizationsHandler: DomainHandler = { getTools, handleCall };