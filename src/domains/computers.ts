import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { DomainHandler, CallToolResult } from '../utils/types.js';
import { getClient } from '../utils/client.js';
import { logger } from '../utils/logger.js';
import { elicitText } from '../utils/elicitation.js';

function getTools(): Tool[] {
  return [
    {
      name: 'threatlocker_computers_list',
      description: 'List ThreatLocker computers with optional filters.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          searchText: { type: 'string', description: 'Search text filter' },
          computerGroup: { type: 'string', description: 'Computer group filter' },
          pageNumber: { type: 'number', description: 'Page number (default 1)' },
          pageSize: { type: 'number', description: 'Page size (default 50)' },
          childOrganizations: { type: 'boolean', description: 'Include child organizations' },
        },
      },
    },
    {
      name: 'threatlocker_computers_get',
      description: 'Get a single computer by ID.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          computerId: { type: 'string', description: 'Computer ID' },
        },
        required: ['computerId'],
      },
    },
    {
      name: 'threatlocker_computers_get_checkins',
      description: 'Get checkin history for a computer.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          computerId: { type: 'string', description: 'Computer ID' },
          pageNumber: { type: 'number', description: 'Page number (default 1)' },
          pageSize: { type: 'number', description: 'Page size (default 50)' },
        },
        required: ['computerId'],
      },
    },
  ];
}

async function handleCall(toolName: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const client = await getClient();

  switch (toolName) {
    case 'threatlocker_computers_list': {
      // Elicitation: if no filters provided, ask for search term
      let searchText = args.searchText as string | undefined;
      if (!searchText && !args.computerGroup) {
        const elicited = await elicitText('Enter search term for computers (or press Enter to list all):');
        searchText = elicited || undefined;
      }

      const params = {
        searchText,
        computerGroup: args.computerGroup as string | undefined,
        pageNumber: args.pageNumber as number | undefined,
        pageSize: args.pageSize as number | undefined,
        childOrganizations: args.childOrganizations as boolean | undefined,
      };
      logger.info('API call: computers.list', params);
      const result = await client.computers.list(params);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case 'threatlocker_computers_get': {
      const computerId = args.computerId as string;
      logger.info('API call: computers.get', { computerId });
      const computer = await client.computers.get(computerId);
      return { content: [{ type: 'text', text: JSON.stringify(computer, null, 2) }] };
    }
    case 'threatlocker_computers_get_checkins': {
      const params = {
        computerId: args.computerId as string,
        pageNumber: args.pageNumber as number | undefined,
        pageSize: args.pageSize as number | undefined,
      };
      logger.info('API call: computers.getCheckins', params);
      // getCheckins takes a single params object (computerId + pagination),
      // not (computerId, paginationObject) — the previous two-argument call
      // silently dropped computerId, causing the API to reject the request.
      const checkins = await client.computers.getCheckins(params);
      return { content: [{ type: 'text', text: JSON.stringify(checkins, null, 2) }] };
    }
    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${toolName}` }], isError: true };
  }
}

export const computersHandler: DomainHandler = { getTools, handleCall };