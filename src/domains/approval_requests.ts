import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { DomainHandler, CallToolResult } from '../utils/types.js';
import { getClient } from '../utils/client.js';
import { logger } from '../utils/logger.js';
import { elicitSelection } from '../utils/elicitation.js';

function getTools(): Tool[] {
  return [
    {
      name: 'threatlocker_approvals_list',
      description: 'List approval requests with optional filters.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          status: { type: 'string', description: 'Approval status filter' },
          pageNumber: { type: 'number', description: 'Page number (default 1)' },
          pageSize: { type: 'number', description: 'Page size (default 50)' },
          searchText: { type: 'string', description: 'Search text filter' },
          childOrganizations: { type: 'boolean', description: 'Include child organizations' },
        },
      },
    },
    {
      name: 'threatlocker_approvals_get',
      description: 'Get a single approval request by ID.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          approvalRequestId: { type: 'string', description: 'Approval request ID' },
        },
        required: ['approvalRequestId'],
      },
    },
    {
      name: 'threatlocker_approvals_pending_count',
      description: 'Get count of pending approval requests.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
      },
    },
    {
      name: 'threatlocker_approvals_get_permit_application',
      description: 'Get permit application details for an approval request.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          approvalRequestId: { type: 'string', description: 'Approval request ID' },
        },
        required: ['approvalRequestId'],
      },
    },
  ];
}

async function handleCall(toolName: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const client = await getClient();

  switch (toolName) {
    case 'threatlocker_approvals_list': {
      // Elicitation: if no status filter provided, ask for status preference
      let status = args.status as string | undefined;
      if (!status) {
        const elicited = await elicitSelection(
          'Select approval request status:',
          ['Pending', 'Approved', 'Denied', 'All'],
          'Pending'
        );
        status = elicited || 'Pending';
      }

      const params = {
        status: status === 'All' ? undefined : status,
        pageNumber: args.pageNumber as number | undefined,
        pageSize: args.pageSize as number | undefined,
        searchText: args.searchText as string | undefined,
        childOrganizations: args.childOrganizations as boolean | undefined,
      };
      logger.info('API call: approvalRequests.list', params);
      const result = await client.approvalRequests.list(params);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case 'threatlocker_approvals_get': {
      const approvalRequestId = args.approvalRequestId as string;
      logger.info('API call: approvalRequests.get', { approvalRequestId });
      const approval = await client.approvalRequests.get(approvalRequestId);
      return { content: [{ type: 'text', text: JSON.stringify(approval, null, 2) }] };
    }
    case 'threatlocker_approvals_pending_count': {
      logger.info('API call: approvalRequests.getPendingCount');
      const count = await client.approvalRequests.getPendingCount();
      return { content: [{ type: 'text', text: JSON.stringify(count, null, 2) }] };
    }
    case 'threatlocker_approvals_get_permit_application': {
      const approvalRequestId = args.approvalRequestId as string;
      logger.info('API call: approvalRequests.getPermitApplication', { approvalRequestId });
      const permitApp = await client.approvalRequests.getPermitApplication(approvalRequestId);
      return { content: [{ type: 'text', text: JSON.stringify(permitApp, null, 2) }] };
    }
    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${toolName}` }], isError: true };
  }
}

export const approvalRequestsHandler: DomainHandler = { getTools, handleCall };