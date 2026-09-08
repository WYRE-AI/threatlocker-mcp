import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { DomainHandler, CallToolResult } from '../utils/types.js';
import { getClient } from '../utils/client.js';
import { logger } from '../utils/logger.js';
import { elicitSelection } from '../utils/elicitation.js';

function getTools(): Tool[] {
  return [
    {
      name: 'threatlocker_audit_search',
      description: 'Search audit log entries with optional filters.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          searchText: { type: 'string', description: 'Search text filter' },
          startDate: { type: 'string', description: 'Start date filter (ISO 8601)' },
          endDate: { type: 'string', description: 'End date filter (ISO 8601)' },
          pageNumber: { type: 'number', description: 'Page number (default 1)' },
          pageSize: { type: 'number', description: 'Page size (default 50)' },
          childOrganizations: { type: 'boolean', description: 'Include child organizations' },
        },
      },
    },
    {
      name: 'threatlocker_audit_get',
      description: 'Get a single audit log entry by ID.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          actionLogId: { type: 'string', description: 'Action log ID' },
        },
        required: ['actionLogId'],
      },
    },
    {
      name: 'threatlocker_audit_file_history',
      description: 'Get audit history for a specific file path.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          fullPath: { type: 'string', description: 'Full file path' },
        },
        required: ['fullPath'],
      },
    },
  ];
}

async function handleCall(toolName: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const client = await getClient();

  switch (toolName) {
    case 'threatlocker_audit_search': {
      // Elicitation: if no searchText AND no date range, elicit date range
      const hasSearchText = !!args.searchText;
      const hasDateRange = !!(args.startDate || args.endDate);

      let startDate = args.startDate as string | undefined;
      let endDate = args.endDate as string | undefined;

      if (!hasSearchText && !hasDateRange) {
        const dateChoice = await elicitSelection(
          'Select audit log date range:',
          ['Last 24h', 'Last 7d', 'Last 30d', 'Custom'],
          'Last 24h'
        );

        const now = new Date();
        if (dateChoice === 'Last 24h') {
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
          endDate = now.toISOString();
        } else if (dateChoice === 'Last 7d') {
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
          endDate = now.toISOString();
        } else if (dateChoice === 'Last 30d') {
          startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
          endDate = now.toISOString();
        }
        // For 'Custom', leave dates undefined to prompt user to specify
      }

      const params = {
        searchText: args.searchText as string | undefined,
        startDate,
        endDate,
        pageNumber: args.pageNumber as number | undefined,
        pageSize: args.pageSize as number | undefined,
        childOrganizations: args.childOrganizations as boolean | undefined,
      };
      logger.info('API call: auditLog.search', params);
      const result = await client.auditLog.search(params);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case 'threatlocker_audit_get': {
      const actionLogId = args.actionLogId as string;
      logger.info('API call: auditLog.get', { actionLogId });
      const auditEntry = await client.auditLog.get(actionLogId);
      return { content: [{ type: 'text', text: JSON.stringify(auditEntry, null, 2) }] };
    }
    case 'threatlocker_audit_file_history': {
      const fullPath = args.fullPath as string;
      logger.info('API call: auditLog.getFileHistory', { fullPath });
      const history = await client.auditLog.getFileHistory(fullPath);
      return { content: [{ type: 'text', text: JSON.stringify(history, null, 2) }] };
    }
    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${toolName}` }], isError: true };
  }
}

export const auditLogHandler: DomainHandler = { getTools, handleCall };