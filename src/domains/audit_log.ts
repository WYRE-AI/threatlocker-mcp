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
      description:
        'Get one audit log entry by eActionLogId, the string id on a threatlocker_audit_search row. ' +
        'Optional sourceTableId (integer 1-4) selects that row\'s source table. ' +
        'actionLogId is a deprecated alias and is stringified into eActionLogId. A numeric id is rejected before the request.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          eActionLogId: {
            type: 'string',
            description:
              'eActionLogId from a threatlocker_audit_search row. ActionLogGetByIdV2 requires this string; the numeric actionLogId on the same row is a different field and returns HTTP 500.',
          },
          sourceTableId: {
            type: 'integer',
            minimum: 1,
            maximum: 4,
            description:
              'Optional source table of that row. ActionLog = 1, DenyActionLog = 2, BaselineActionLog = 3, EventLogActionLog = 4.',
          },
          actionLogId: {
            type: 'string',
            deprecated: true,
            description:
              'Deprecated alias for eActionLogId. Stringified and sent as eActionLogId when it is not numeric. A numeric actionLogId is rejected; use eActionLogId from the search row.',
          },
        },
        // One id is required. Existing callers send actionLogId; new callers send eActionLogId.
        anyOf: [{ required: ['eActionLogId'] }, { required: ['actionLogId'] }],
      },
    },
    {
      name: 'threatlocker_audit_file_history',
      description:
        'Get audit history for a file on one computer. fullPath is required, plus hostname or computerId (a GUID). The Portal file-history API returns HTTP 417 when only fullPath is sent.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          fullPath: { type: 'string', description: 'Full file path. Required.' },
          hostname: {
            type: 'string',
            description: 'Computer hostname. Required unless computerId is set.',
          },
          computerId: {
            type: 'string',
            description: 'Computer GUID (not a numeric id). Required unless hostname is set.',
          },
          sourceTableId: {
            type: 'number',
            description:
              'Optional source table. ActionLog = 1, DenyActionLog = 2, BaselineActionLog = 3, EventLogActionLog = 4.',
          },
          pageNumber: { type: 'number', description: 'Optional page number.' },
          pageSize: { type: 'number', description: 'Optional page size.' },
        },
        required: ['fullPath'],
        // `required` cannot express "hostname or computerId". anyOf requires
        // at least one identifier; both may be sent together.
        anyOf: [{ required: ['hostname'] }, { required: ['computerId'] }],
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
      // node-threatlocker@3.0.0 (WYREAI-386): get(id: string, { sourceTableId }?)
      // sends eActionLogId. The numeric actionLogId is V1 and HTTP 500s on V2.
      const resolved = auditGetArgs(args);
      if (!resolved.ok) {
        return {
          content: [{ type: 'text', text: resolved.message }],
          isError: true,
        };
      }
      const { eActionLogId, sourceTableId } = resolved;
      logger.info('API call: auditLog.get', { eActionLogId, sourceTableId });
      const auditEntry = await client.auditLog.get(eActionLogId, { sourceTableId });
      return { content: [{ type: 'text', text: JSON.stringify(auditEntry, null, 2) }] };
    }
    case 'threatlocker_audit_file_history': {
      // Object form from node-threatlocker#32 (WYREAI-386), published in
      // @wyre-ai/node-threatlocker@2.0.0. The string call
      // getFileHistory(fullPath) is the HTTP 417.
      const params = fileHistoryParams(args);
      if (!params) {
        return {
          content: [{ type: 'text', text: FILE_HISTORY_ARG_ERROR }],
          isError: true,
        };
      }
      logger.info('API call: auditLog.getFileHistory', params);
      const history = await client.auditLog.getFileHistory(params);
      return { content: [{ type: 'text', text: JSON.stringify(history, null, 2) }] };
    }
    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${toolName}` }], isError: true };
  }
}

const AUDIT_GET_ARG_ERROR =
  'threatlocker_audit_get requires eActionLogId, the string id on a threatlocker_audit_search row. ' +
  'actionLogId is accepted as a deprecated alias and is stringified into eActionLogId. ' +
  'The numeric actionLogId is not that id; ActionLogGetByIdV2 returns HTTP 500 for it.';

const SOURCE_TABLE_ID_ERROR =
  'threatlocker_audit_get sourceTableId must be an integer 1 (ActionLog), 2 (DenyActionLog), 3 (BaselineActionLog), or 4 (EventLogActionLog).';

const AUDIT_GET_NUMERIC_ID_ERROR =
  'threatlocker_audit_get got a numeric action log id. actionLogId is a deprecated alias and is stringified, ' +
  'but ActionLogGetByIdV2 does not accept the numeric actionLogId (that request is HTTP 500). ' +
  'Pass eActionLogId, the string id on the threatlocker_audit_search row.';

/** Digit-only ids are V1 actionLogId values. The SDK rejects them before the request. */
const NUMERIC_ACTION_LOG_ID = /^-?\d+$/;

type AuditGetSuccess = {
  ok: true;
  eActionLogId: string;
  sourceTableId?: 1 | 2 | 3 | 4;
};

type AuditGetFailure = { ok: false; message: string };

/**
 * Prefers eActionLogId. actionLogId is the deprecated alias and is stringified
 * (a numeric actionLogId becomes its decimal string) so older callers still reach get().
 */
function auditGetArgs(args: Record<string, unknown>): AuditGetSuccess | AuditGetFailure {
  const eActionLogId = nonEmptyString(args.eActionLogId) ?? stringifiedId(args.actionLogId);
  if (!eActionLogId) return { ok: false, message: AUDIT_GET_ARG_ERROR };
  if (NUMERIC_ACTION_LOG_ID.test(eActionLogId)) return { ok: false, message: AUDIT_GET_NUMERIC_ID_ERROR };

  if (args.sourceTableId == null) return { ok: true, eActionLogId };
  if (!isSourceTableId(args.sourceTableId)) return { ok: false, message: SOURCE_TABLE_ID_ERROR };
  return { ok: true, eActionLogId, sourceTableId: args.sourceTableId };
}

function stringifiedId(value: unknown): string | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return nonEmptyString(value);
}

function isSourceTableId(value: unknown): value is 1 | 2 | 3 | 4 {
  return value === 1 || value === 2 || value === 3 || value === 4;
}

const FILE_HISTORY_ARG_ERROR =
  'threatlocker_audit_file_history requires fullPath and either hostname or computerId. ' +
  'ActionLogGetAllForFileHistoryV2 returns HTTP 417 "Missing Parameters. Unable to load details." ' +
  'when only fullPath is sent.';

function nonEmptyString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Builds the object `auditLog.getFileHistory` expects.
 * Returns null when fullPath is blank or both computer identifiers are missing.
 */
function fileHistoryParams(args: Record<string, unknown>): Record<string, unknown> | null {
  const fullPath = nonEmptyString(args.fullPath);
  const hostname = nonEmptyString(args.hostname);
  const computerId = nonEmptyString(args.computerId);
  if (!fullPath || (!hostname && !computerId)) return null;

  const params: Record<string, unknown> = { fullPath };
  if (hostname) params.hostname = hostname;
  if (computerId) params.computerId = computerId;
  if (typeof args.sourceTableId === 'number') params.sourceTableId = args.sourceTableId;
  if (typeof args.pageNumber === 'number') params.pageNumber = args.pageNumber;
  if (typeof args.pageSize === 'number') params.pageSize = args.pageSize;
  return params;
}

export const auditLogHandler: DomainHandler = { getTools, handleCall };