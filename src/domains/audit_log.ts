import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { DomainHandler, CallToolResult } from '../utils/types.js';
import { getClient } from '../utils/client.js';
import { logger } from '../utils/logger.js';
import { elicitSelection } from '../utils/elicitation.js';

function getTools(): Tool[] {
  return [
    {
      name: 'threatlocker_audit_search',
      description:
        'Search audit log entries with optional filters. Each row includes eActionLogId and organizationId when the ' +
        'upstream search returns them. sourceTableId (1-4) is included when present or under a known alias ' +
        '(SourceTableId, sourceTable, SourceTable). Pass those three fields to threatlocker_audit_get. ' +
        'If a row has no sourceTableId, audit_get will probe tables 1-4.',
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
        'Pass eActionLogId, sourceTableId and organizationId from the same search row when present: sourceTableId selects the row\'s source table (integer 1-4) ' +
        'and organizationId scopes the lookup to the org that owns the row (required for rows from child organizations). ' +
        'If sourceTableId is omitted, the tool probes ActionLogGetByIdV2 with tables 1-4 and returns the first success. ' +
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
          organizationId: {
            type: 'string',
            description:
              'organizationId from the threatlocker_audit_search row; scopes the lookup to the org that owns the row (required for rows from child organizations).',
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
      const normalized = normalizeAuditSearchResult(result);
      return { content: [{ type: 'text', text: JSON.stringify(normalized, null, 2) }] };
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
      const { eActionLogId, sourceTableId, organizationId } = resolved;
      logger.info('API call: auditLog.get', { eActionLogId, sourceTableId, organizationId });
      // SDK 3.0.2 sends organizationId as the ManagedOrganizationId header
      // to scope the lookup to the organization that owns the audit row.
      const getOptions: { sourceTableId?: 1 | 2 | 3 | 4; organizationId?: string } = {};
      if (sourceTableId !== undefined) getOptions.sourceTableId = sourceTableId;
      if (organizationId !== undefined) getOptions.organizationId = organizationId;
      try {
        const auditEntry = await getAuditEntry(client, eActionLogId, getOptions);
        return { content: [{ type: 'text', text: JSON.stringify(auditEntry, null, 2) }] };
      } catch (error) {
        if (!isHttp500(error)) throw error;
        const probed = sourceTableId === undefined ? SOURCE_TABLE_IDS : undefined;
        return {
          content: [{ type: 'text', text: auditGet500Message(eActionLogId, sourceTableId, organizationId, probed) }],
          isError: true,
        };
      }
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

/** Official GetByIdV2 source-table ids. Used to probe when search omits sourceTableId. */
export const SOURCE_TABLE_IDS = [1, 2, 3, 4] as const;

const SOURCE_TABLE_ID_ALIASES = [
  'sourceTableId',
  'SourceTableId',
  'sourceTable',
  'SourceTable',
  'eSourceTableId',
] as const;

const ORGANIZATION_ID_ALIASES = ['organizationId', 'OrganizationId', 'orgId'] as const;

/**
 * Map a search-row alias onto sourceTableId 1-4. Official
 * ActionLogGetByParametersV2 docs do not list sourceTableId as a response
 * field; some payloads still carry it under a PascalCase or shortened name.
 * Returns undefined when nothing coerceable is present — never invents a table.
 */
export function coerceSourceTableId(value: unknown): 1 | 2 | 3 | 4 | undefined {
  if (typeof value === 'number' && isSourceTableId(value)) return value;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^[1-4]$/.test(trimmed)) return Number(trimmed) as 1 | 2 | 3 | 4;
    const named: Record<string, 1 | 2 | 3 | 4> = {
      actionlog: 1,
      denyactionlog: 2,
      deny: 2,
      baselineactionlog: 3,
      baseline: 3,
      eventlogactionlog: 4,
      eventlog: 4,
    };
    return named[trimmed.toLowerCase()];
  }
  return undefined;
}

export function normalizeAuditRow(row: unknown): unknown {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return row;
  const rec = row as Record<string, unknown>;
  const sourceTableId =
    coerceSourceTableId(rec.sourceTableId) ??
    SOURCE_TABLE_ID_ALIASES.reduce<1 | 2 | 3 | 4 | undefined>(
      (found, key) => found ?? coerceSourceTableId(rec[key]),
      undefined,
    );
  const organizationId = ORGANIZATION_ID_ALIASES.map((key) => nonEmptyString(rec[key])).find(Boolean);
  return {
    ...rec,
    ...(sourceTableId !== undefined ? { sourceTableId } : {}),
    ...(organizationId !== undefined ? { organizationId } : {}),
  };
}

export function normalizeAuditSearchResult(result: unknown): unknown {
  if (Array.isArray(result)) return result.map(normalizeAuditRow);
  if (!result || typeof result !== 'object') return result;
  const rec = result as Record<string, unknown>;
  const copy: Record<string, unknown> = { ...rec };
  for (const key of ['items', 'data', 'logs', 'results']) {
    if (Array.isArray(copy[key])) copy[key] = (copy[key] as unknown[]).map(normalizeAuditRow);
  }
  return copy;
}

type AuditGetClient = {
  auditLog: {
    get: (
      id: string,
      options?: { sourceTableId?: 1 | 2 | 3 | 4; organizationId?: string },
    ) => Promise<unknown>;
  };
};

/**
 * When sourceTableId is already known, call get() once.
 * When it is omitted (search often does not return it), probe tables 1-4
 * and return the first success. A non-500 error is not retried against
 * another table.
 */
async function getAuditEntry(
  client: AuditGetClient,
  eActionLogId: string,
  options: { sourceTableId?: 1 | 2 | 3 | 4; organizationId?: string },
): Promise<unknown> {
  if (options.sourceTableId !== undefined) {
    return client.auditLog.get(eActionLogId, options);
  }
  let lastError: unknown;
  for (const sourceTableId of SOURCE_TABLE_IDS) {
    try {
      logger.info('API call: auditLog.get probe', { eActionLogId, sourceTableId, organizationId: options.organizationId });
      return await client.auditLog.get(eActionLogId, { ...options, sourceTableId });
    } catch (error) {
      if (!isHttp500(error)) throw error;
      lastError = error;
    }
  }
  throw lastError ?? new Error('Server error: 500');
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
  organizationId?: string;
};

const ORGANIZATION_ID_ERROR =
  'threatlocker_audit_get organizationId must be a non-empty string (the organizationId on the threatlocker_audit_search row).';

function isHttp500(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const { message, statusCode } = error as { message?: unknown; statusCode?: unknown };
  return statusCode === 500 || (typeof message === 'string' && message.startsWith('Server error: 500'));
}

function auditGet500Message(
  eActionLogId: string,
  sourceTableId: number | undefined,
  organizationId: string | undefined,
  probedTables?: readonly number[],
): string {
  const missing = [
    sourceTableId === undefined ? 'sourceTableId' : null,
    organizationId === undefined ? 'organizationId' : null,
  ].filter(Boolean);
  const missingNote = missing.length
    ? `Missing from this call: ${missing.join(', ')}.`
    : 'sourceTableId and organizationId were both provided.';
  const probeNote = probedTables?.length
    ? ` Already probed ActionLogGetByIdV2 with sourceTableId ${probedTables.join(', ')}.`
    : '';
  return (
    `ThreatLocker returned HTTP 500 for eActionLogId ${eActionLogId}. ` +
    'This usually means the id is stale/out of retention, or the lookup ran without the row\'s organization scope or source table. ' +
    `${missingNote}${probeNote} ` +
    'Re-run threatlocker_audit_search and pass eActionLogId, sourceTableId and organizationId from the same row when they are present. ' +
    'Do not retry the same arguments unchanged.'
  );
}

type AuditGetFailure = { ok: false; message: string };

/**
 * Prefers eActionLogId. actionLogId is the deprecated alias and is stringified
 * (a numeric actionLogId becomes its decimal string) so older callers still reach get().
 */
function auditGetArgs(args: Record<string, unknown>): AuditGetSuccess | AuditGetFailure {
  const eActionLogId = nonEmptyString(args.eActionLogId) ?? stringifiedId(args.actionLogId);
  if (!eActionLogId) return { ok: false, message: AUDIT_GET_ARG_ERROR };
  if (NUMERIC_ACTION_LOG_ID.test(eActionLogId)) return { ok: false, message: AUDIT_GET_NUMERIC_ID_ERROR };

  const result: AuditGetSuccess = { ok: true, eActionLogId };

  if (args.organizationId != null) {
    const organizationId = nonEmptyString(args.organizationId);
    if (!organizationId) return { ok: false, message: ORGANIZATION_ID_ERROR };
    result.organizationId = organizationId;
  }

  if (args.sourceTableId != null) {
    // Models often send "1".."4" as strings.
    const raw = args.sourceTableId;
    const sourceTableId = typeof raw === 'string' && /^[1-4]$/.test(raw.trim()) ? Number(raw.trim()) : raw;
    if (!isSourceTableId(sourceTableId)) return { ok: false, message: SOURCE_TABLE_ID_ERROR };
    result.sourceTableId = sourceTableId;
  }
  return result;
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