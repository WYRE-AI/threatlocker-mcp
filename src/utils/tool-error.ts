/**
 * The MCP result for a tool call that threw.
 *
 * A ThreatLocker rate limit (node-threatlocker's `RateLimitError`: HTTP 429,
 * `retryAfter` in seconds) also carries the wait as a field, so clients can
 * key off `retry_after_seconds` instead of parsing the message. N is the
 * error's `retryAfter`, at least 1. Duck-typed so it does not depend on the
 * error class identity across package versions.
 */
export function toolErrorResult(error: unknown): {
  content: Array<{ type: 'text'; text: string }>;
  isError: true;
  structuredContent?: { error_type: 'rate_limited'; retry_after_seconds: number };
} {
  const message = error instanceof Error ? error.message : String(error);
  const result = { content: [{ type: 'text' as const, text: `Error: ${message}` }], isError: true as const };
  const e = error as { statusCode?: unknown; retryAfter?: unknown } | null;
  if (e && typeof e === 'object' && e.statusCode === 429 && typeof e.retryAfter === 'number' && Number.isFinite(e.retryAfter)) {
    return {
      ...result,
      structuredContent: { error_type: 'rate_limited', retry_after_seconds: Math.max(1, Math.ceil(e.retryAfter)) },
    };
  }
  return result;
}
