import { describe, it, expect } from 'vitest';
import { toolErrorResult } from '../utils/tool-error.js';

/** Same shape as node-threatlocker's RateLimitError (statusCode 429, retryAfter in seconds). */
function rateLimitError(message: string, retryAfter: number): Error {
  return Object.assign(new Error(message), { statusCode: 429, retryAfter, response: {} });
}

describe('toolErrorResult', () => {
  it('puts retry_after_seconds on a rate-limit error, matching the message', () => {
    const error = rateLimitError(
      'ThreatLocker rate-limited the request (HTTP 429) for /Computer. Try again in 7 s.',
      7,
    );

    const result = toolErrorResult(error);

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(
      'Error: ThreatLocker rate-limited the request (HTTP 429) for /Computer. Try again in 7 s.',
    );
    expect(result.structuredContent).toEqual({ error_type: 'rate_limited', retry_after_seconds: 7 });
  });

  it('clamps the field to at least 1', () => {
    const error = Object.assign(new Error('HTTP 429'), { statusCode: 429, retryAfter: 0 });
    expect(toolErrorResult(error).structuredContent?.retry_after_seconds).toBe(1);
  });

  it('leaves other errors as plain text', () => {
    const result = toolErrorResult(Object.assign(new Error('Server error: 500 for /Thing'), { statusCode: 500 }));
    expect(result).toEqual({ content: [{ type: 'text', text: 'Error: Server error: 500 for /Thing' }], isError: true });
    expect(toolErrorResult('boom').content[0].text).toBe('Error: boom');
  });
});
