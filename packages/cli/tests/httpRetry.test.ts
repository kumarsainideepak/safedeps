import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fetchWithRetry } from '../src/utils/httpRetry';

/**
 * httpRetry tests — no real network calls.
 * We override the global `fetch` per test via a local mock.
 */

type FetchMock = (url: string, init: RequestInit) => Promise<Response>;

function withMockFetch(mock: FetchMock, fn: () => Promise<void>): Promise<void> {
  const original = global.fetch;
  (global as Record<string, unknown>).fetch = mock;
  return fn().finally(() => {
    (global as Record<string, unknown>).fetch = original;
  });
}

function makeResponse(status: number, body = '{}'): Response {
  return new Response(body, { status });
}

describe('fetchWithRetry()', () => {

  it('returns response immediately on 200', async () => {
    let callCount = 0;
    await withMockFetch(async (_url, _init) => {
      callCount++;
      return makeResponse(200);
    }, async () => {
      const res = await fetchWithRetry('http://example.com', {}, { maxRetries: 2 });
      assert.equal(res.status, 200);
      assert.equal(callCount, 1);
    });
  });

  it('does NOT retry on 404', async () => {
    let callCount = 0;
    await withMockFetch(async () => {
      callCount++;
      return makeResponse(404);
    }, async () => {
      const res = await fetchWithRetry('http://example.com', {}, { maxRetries: 2, baseDelayMs: 1 });
      assert.equal(res.status, 404);
      assert.equal(callCount, 1, 'should not retry 404');
    });
  });

  it('retries on 503 up to maxRetries then returns last response', async () => {
    let callCount = 0;
    await withMockFetch(async () => {
      callCount++;
      return makeResponse(503);
    }, async () => {
      const res = await fetchWithRetry('http://example.com', {}, { maxRetries: 2, baseDelayMs: 1 });
      assert.equal(res.status, 503);
      assert.equal(callCount, 3, 'initial attempt + 2 retries = 3 total');
    });
  });

  it('retries on 429 up to maxRetries then returns last response', async () => {
    let callCount = 0;
    await withMockFetch(async () => {
      callCount++;
      return makeResponse(429);
    }, async () => {
      const res = await fetchWithRetry('http://example.com', {}, { maxRetries: 1, baseDelayMs: 1 });
      assert.equal(res.status, 429);
      assert.equal(callCount, 2, 'initial attempt + 1 retry = 2 total');
    });
  });

  it('succeeds on retry after initial failure', async () => {
    let callCount = 0;
    await withMockFetch(async () => {
      callCount++;
      return makeResponse(callCount === 1 ? 503 : 200);
    }, async () => {
      const res = await fetchWithRetry('http://example.com', {}, { maxRetries: 2, baseDelayMs: 1 });
      assert.equal(res.status, 200);
      assert.equal(callCount, 2);
    });
  });

  it('throws on network error after exhausting retries', async () => {
    let callCount = 0;
    await withMockFetch(async () => {
      callCount++;
      throw new Error('ECONNREFUSED');
    }, async () => {
      await assert.rejects(
        () => fetchWithRetry('http://example.com', {}, { maxRetries: 1, baseDelayMs: 1 }),
        /ECONNREFUSED/,
      );
      assert.equal(callCount, 2);
    });
  });

  it('times out after timeoutMs and throws', async () => {
    await withMockFetch(async (_url, init) => {
      // Wait until the signal aborts
      await new Promise<void>((resolve, reject) => {
        const signal = (init as RequestInit & { signal?: AbortSignal }).signal;
        if (signal?.aborted) {
          reject(Object.assign(new Error('AbortError'), { name: 'AbortError' }));
          return;
        }
        signal?.addEventListener('abort', () => {
          reject(Object.assign(new Error('AbortError'), { name: 'AbortError' }));
        });
        // Don't resolve — simulates a hung connection
      });
      return makeResponse(200);  // unreachable
    }, async () => {
      await assert.rejects(
        () => fetchWithRetry('http://example.com', {}, { maxRetries: 0, timeoutMs: 20 }),
      );
    });
  });

});
