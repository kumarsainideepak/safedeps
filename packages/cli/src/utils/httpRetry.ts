/**
 * HTTP fetch with retry, exponential backoff, and timeout.
 *
 * Retries on: network errors, 429, 503, 5xx responses.
 * Does NOT retry: 400, 401, 403, 404, or other 4xx.
 * Backoff: baseDelayMs × 2^attempt with ±25% jitter.
 * Respects Retry-After header on 429.
 */

export interface RetryOptions {
  maxRetries?:  number;   // default 2
  baseDelayMs?: number;   // default 500
  timeoutMs?:   number;   // default 10_000
}

function _shouldRetry(status: number): boolean {
  return status === 429 || status === 503 || (status >= 500 && status < 600);
}

function _backoffMs(attempt: number, baseDelayMs: number): number {
  const base  = baseDelayMs * Math.pow(2, attempt);
  const jitter = base * 0.25 * (Math.random() * 2 - 1);  // ±25%
  return Math.max(0, Math.round(base + jitter));
}

function _retryAfterMs(response: Response): number | null {
  const header = response.headers.get('retry-after');
  if (!header) return null;
  const seconds = parseFloat(header);
  if (!isNaN(seconds)) return Math.round(seconds * 1000);
  const date = new Date(header).getTime();
  if (!isNaN(date)) return Math.max(0, date - Date.now());
  return null;
}

function _sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch with retry + exponential backoff + per-attempt timeout.
 */
export async function fetchWithRetry(
  url: string,
  init: RequestInit,
  options: RetryOptions = {},
): Promise<Response> {
  const { maxRetries = 2, baseDelayMs = 500, timeoutMs = 10_000 } = options;

  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), timeoutMs);

    // Merge caller's signal with our timeout signal if present
    const signal = init.signal
      ? _mergeSignals(init.signal as AbortSignal, controller.signal)
      : controller.signal;

    let response: Response;
    try {
      response = await fetch(url, { ...init, signal });
      clearTimeout(timer);
    } catch (err) {
      clearTimeout(timer);
      lastError = err;
      // Network error or abort — retry unless this was the last attempt
      if (attempt < maxRetries) {
        await _sleep(_backoffMs(attempt, baseDelayMs));
        continue;
      }
      throw err;
    }

    // Success or a non-retryable error status — return immediately
    if (!_shouldRetry(response.status)) {
      return response;
    }

    // Retryable status
    if (attempt < maxRetries) {
      const retryAfter = _retryAfterMs(response);
      const delay      = retryAfter ?? _backoffMs(attempt, baseDelayMs);
      await _sleep(delay);
      continue;
    }

    // Exhausted retries — return the last response so caller can inspect status
    return response;
  }

  // Should never reach here, but TypeScript requires a return
  throw lastError ?? new Error(`fetchWithRetry: exhausted retries for ${url}`);
}

/** Combines two AbortSignals so either one aborting aborts the merged signal. */
function _mergeSignals(a: AbortSignal, b: AbortSignal): AbortSignal {
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  if (a.aborted || b.aborted) {
    controller.abort();
  } else {
    a.addEventListener('abort', onAbort, { once: true });
    b.addEventListener('abort', onAbort, { once: true });
  }
  return controller.signal;
}
