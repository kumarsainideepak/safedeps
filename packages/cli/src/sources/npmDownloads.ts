/**
 * npm Downloads API client
 *
 * Fetches weekly download counts from the npm downloads API.
 * Used as an authenticity signal in typosquat detection — a package with
 * high weekly downloads is very unlikely to be a typosquat.
 *
 * Endpoint: GET https://api.npmjs.org/downloads/point/last-week/<name>
 *   — Returns download stats for the last 7 days.
 *   — No API key required. No published rate limit.
 *   — Scoped packages must be percent-encoded (@scope%2Fname).
 */

import { USER_AGENT } from '../utils/constants';
import { fetchWithRetry } from '../utils/httpRetry';

const DOWNLOADS_BASE = 'https://api.npmjs.org';
const TIMEOUT_MS     = 6_000;

export interface NpmDownloadStats {
  weeklyDownloads: number | null;
  /** true = 200 OK, false = 404 (not on npm), null = network error */
  existsOnNpm: boolean | null;
}

/**
 * Fetches the number of downloads in the last 7 days for a package.
 * Also indicates whether the package exists on npm at all.
 */
export async function fetchWeeklyDownloads(name: string): Promise<NpmDownloadStats> {
  const encoded = name.startsWith('@')
    ? '@' + encodeURIComponent(name.slice(1))
    : encodeURIComponent(name);

  const url = `${DOWNLOADS_BASE}/downloads/point/last-week/${encoded}`;

  try {
    const response = await fetchWithRetry(
      url,
      { headers: { Accept: 'application/json', 'User-Agent': USER_AGENT } },
      { timeoutMs: TIMEOUT_MS },
    );

    if (response.status === 404) return { weeklyDownloads: null, existsOnNpm: false };
    if (!response.ok)            return { weeklyDownloads: null, existsOnNpm: null };

    const data = await response.json() as Record<string, unknown>;
    const downloads = typeof data.downloads === 'number' ? data.downloads : null;
    return { weeklyDownloads: downloads, existsOnNpm: true };
  } catch {
    return { weeklyDownloads: null, existsOnNpm: null };
  }
}

/**
 * Batch-fetches weekly download stats for multiple packages with concurrency control.
 *
 * @returns Map of package name → NpmDownloadStats
 */
export async function batchFetchDownloads(
  names: string[],
  concurrency = 8,
): Promise<Map<string, NpmDownloadStats>> {
  const results = new Map<string, NpmDownloadStats>();

  for (let i = 0; i < names.length; i += concurrency) {
    const chunk   = names.slice(i, i + concurrency);
    const settled = await Promise.allSettled(chunk.map(n => fetchWeeklyDownloads(n)));

    for (let j = 0; j < chunk.length; j++) {
      const outcome = settled[j];
      results.set(
        chunk[j],
        outcome.status === 'fulfilled'
          ? outcome.value
          : { weeklyDownloads: null, existsOnNpm: null },
      );
    }
  }

  return results;
}
