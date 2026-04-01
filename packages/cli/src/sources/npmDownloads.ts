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

const DOWNLOADS_BASE = 'https://api.npmjs.org';
const TIMEOUT_MS     = 6_000;

export interface NpmDownloadStats {
  weeklyDownloads: number | null;
}

/**
 * Fetches the number of downloads in the last 7 days for a package.
 * Returns `null` on network error or if the package has no recorded downloads.
 */
export async function fetchWeeklyDownloads(name: string): Promise<NpmDownloadStats> {
  const encoded = name.startsWith('@')
    ? '@' + encodeURIComponent(name.slice(1))
    : encodeURIComponent(name);

  const url = `${DOWNLOADS_BASE}/downloads/point/last-week/${encoded}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      headers: { Accept: 'application/json', 'User-Agent': USER_AGENT },
      signal:  controller.signal,
    });
    clearTimeout(timer);

    if (!response.ok) return { weeklyDownloads: null };

    const data = await response.json() as Record<string, unknown>;
    const downloads = typeof data.downloads === 'number' ? data.downloads : null;
    return { weeklyDownloads: downloads };
  } catch {
    clearTimeout(timer);
    return { weeklyDownloads: null };
  }
}

/**
 * Batch-fetches weekly download stats for multiple packages with concurrency control.
 *
 * @returns Map of package name → weekly download count (null on error)
 */
export async function batchFetchDownloads(
  names: string[],
  concurrency = 8,
): Promise<Map<string, number | null>> {
  const results = new Map<string, number | null>();

  for (let i = 0; i < names.length; i += concurrency) {
    const chunk   = names.slice(i, i + concurrency);
    const settled = await Promise.allSettled(chunk.map(n => fetchWeeklyDownloads(n)));

    for (let j = 0; j < chunk.length; j++) {
      const outcome = settled[j];
      results.set(
        chunk[j],
        outcome.status === 'fulfilled' ? outcome.value.weeklyDownloads : null,
      );
    }
  }

  return results;
}
