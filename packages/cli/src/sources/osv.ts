import type { OsvVuln } from '../utils/severity';
import { USER_AGENT } from '../utils/constants';
import { fetchWithRetry } from '../utils/httpRetry';

/**
 * OSV.dev API client
 *
 * OSV (Open Source Vulnerabilities) is Google's free, public vulnerability
 * database covering npm, PyPI, RubyGems, Go, Rust, Maven, and more.
 *
 * Key endpoint: POST https://api.osv.dev/v1/querybatch
 *   — Batch query: up to 1,000 packages in one HTTP request
 *
 * Rate limits (unauthenticated): 1,000 requests/day
 * We use /querybatch so one request covers ALL packages → very efficient
 *
 * No API key required.
 */

const OSV_BATCH_URL  = 'https://api.osv.dev/v1/querybatch';
const OSV_VULNS_URL  = 'https://api.osv.dev/v1/vulns';

/** Maximum packages per batch request (OSV limit) */
const BATCH_SIZE = 1000;

/** Maximum concurrent individual vuln-detail fetches */
const VULN_DETAIL_CONCURRENCY = 10;

/** Request timeout in milliseconds */
const TIMEOUT_MS = 15000;

export interface OsvPackage {
  name: string;
  version: string;
}

export interface OsvResult {
  name: string;
  version: string;
  vulns: OsvVuln[];
}

interface OsvBatchResponse {
  results?: Array<{ vulns?: OsvVuln[] }>;
}

/**
 * Queries OSV.dev for vulnerabilities across multiple npm packages.
 *
 * Two-phase strategy:
 *   Phase 1 — /v1/querybatch: single POST to map packages → vuln IDs.
 *             The batch endpoint returns only { id, modified } per vuln.
 *   Phase 2 — /v1/vulns/{id}: fetch full details (severity, aliases, affected
 *             ranges, CVSS vectors, etc.) for each unique vuln ID found.
 *             Unique IDs are de-duplicated so shared advisories are fetched once.
 *
 * Automatically splits into multiple batch requests if > 1000 packages.
 */
export async function queryOSV(packages: OsvPackage[]): Promise<OsvResult[]> {
  if (!packages || packages.length === 0) return [];

  const results: OsvResult[] = [];

  // Phase 1: querybatch — one request per BATCH_SIZE packages
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE);
    const batchResults = await _querySingleBatch(batch);
    results.push(...batchResults);
  }

  // Phase 2: fetch full vuln details for every unique ID discovered
  const vulnIds = new Set<string>();
  for (const result of results) {
    for (const v of result.vulns) {
      if (v.id) vulnIds.add(v.id);
    }
  }

  const vulnDetailsMap = new Map<string, OsvVuln>();
  await _withConcurrency([...vulnIds], VULN_DETAIL_CONCURRENCY, async (id) => {
    try {
      const details = await _fetchVulnDetails(id);
      vulnDetailsMap.set(id, details);
    } catch {
      // If individual fetch fails, keep the minimal stub (id + modified only)
    }
  });

  // Replace minimal stubs with full detail objects
  for (const result of results) {
    result.vulns = result.vulns.map(v => (v.id ? vulnDetailsMap.get(v.id) : undefined) ?? v);
  }

  return results;
}

/** Fetches full vulnerability details for a single OSV advisory ID. */
async function _fetchVulnDetails(id: string): Promise<OsvVuln> {
  const response = await fetchWithRetry(
    `${OSV_VULNS_URL}/${encodeURIComponent(id)}`,
    { method: 'GET', headers: { 'User-Agent': USER_AGENT } },
    { timeoutMs: TIMEOUT_MS },
  );
  if (!response.ok) throw new Error(`OSV vuln detail HTTP ${response.status} for ${id}`);
  return response.json() as Promise<OsvVuln>;
}

/** Runs `fn` over `items` with at most `concurrency` items in flight at once. */
async function _withConcurrency<T>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  for (let i = 0; i < items.length; i += concurrency) {
    await Promise.allSettled(items.slice(i, i + concurrency).map(fn));
  }
}

async function _querySingleBatch(packages: OsvPackage[]): Promise<OsvResult[]> {
  // Build OSV query payload
  // Each query targets a specific package + version in the npm ecosystem
  const queries = packages.map(pkg => ({
    version: pkg.version,
    package: {
      name:      pkg.name,
      ecosystem: 'npm',
    },
  }));

  const body = JSON.stringify({ queries });

  let response: Response;
  try {
    response = await fetchWithRetry(
      OSV_BATCH_URL,
      {
        method:  'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent':   USER_AGENT,
        },
        body,
      },
      { timeoutMs: TIMEOUT_MS },
    );
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      throw new Error(`OSV.dev API timed out after ${TIMEOUT_MS}ms`);
    }
    throw new Error(`OSV.dev API network error: ${(err as Error).message}`);
  }

  if (!response.ok) {
    throw new Error(`OSV.dev API returned HTTP ${response.status}`);
  }

  const data = await response.json() as OsvBatchResponse;

  // OSV returns results in the same order as the queries array
  return packages.map((pkg, idx) => ({
    name:    pkg.name,
    version: pkg.version,
    vulns:   data.results?.[idx]?.vulns ?? [],
  }));
}
