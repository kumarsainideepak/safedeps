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

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';

/** Maximum packages per batch request (OSV limit) */
const BATCH_SIZE = 1000;

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
 * Automatically splits into multiple batch requests if > 1000 packages.
 */
export async function queryOSV(packages: OsvPackage[]): Promise<OsvResult[]> {
  if (!packages || packages.length === 0) return [];

  const results: OsvResult[] = [];

  // Split into batches of BATCH_SIZE
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE);
    const batchResults = await _querySingleBatch(batch);
    results.push(...batchResults);
  }

  return results;
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
