import path from 'path';
import fs from 'fs';
import { Command } from 'commander';
import { fetchWithRetry } from '../utils/httpRetry';
import { USER_AGENT } from '../utils/constants';

const SEARCH_URL    = 'https://registry.npmjs.org/-/v1/search';
const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week';
const PAGE_SIZE     = 250;

/** Weekly download threshold — packages below this are excluded from the list.
 *  Filters out low-quality packages like typosquats themselves (e.g. retux: 37/week). */
const MIN_WEEKLY_DOWNLOADS = 1_000;

/** Max unscoped packages per npm downloads bulk request (URL length limit). */
const UNSCOPED_BATCH_SIZE = 100;

/** Max concurrent download-count fetches for scoped packages (no bulk API). */
const SCOPED_CONCURRENCY = 10;

/** Delay between npm search requests to avoid rate-limiting (HTTP 429). */
const SEARCH_REQUEST_DELAY_MS = 400;

/**
 * Broad search terms that supplement the existing package list with newly
 * popular packages. Each term returns up to 250 search results.
 * The current list is always included as seeds regardless of search results.
 */
const SEARCH_TERMS = [
  'react', 'vue', 'angular', 'svelte',
  'typescript', 'javascript', 'node',
  'webpack', 'vite', 'rollup', 'esbuild',
  'express', 'fastify', 'koa', 'nest',
  'jest', 'vitest', 'mocha', 'chai',
  'lodash', 'axios', 'moment', 'dayjs',
  'babel', 'eslint', 'prettier',
  'next', 'nuxt', 'gatsby', 'remix',
  'cli', 'util', 'http', 'async', 'json',
  'database', 'mongodb', 'redis', 'postgres',
  'test', 'lint', 'build', 'deploy',
  'socket', 'crypto', 'auth', 'jwt',
  'graphql', 'prisma', 'sequelize',
  'zod', 'yup', 'validator',
];

interface NpmSearchResult {
  package: { name: string };
}

interface NpmSearchResponse {
  objects?: NpmSearchResult[];
}

function _sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Fetches one page of npm search results for a given text term. */
async function _fetchPage(term: string, from: number): Promise<string[]> {
  const url = `${SEARCH_URL}?text=${encodeURIComponent(term)}&size=${PAGE_SIZE}&from=${from}`;
  try {
    const response = await fetchWithRetry(
      url,
      { headers: { Accept: 'application/json', 'User-Agent': USER_AGENT } },
      { timeoutMs: 15_000 },
    );
    if (!response.ok) return [];
    const data = await response.json() as NpmSearchResponse;
    return (data.objects ?? []).map(o => o.package.name);
  } catch {
    return [];
  }
}

/**
 * Runs `fn` over `items` with at most `concurrency` items in-flight at once.
 */
async function _withConcurrency<T>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  for (let i = 0; i < items.length; i += concurrency) {
    await Promise.allSettled(items.slice(i, i + concurrency).map(fn));
  }
}

/**
 * Collects candidate package names using two sources:
 *
 *   1. Seed list — the current top-packages.json (ensures well-known packages
 *      like lodash, redis, express are always candidates regardless of search).
 *   2. npm search — one page per search term, with a delay between requests to
 *      avoid the registry's rate limit (HTTP 429 after ~8 rapid requests).
 */
async function _collectCandidates(
  seedList: string[],
  onSearchProgress: (term: string, found: number, total: number) => void,
): Promise<string[]> {
  const candidates = new Set<string>(seedList);

  for (let i = 0; i < SEARCH_TERMS.length; i++) {
    const term = SEARCH_TERMS[i];
    onSearchProgress(term, i + 1, SEARCH_TERMS.length);
    const names = await _fetchPage(term, 0);
    names.forEach(n => candidates.add(n));
    // Delay between requests to avoid hitting the registry rate limit
    if (i < SEARCH_TERMS.length - 1) await _sleep(SEARCH_REQUEST_DELAY_MS);
  }

  return [...candidates];
}

interface DownloadEntry { name: string; downloads: number }

/**
 * Verifies download counts for candidate packages and returns only those
 * with >= minDownloads weekly downloads, sorted by downloads descending.
 *
 * npm bulk downloads API does NOT support scoped packages (@scope/pkg), so
 * unscoped packages are batched (100 per request) and scoped packages are
 * fetched individually with concurrency control.
 */
async function _verifyByDownloads(
  candidates: string[],
  minDownloads: number,
  onProgress: (done: number, total: number) => void,
): Promise<DownloadEntry[]> {
  const results: DownloadEntry[] = [];
  let done = 0;
  const total = candidates.length;

  const scoped   = candidates.filter(n => n.startsWith('@'));
  const unscoped = candidates.filter(n => !n.startsWith('@'));

  // ── Unscoped: bulk batches ────────────────────────────────────────────────
  for (let i = 0; i < unscoped.length; i += UNSCOPED_BATCH_SIZE) {
    const batch = unscoped.slice(i, i + UNSCOPED_BATCH_SIZE);
    const url   = `${DOWNLOADS_URL}/${batch.join(',')}`;
    try {
      const res = await fetchWithRetry(
        url,
        { headers: { 'User-Agent': USER_AGENT } },
        { timeoutMs: 10_000 },
      );
      if (res.ok) {
        const data = await res.json() as Record<string, { downloads?: number }>;
        for (const [name, info] of Object.entries(data)) {
          const dl = info?.downloads ?? 0;
          if (dl >= minDownloads) results.push({ name, downloads: dl });
        }
      }
    } catch { /* skip batch on network error */ }
    done += batch.length;
    onProgress(done, total);
  }

  // ── Scoped: individual requests (bulk API rejects scoped packages) ────────
  await _withConcurrency(scoped, SCOPED_CONCURRENCY, async (name) => {
    const url = `${DOWNLOADS_URL}/${encodeURIComponent(name)}`;
    try {
      const res = await fetchWithRetry(
        url,
        { headers: { 'User-Agent': USER_AGENT } },
        { timeoutMs: 8_000 },
      );
      if (res.ok) {
        const data = await res.json() as { downloads?: number };
        const dl = data?.downloads ?? 0;
        if (dl >= minDownloads) results.push({ name, downloads: dl });
      }
    } catch { /* skip on error */ }
    done++;
    onProgress(done, total);
  });

  // Sort by weekly downloads descending so the most popular are ranked first
  return results.sort((a, b) => b.downloads - a.downloads);
}

/**
 * Registers the `safedeps update-packages` command.
 *
 * Strategy (two-phase):
 *   Phase 1 — Candidate discovery:
 *     Starts with the current top-packages.json as seeds (guarantees well-known
 *     packages are always candidates), then supplements by searching npm with
 *     broad ecosystem terms. A 400ms delay between search requests prevents
 *     hitting the registry's rate limit (HTTP 429).
 *
 *   Phase 2 — Download verification:
 *     Queries actual weekly download counts via the npm downloads API and keeps
 *     only packages with >= minDownloads weekly downloads (default: 1,000).
 *     This filters out low-quality packages (typosquats, abandoned packages)
 *     that might appear in search results.
 *
 *   Final list is sorted by weekly downloads descending and trimmed to --count.
 */
export default function registerUpdatePackagesCommand(program: Command): void {
  program
    .command('update-packages')
    .description('Update data/top-packages.json with the latest top npm packages')
    .option('--count <number>',        'Number of top packages to keep',                   '5000')
    .option('--min-downloads <number>', 'Minimum weekly downloads to include a package',   '1000')
    .option('-O, --output <format>',   'Output format: terminal | json',                   'terminal')
    .action(async (options: { count: string; minDownloads: string; output: string }) => {
      const count        = parseInt(options.count, 10);
      const minDownloads = parseInt(options.minDownloads, 10);

      if (isNaN(count) || count < 1) {
        console.error('\n  Error: --count must be a positive integer\n');
        process.exit(1);
        return;
      }
      if (isNaN(minDownloads) || minDownloads < 0) {
        console.error('\n  Error: --min-downloads must be a non-negative integer\n');
        process.exit(1);
        return;
      }

      const outPath = path.resolve(__dirname, '../../data/top-packages.json');

      // Load the current list — used both for seed candidates and previous-count display
      let seedList: string[] = [];
      try {
        const existing = JSON.parse(fs.readFileSync(outPath, 'utf8')) as unknown[];
        if (Array.isArray(existing)) seedList = existing.map(String);
      } catch { /* file doesn't exist yet */ }

      const previousCount = seedList.length;

      let spinner: import('ora').Ora | null = null;
      if (options.output !== 'json') {
        const ora = ((await (Function('return import("ora")')() as Promise<{ default: typeof import('ora').default }>)).default);
        spinner = ora(`Phase 1/2 — Collecting candidates (${seedList.length} seeded from current list)…`).start();
      }

      // ── Phase 1: collect candidates ───────────────────────────────────────
      let candidates: string[];
      try {
        candidates = await _collectCandidates(seedList, (term, idx, total) => {
          if (spinner) {
            spinner.text = `Phase 1/2 — Searching npm: "${term}" (${idx}/${total})…`;
          }
        });
      } catch (err) {
        spinner?.fail('Failed to collect candidates');
        console.error(`\n  Error: ${(err as Error).message}\n`);
        process.exit(1);
        return;
      }

      if (spinner) {
        spinner.text = `Phase 2/2 — Verifying download counts for ${candidates.length} candidates…`;
      }

      // ── Phase 2: verify downloads ─────────────────────────────────────────
      let verified: DownloadEntry[] = [];
      try {
        verified = await _verifyByDownloads(
          candidates,
          minDownloads,
          (done, total) => {
            if (spinner) {
              spinner.text = `Phase 2/2 — Verifying downloads… (${done}/${total} checked, ${verified.length} passed so far)`;
            }
          },
        );
      } catch (err) {
        spinner?.fail('Failed to verify download counts');
        console.error(`\n  Error: ${(err as Error).message}\n`);
        process.exit(1);
        return;
      }

      // Safety guard: refuse to overwrite the list if verification returned
      // suspiciously few packages — likely a transient network failure.
      const MIN_VALID_RESULTS = 50;
      if (verified.length < MIN_VALID_RESULTS) {
        spinner?.fail(`Verification returned only ${verified.length} packages — aborting to protect the existing list.`);
        console.error('    This may indicate a network issue. The existing list has not been modified.\n');
        process.exit(1);
        return;
      }

      const finalList = verified.slice(0, count).map(e => e.name);

      spinner?.stop();

      // ── Write output ──────────────────────────────────────────────────────
      const dataDir = path.dirname(outPath);
      if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
      fs.writeFileSync(outPath, JSON.stringify(finalList, null, 2) + '\n', 'utf8');

      if (options.output === 'json') {
        console.log(JSON.stringify({
          updated:      finalList.length,
          was:          previousCount,
          candidates:   candidates.length,
          minDownloads,
        }));
      } else {
        const chalk = ((await (Function('return import("chalk")')() as Promise<{ default: typeof import('chalk').default }>)).default);
        console.log(
          chalk.green('  ✓ ') +
          `Updated top-packages.json: ${finalList.length} packages (was ${previousCount})\n` +
          `    Verified ${candidates.length} candidates, kept packages with ≥ ${minDownloads.toLocaleString()} weekly downloads.`,
        );
      }
    });
}
