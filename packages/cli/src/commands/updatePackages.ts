import path from 'path';
import fs from 'fs';
import { Command } from 'commander';
import { fetchWithRetry } from '../utils/httpRetry';
import { USER_AGENT } from '../utils/constants';

const SEARCH_URL = 'https://registry.npmjs.org/-/v1/search';
const PAGE_SIZE  = 250;

interface NpmSearchResult {
  package: { name: string };
}

interface NpmSearchResponse {
  objects?: NpmSearchResult[];
  total?:   number;
}

async function _fetchPage(from: number): Promise<string[]> {
  const url = `${SEARCH_URL}?text=boost-exact:true&size=${PAGE_SIZE}&from=${from}`;
  const response = await fetchWithRetry(
    url,
    { headers: { Accept: 'application/json', 'User-Agent': USER_AGENT } },
    { timeoutMs: 15_000 },
  );

  if (!response.ok) throw new Error(`npm search API returned HTTP ${response.status}`);

  const data = await response.json() as NpmSearchResponse;
  return (data.objects ?? []).map(o => o.package.name);
}

/**
 * Registers the `safedeps update-packages` command.
 *
 * Fetches the top N npm packages by download popularity and writes the result
 * to data/top-packages.json, replacing the previous list.
 */
export default function registerUpdatePackagesCommand(program: Command): void {
  program
    .command('update-packages')
    .description('Update data/top-packages.json with the latest top npm packages')
    .option('--count <number>', 'Number of packages to fetch', '5000')
    .option('-O, --output <format>', 'Output format: terminal | json', 'terminal')
    .action(async (options: { count: string; output: string }) => {
      const count = parseInt(options.count, 10);
      if (isNaN(count) || count < 1) {
        console.error('\n  Error: --count must be a positive integer\n');
        process.exit(1);
        return;
      }

      const outPath = path.resolve(__dirname, '../../data/top-packages.json');

      // Read the current count for the summary message
      let previousCount = 0;
      try {
        const existing = JSON.parse(fs.readFileSync(outPath, 'utf8')) as unknown[];
        previousCount = Array.isArray(existing) ? existing.length : 0;
      } catch {
        // file doesn't exist yet — that's fine
      }

      let spinner: import('ora').Ora | null = null;
      if (options.output !== 'json') {
        const ora = (await import('ora')).default;
        spinner = ora(`Fetching top ${count} npm packages…`).start();
      }

      const packages: string[] = [];
      let from = 0;

      try {
        while (packages.length < count) {
          const page = await _fetchPage(from);
          if (page.length === 0) break;
          packages.push(...page);
          from += PAGE_SIZE;
          if (spinner) {
            spinner.text = `Fetching top ${count} npm packages… (${Math.min(packages.length, count)} / ${count})`;
          }
        }
      } catch (err) {
        spinner?.fail('Failed to fetch packages');
        console.error(`\n  Error: ${(err as Error).message}\n`);
        process.exit(1);
        return;
      }

      // Trim to requested count and deduplicate
      const deduplicated = [...new Set(packages)].slice(0, count);

      spinner?.stop();

      // Ensure data/ directory exists
      const dataDir = path.dirname(outPath);
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }

      fs.writeFileSync(outPath, JSON.stringify(deduplicated, null, 2) + '\n', 'utf8');

      if (options.output === 'json') {
        console.log(JSON.stringify({ updated: deduplicated.length, was: previousCount }));
      } else {
        const chalk = (await import('chalk')).default;
        console.log(
          chalk.green('  ✓ ') +
          `Updated top-packages.json: ${deduplicated.length} packages (was ${previousCount})`,
        );
      }
    });
}
