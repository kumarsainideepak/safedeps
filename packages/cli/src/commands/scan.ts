import path from 'path';
import { Command } from 'commander';
import { parsePackageJson } from '../utils/packageParser';
import { parseLockfile } from '../utils/lockfileParser';
import { scanPackages, enrichWithAuthenticity } from '../detectors/typosquat';
import { scanCVEs } from '../detectors/cve';
import type { CveResult } from '../detectors/cve';
import { scanLicenses } from '../detectors/license';
import type { LicenseResult } from '../detectors/license';
import { scanMaintainerHealth } from '../detectors/maintainer';
import type { MaintainerResult } from '../detectors/maintainer';
import { renderFullReport } from '../reporters/terminal';
import type { ScanResult } from '../reporters/terminal';
import { SignalRegistry } from '../utils/signalRegistry';

interface ScanOptions {
  path: string;
  severity: string;
  output: string;
  license?: string;
  offline?: boolean;
  failOn?: string;
  includeDev?: boolean;
  verbose?: boolean;
}

/**
 * Registers the `safedeps scan` command.
 *
 * Runs two detectors in parallel:
 *   1. Typosquatting (local, instant)
 *   2. CVE scan via OSV.dev API (network)
 *
 * Usage:
 *   safedeps scan
 *   safedeps scan --path ./my-project
 *   safedeps scan --severity high
 *   safedeps scan --output json
 *   safedeps scan --offline          (skip CVE scan, no network)
 *   safedeps scan --fail-on critical
 */
export default function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan all dependencies for typosquatting and known CVEs')
    .option('-P, --path <dir>',       'Path to project root',                    process.cwd())
    .option('-S, --severity <level>', 'Min severity to report',                  'low')
    .option('-O, --output <format>',  'Output format: terminal | json',          'terminal')
    .option('-L, --license <spdx>',   'Project license (overrides package.json)')
    .option('--offline',              'Skip CVE scan (no network calls)')
    .option('--fail-on <level>',      'Exit with code 1 if issues found at this level')
    .option('--include-dev',          'Include devDependencies in license scan')
    .option('-v, --verbose',          'Show enriched output with links and extended detail')
    .action(async (options: ScanOptions) => {
      const projectPath = path.resolve(options.path);

      // ── 1. Validate options ────────────────────────────────────────────
      const VALID_LEVELS = ['critical', 'high', 'medium', 'low'];
      if (!VALID_LEVELS.includes(options.severity.toLowerCase())) {
        console.error(`\n  Error: invalid --severity "${options.severity}". Valid values: ${VALID_LEVELS.join(', ')}\n`);
        process.exit(1);
        return;
      }
      if (options.failOn && !VALID_LEVELS.includes(options.failOn.toLowerCase())) {
        console.error(`\n  Error: invalid --fail-on "${options.failOn}". Valid values: ${VALID_LEVELS.join(', ')}\n`);
        process.exit(1);
        return;
      }

      // ── 2. Parse package.json ──────────────────────────────────────────
      let parsed: ReturnType<typeof parsePackageJson>;
      try {
        parsed = parsePackageJson(projectPath);
      } catch (err) {
        console.error(`\n  Error: ${(err as Error).message}\n`);
        process.exit(1);
        return; // unreachable, but satisfies TypeScript control flow
      }

      const start = Date.now();

      // Parse lockfile once — shared across all detectors to avoid 3× I/O
      const lockVersions = parseLockfile(projectPath);

      // Shared signal registry — collects per-package signals from maintainer detector
      const signalRegistry = new SignalRegistry();

      // ── 3. Run detectors concurrently ─────────────────────────────────
      const rawTyposquatFindings = scanPackages(parsed.allPackages);

      // Show a spinner during network-bound detector phases (terminal mode only)
      let spinner: import('ora').Ora | null = null;
      if (options.output !== 'json') {
        const ora = ((await (Function('return import("ora")')() as Promise<{ default: typeof import('ora').default }>)).default);
        const networkNote = options.offline ? '' : ' (CVE + maintainer + authenticity checks)';
        spinner = ora(`Scanning ${parsed.allPackages.length} dependencies${networkNote}…`).start();
      }

      const [cveSettled, licenseSettled, maintainerSettled, enrichedSettled] = await Promise.allSettled([
        options.offline
          ? Promise.resolve<CveResult | null>(null)
          : scanCVEs(parsed, { projectPath, minSeverity: options.severity, lockVersions }),
        scanLicenses(parsed, { projectPath, projectLicense: options.license, lockVersions, includeDevDeps: options.includeDev }),
        options.offline
          ? Promise.resolve<MaintainerResult | null>(null)
          : scanMaintainerHealth(parsed, { projectPath, lockVersions, signalRegistry }),
        options.offline
          ? Promise.resolve(rawTyposquatFindings)
          : enrichWithAuthenticity(rawTyposquatFindings, { signalRegistry }),
      ]);

      spinner?.stop();

      // Filter out dismissed false positives (packages with high npm adoption)
      const typosquatFindings = (
        enrichedSettled.status === 'fulfilled'
          ? enrichedSettled.value
          : rawTyposquatFindings
      ).filter(f => !f.authenticity?.dismissed);

      const cveResult: CveResult | null = options.offline
        ? null
        : cveSettled.status === 'fulfilled'
          ? cveSettled.value
          : { findings: [], scanned: 0, skipped: 0, error: (cveSettled.reason as Error).message };

      const licenseResult: LicenseResult | null =
        licenseSettled.status === 'fulfilled'
          ? licenseSettled.value
          : {
              projectLicense:  options.license ?? parsed.license ?? 'UNKNOWN',
              findings: [], scanned: 0, conflicts: 0, warnings: 0, unknowns: 0,
              includesDevDeps: options.includeDev ?? false,
              error: (licenseSettled.reason as Error).message,
            };

      const maintainerResult: MaintainerResult | null = options.offline
        ? null
        : maintainerSettled.status === 'fulfilled'
          ? maintainerSettled.value
          : { findings: [], scanned: 0, highRisk: 0, mediumRisk: 0, error: (maintainerSettled.reason as Error).message };

      const durationMs = Date.now() - start;

      const scanResult: ScanResult = {
        projectName:       parsed.name,
        totalScanned:      parsed.allPackages.length,
        typosquatFindings,
        cveResult,
        licenseResult,
        maintainerResult,
        durationMs,
        verbose:           options.verbose ?? false,
      };

      // ── 4. Render output ───────────────────────────────────────────────
      if (options.output === 'json') {
        console.log(JSON.stringify(scanResult, null, 2));
      } else {
        await renderFullReport(scanResult);
      }

      // ── 5. CI/CD exit code ─────────────────────────────────────────────
      if (options.failOn) {
        const severityOrder = ['critical', 'high', 'medium', 'low'];
        const threshold = severityOrder.indexOf(options.failOn.toLowerCase());

        const typoBlocking = typosquatFindings.some(f => {
          const idx = ({ high: 0, medium: 1, low: 2 } as Record<string, number>)[f.confidence] ?? 3;
          return idx <= threshold;
        });

        const cveBlocking = (cveResult?.findings ?? []).some(pkg => {
          const idx = severityOrder.indexOf(pkg.topSeverity.toLowerCase());
          return idx !== -1 && idx <= threshold;
        });

        // License conflicts → treated as "high"; warnings → "medium"
        const licenseBlocking = licenseResult !== null && (
          (licenseResult.conflicts > 0 && severityOrder.indexOf('high') <= threshold) ||
          (licenseResult.warnings  > 0 && severityOrder.indexOf('medium') <= threshold)
        );

        // Maintainer high risk → "high"; medium risk → "medium"
        const maintainerBlocking = maintainerResult !== null && (
          (maintainerResult.highRisk   > 0 && severityOrder.indexOf('high')   <= threshold) ||
          (maintainerResult.mediumRisk > 0 && severityOrder.indexOf('medium') <= threshold)
        );

        if (typoBlocking || cveBlocking || licenseBlocking || maintainerBlocking) {
          console.error(`  Build failed: issues found at "${options.failOn}" level or above.\n`);
          process.exit(1);
        }
      }
    });
}
