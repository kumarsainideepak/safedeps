import { Command } from 'commander';
import { analysePackage, enrichWithAuthenticity } from '../detectors/typosquat';
import { scanCVEs } from '../detectors/cve';
import { scanLicenses } from '../detectors/license';
import { scanMaintainerHealth } from '../detectors/maintainer';
import { fetchNpmLicense, fetchNpmPackumentInfo } from '../sources/npmRegistry';
import { renderCheckReport } from '../reporters/terminal';
import type { ParsedPackageJson } from '../utils/packageParser';

interface CheckOptions {
  output: string;
}

/**
 * Registers the `safedeps check <package>` command.
 *
 * Performs a comprehensive analysis of a single package by name (optionally
 * with a version). Runs all detectors: typosquat, authenticity, CVE, license,
 * and maintainer health — without requiring a local project.
 *
 * Usage:
 *   safedeps check lodash
 *   safedeps check left-pad@1.3.0
 *   safedeps check @types/node@18.0.0
 *   safedeps check lodash --output json
 */
export default function registerCheckCommand(program: Command): void {
  program
    .command('check <packageName>')
    .description('Run a full security check on a single package (typosquat, CVE, license, maintainer)')
    .option('-O, --output <format>', 'Output format: terminal | json', 'terminal')
    .action(async (packageName: string, options: CheckOptions) => {
      const start = Date.now();

      // ── 1. Parse name and optional version from input ────────────────────
      // Handles: lodash, lodash@4.17.21, @types/node, @types/node@18.0.0
      let name: string;
      let requestedVersion: string | null;

      if (packageName.startsWith('@')) {
        const lastAt = packageName.lastIndexOf('@');
        if (lastAt > 0) {
          name             = packageName.slice(0, lastAt);
          requestedVersion = packageName.slice(lastAt + 1);
        } else {
          name             = packageName;
          requestedVersion = null;
        }
      } else {
        const atIdx = packageName.indexOf('@');
        if (atIdx > 0) {
          name             = packageName.slice(0, atIdx);
          requestedVersion = packageName.slice(atIdx + 1);
        } else {
          name             = packageName;
          requestedVersion = null;
        }
      }

      // ── 2. Fetch package info from npm registry ──────────────────────────
      let resolvedVersion = requestedVersion ?? 'latest';
      let license: string | null = null;
      let createdAt: Date | null = null;
      let publishedVersions: number | null = null;
      let maintainerNames: string[] = [];
      let ageInDays: number | null = null;

      try {
        const [licenseInfo, packument] = await Promise.all([
          fetchNpmLicense(name, requestedVersion ?? 'latest'),
          fetchNpmPackumentInfo(name),
        ]);

        resolvedVersion   = licenseInfo.version;
        license           = licenseInfo.license;
        createdAt         = packument.createdAt;
        publishedVersions = packument.publishedVersions;
        maintainerNames   = packument.maintainers.map(m => m.name);

        if (createdAt) {
          ageInDays = Math.floor((Date.now() - createdAt.getTime()) / 86_400_000);
        }
      } catch (err) {
        if (options.output !== 'json') {
          const chalk = (await import('chalk')).default;
          console.log('');
          console.log(chalk.yellow(`  ⚠ Could not fetch package info from npm: ${(err as Error).message}`));
          console.log(chalk.dim('  Continuing with local checks only.'));
          console.log('');
        }
      }

      // ── 3. Typosquat check ───────────────────────────────────────────────
      const rawFinding = analysePackage(name);
      const ageMap = ageInDays !== null ? new Map([[name, ageInDays]]) : undefined;
      const [enriched] = rawFinding
        ? await enrichWithAuthenticity([rawFinding], { ageMap })
        : [null];

      // ── 4. CVE, Maintainer checks using synthetic ParsedPackageJson ──────
      const syntheticParsed: ParsedPackageJson = {
        name:                 'check-target',
        version:              '0.0.0',
        license:              null,
        allPackages:          [name],
        dependencies:         { [name]: resolvedVersion },
        devDependencies:      {},
        peerDependencies:     {},
        optionalDependencies: {},
      };
      const lockVersions = new Map([[name, resolvedVersion]]);

      const [cveSettled, licenseSettled, maintainerSettled] = await Promise.allSettled([
        scanCVEs(syntheticParsed, { lockVersions }),
        scanLicenses(syntheticParsed, { lockVersions, projectLicense: license ?? undefined }),
        scanMaintainerHealth(syntheticParsed, { lockVersions }),
      ]);

      const cveResult = cveSettled.status === 'fulfilled'
        ? cveSettled.value
        : { findings: [], scanned: 0, skipped: 0, error: (cveSettled.reason as Error).message };

      const licenseResult = licenseSettled.status === 'fulfilled'
        ? licenseSettled.value
        : null;

      const maintainerResult = maintainerSettled.status === 'fulfilled'
        ? maintainerSettled.value
        : { findings: [], scanned: 0, highRisk: 0, mediumRisk: 0, error: (maintainerSettled.reason as Error).message };

      const durationMs = Date.now() - start;

      // ── 5. Output ────────────────────────────────────────────────────────
      if (options.output === 'json') {
        console.log(JSON.stringify({
          name,
          version: resolvedVersion,
          license,
          weeklyDownloads:   enriched?.authenticity?.weeklyDownloads ?? null,
          ageInDays,
          publishedVersions,
          maintainers:       maintainerNames,
          typosquat:         enriched
            ? {
                match:        enriched.match,
                distance:     enriched.distance,
                method:       enriched.method,
                confidence:   enriched.confidence,
                authenticity: enriched.authenticity ?? null,
                dismissed:    enriched.authenticity?.dismissed ?? false,
              }
            : null,
          cve:               cveResult,
          licenseCompliance: licenseResult,
          maintainer:        maintainerResult,
          durationMs,
        }, null, 2));
        return;
      }

      await renderCheckReport({
        name,
        requestedVersion,
        resolvedVersion,
        license,
        weeklyDownloads:   enriched?.authenticity?.weeklyDownloads ?? null,
        ageInDays,
        publishedVersions,
        maintainerNames,
        typosquatFinding:  enriched,
        cveResult,
        licenseResult,
        maintainerResult,
        durationMs,
      });
    });
}
