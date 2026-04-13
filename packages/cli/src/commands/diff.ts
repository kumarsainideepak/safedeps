/**
 * `safedeps diff <pkg@v1> <pkg@v2>`
 *
 * Compares two versions of an npm package and highlights security-relevant
 * changes: publisher identity, install scripts, and dependency additions.
 *
 * Usage:
 *   safedeps diff express@4.18.0 express@4.21.0
 *   safedeps diff lodash 4.17.20 4.17.21
 */

import { Command } from 'commander';
import { fetchVersionManifest } from '../sources/npmRegistry';
import type { VersionManifestRaw } from '../sources/npmRegistry';
import { computeDiff } from '../utils/packageDiff';
import type { PackageDiff } from '../utils/packageDiff';
import type { VersionManifest } from '../utils/packageDiff';

// ─── Argument parsing ──────────────────────────────────────────────────────

interface ParsedTarget {
  name:    string;
  version: string;
}

/**
 * Parses a "pkg@version" string into { name, version }.
 * Handles scoped packages (@scope/name@version).
 */
export function parsePackageTarget(raw: string): ParsedTarget | null {
  // Scoped: @scope/name@version
  if (raw.startsWith('@')) {
    const rest = raw.slice(1);       // "scope/name@version"
    const atIdx = rest.lastIndexOf('@');
    if (atIdx > 0) {
      const name    = '@' + rest.slice(0, atIdx);
      const version = rest.slice(atIdx + 1);
      if (version) return { name, version };
    }
    return null;
  }

  // Unscoped: name@version
  const atIdx = raw.lastIndexOf('@');
  if (atIdx > 0) {
    return { name: raw.slice(0, atIdx), version: raw.slice(atIdx + 1) };
  }
  return null;
}

// ─── Rendering ─────────────────────────────────────────────────────────────

async function renderDiffReport(diff: PackageDiff): Promise<void> {
  const { default: chalk } = await import('chalk');

  console.log('');
  console.log(chalk.bold(`Package diff: ${diff.name}`));
  console.log(chalk.dim(`  ${diff.fromVersion}  →  ${diff.toVersion}`));
  console.log('');

  // ── Risk flags ─────────────────────────────────────────────────────────
  if (diff.riskFlags.length > 0) {
    console.log(chalk.bold.red('  ⚠ Risk flags'));
    for (const flag of diff.riskFlags) {
      console.log(chalk.red(`    • ${flag}`));
    }
    console.log('');
  } else {
    console.log(chalk.green('  ✓ No risk flags detected'));
    console.log('');
  }

  // ── Publisher ──────────────────────────────────────────────────────────
  if (diff.publisherChanged) {
    console.log(chalk.bold('  Publisher'));
    console.log(
      `    ${chalk.dim(diff.previousPublisher ?? '(unknown)')}  →  ${chalk.yellow(diff.currentPublisher ?? '(unknown)')}`,
    );
    console.log('');
  }

  // ── Install script changes ─────────────────────────────────────────────
  const hasScriptChanges =
    diff.scriptsAdded.length + diff.scriptsRemoved.length + diff.scriptsChanged.length > 0;

  if (hasScriptChanges) {
    console.log(chalk.bold('  Install scripts'));

    for (const s of diff.scriptsAdded) {
      console.log(chalk.green(`    + [${s.key}] ${s.value}`));
    }
    for (const key of diff.scriptsRemoved) {
      console.log(chalk.dim(`    - [${key}] (removed)`));
    }
    for (const s of diff.scriptsChanged) {
      console.log(chalk.yellow(`    ~ [${s.key}]`));
      console.log(chalk.dim(`        was: ${s.from}`));
      console.log(`        now: ${s.to}`);
    }
    console.log('');
  } else {
    console.log(chalk.dim('  Install scripts: no changes'));
    console.log('');
  }

  // ── Dependency changes ─────────────────────────────────────────────────
  const hasDepChanges =
    diff.depsAdded.length + diff.depsRemoved.length + diff.depsChanged.length > 0;

  if (hasDepChanges) {
    console.log(chalk.bold('  Dependencies'));
    for (const d of diff.depsAdded) {
      console.log(chalk.green(`    + ${d.name}@${d.version}`));
    }
    for (const name of diff.depsRemoved) {
      console.log(chalk.dim(`    - ${name}`));
    }
    for (const d of diff.depsChanged) {
      console.log(chalk.yellow(`    ~ ${d.name}: ${d.from}  →  ${d.to}`));
    }
    console.log('');
  } else {
    console.log(chalk.dim('  Dependencies: no changes'));
    console.log('');
  }
}

// ─── Command registration ──────────────────────────────────────────────────

export default function registerDiffCommand(program: Command): void {
  program
    .command('diff <from> <to>')
    .description(
      'Compare two versions of a package  (e.g. express@4.18.0 express@4.21.0)\n' +
      '  or: diff <name> <v1> <v2>  if you prefer positional version args',
    )
    .action(async (fromArg: string, toArg: string) => {
      let fromTarget = parsePackageTarget(fromArg);
      let toTarget   = parsePackageTarget(toArg);

      // Fallback: user passed bare versions as separate args?
      // e.g. safedeps diff express 4.18.0 4.21.0 (commander treats 4.21.0 as extra)
      if (!fromTarget || !toTarget) {
        console.error(
          'Usage: safedeps diff <pkg@v1> <pkg@v2>\n' +
          'Example: safedeps diff express@4.18.0 express@4.21.0',
        );
        process.exit(1);
      }

      if (fromTarget.name !== toTarget.name) {
        console.error(`Package names must match (got "${fromTarget.name}" and "${toTarget.name}")`);
        process.exit(1);
      }

      const { default: ora } = await import('ora');
      const spinner = ora(
        `Fetching ${fromTarget.name}@${fromTarget.version} and @${toTarget.version}…`,
      ).start();

      let fromManifest: VersionManifestRaw;
      let toManifest:   VersionManifestRaw;

      try {
        [fromManifest, toManifest] = await Promise.all([
          fetchVersionManifest(fromTarget.name, fromTarget.version),
          fetchVersionManifest(toTarget.name,   toTarget.version),
        ]);
        spinner.succeed('Fetched both manifests');
      } catch (err) {
        spinner.fail(`Failed to fetch manifests: ${(err as Error).message}`);
        process.exit(1);
      }

      const toVM = (raw: VersionManifestRaw): VersionManifest => ({
        name:            raw.name,
        version:         raw.version,
        dependencies:    raw.dependencies,
        devDependencies: raw.devDependencies,
        scripts:         raw.scripts,
        publisher:       raw.publisher,
      });

      const diff = computeDiff(toVM(fromManifest), toVM(toManifest));
      await renderDiffReport(diff);
    });
}
