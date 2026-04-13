/**
 * `safedeps guard [npm install args...]`
 *
 * Pre-install security firewall. Intercepts an `npm install` invocation,
 * performs a dry-run to determine what packages would be added or changed,
 * scans them for typosquatting and malicious install scripts, and only
 * proceeds with the real install if the user confirms (or --yes is passed).
 *
 * Usage:
 *   safedeps guard                        # wrap a plain npm install
 *   safedeps guard some-package           # install + scan one package
 *   safedeps guard some-package --yes     # non-interactive (CI use)
 */

import { execSync, spawn } from 'child_process';
import * as readline from 'readline';
import { Command } from 'commander';
import { scanPackages } from '../detectors/typosquat';
import { fetchVersionManifest } from '../sources/npmRegistry';
import { _classifyScriptRisk } from '../detectors/installScript';
import type { ScriptType } from '../detectors/installScript';

// ─── npm dry-run parsing ───────────────────────────────────────────────────

interface DryRunPackage {
  name:    string;
  version: string;
  action:  'add' | 'update';
}

/**
 * Runs `npm install --dry-run --json [args]` and extracts new/updated packages.
 * Falls back to an empty list on parse failure.
 */
export function parseDryRun(npmArgs: string[]): DryRunPackage[] {
  const cmd = `npm install --dry-run --json ${npmArgs.join(' ')}`;
  let stdout: string;

  try {
    stdout = execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (err) {
    // npm often exits non-zero during dry-run; stdout still has JSON
    stdout = (err as { stdout?: string }).stdout ?? '';
  }

  if (!stdout.trim()) return [];

  let json: Record<string, unknown>;
  try {
    json = JSON.parse(stdout);
  } catch {
    return [];
  }

  // npm --json dry-run output has an "added" array and a "updated" array
  const packages: DryRunPackage[] = [];

  const added = Array.isArray(json.added) ? json.added as Array<{ name?: string; version?: string }> : [];
  for (const pkg of added) {
    if (pkg.name && pkg.version) {
      packages.push({ name: pkg.name, version: pkg.version, action: 'add' });
    }
  }

  const updated = Array.isArray(json.updated) ? json.updated as Array<{ name?: string; version?: string }> : [];
  for (const pkg of updated) {
    if (pkg.name && pkg.version) {
      packages.push({ name: pkg.name, version: pkg.version, action: 'update' });
    }
  }

  return packages;
}

// ─── Script scanning (fetches from registry for not-yet-installed pkgs) ────

interface ScriptRisk {
  name:       string;
  version:    string;
  scriptType: ScriptType;
  scriptBody: string;
  reason:     string;
  risk:       'high' | 'medium' | 'informational';
}

async function _fetchAndClassifyScripts(
  pkg: DryRunPackage,
): Promise<ScriptRisk[]> {
  let manifest: Awaited<ReturnType<typeof fetchVersionManifest>>;
  try {
    manifest = await fetchVersionManifest(pkg.name, pkg.version);
  } catch {
    return [];
  }

  const HOOKS: ScriptType[] = ['preinstall', 'install', 'postinstall'];
  const findings: ScriptRisk[] = [];

  for (const hook of HOOKS) {
    const body = manifest.scripts[hook];
    if (!body) continue;

    const { risk, reason } = _classifyScriptRisk(body, hook);
    if (risk !== 'informational') {
      findings.push({
        name:       pkg.name,
        version:    pkg.version,
        scriptType: hook,
        scriptBody: body,
        reason,
        risk,
      });
    }
  }

  return findings;
}

// ─── User prompt ───────────────────────────────────────────────────────────

function _prompt(question: string): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y' || answer.trim().toLowerCase() === 'yes');
    });
  });
}

// ─── Command registration ──────────────────────────────────────────────────

export default function registerGuardCommand(program: Command): void {
  program
    .command('guard [args...]')
    .description(
      'Pre-scan packages before installing them\n' +
      '  Examples:\n' +
      '    safedeps guard some-package\n' +
      '    safedeps guard some-package --yes   (non-interactive)',
    )
    .option('--yes', 'Skip confirmation prompt and proceed automatically')
    .allowUnknownOption()
    .action(async (args: string[], opts: { yes?: boolean }) => {
      const { default: chalk } = await import('chalk');
      const { default: ora }   = await import('ora');

      // ── Step 1: dry-run ──────────────────────────────────────────────────
      const drySpinner = ora('Running npm dry-run…').start();
      const incoming   = parseDryRun(args);
      drySpinner.succeed(`Dry-run complete — ${incoming.length} package(s) to evaluate`);

      if (incoming.length === 0) {
        console.log(chalk.dim('  No new or changed packages detected — nothing to scan.'));
        _runNpmInstall(args);
        return;
      }

      // ── Step 2: typosquat check ──────────────────────────────────────────
      const typoFindings = scanPackages(incoming.map(p => p.name));

      // ── Step 3: install script check (via registry) ──────────────────────
      const scriptSpinner = ora('Fetching install scripts from registry…').start();
      const scriptFindings: ScriptRisk[] = [];

      await Promise.allSettled(
        incoming.map(async pkg => {
          const findings = await _fetchAndClassifyScripts(pkg);
          scriptFindings.push(...findings);
        }),
      );
      scriptSpinner.succeed('Script scan complete');

      // ── Step 4: display findings ─────────────────────────────────────────
      const highRiskScripts  = scriptFindings.filter(f => f.risk === 'high');
      const medRiskScripts   = scriptFindings.filter(f => f.risk === 'medium');
      const highRiskTypo     = typoFindings.filter(f => f.confidence === 'high' && !f.authenticity?.dismissed);

      const hasRisks = highRiskScripts.length > 0 || highRiskTypo.length > 0;

      console.log('');
      console.log(chalk.bold('SafeDeps Guard — Pre-install scan'));
      console.log(chalk.dim('─'.repeat(60)));

      if (typoFindings.length > 0) {
        console.log(chalk.bold('\n  Typosquat risks'));
        for (const f of typoFindings) {
          const color = f.confidence === 'high' ? chalk.red : chalk.yellow;
          console.log(color(`  [${f.confidence.toUpperCase()}] ${f.suspicious}  →  similar to "${f.match}"`));
        }
      }

      if (highRiskScripts.length > 0) {
        console.log(chalk.bold.red('\n  High-risk install scripts'));
        for (const f of highRiskScripts) {
          console.log(chalk.red(`  [HIGH] ${f.name}@${f.version}  [${f.scriptType}]  ${f.reason}`));
        }
      }

      if (medRiskScripts.length > 0) {
        console.log(chalk.bold.yellow('\n  Medium-risk install scripts'));
        for (const f of medRiskScripts) {
          console.log(chalk.yellow(`  [MED]  ${f.name}@${f.version}  [${f.scriptType}]  ${f.reason}`));
        }
      }

      if (!hasRisks) {
        console.log(chalk.green('\n  ✓ No high-risk packages detected'));
      }

      console.log('');

      // ── Step 5: prompt or auto-proceed ───────────────────────────────────
      let proceed = false;

      if (opts.yes) {
        proceed = true;
        if (hasRisks) {
          console.log(chalk.yellow('  --yes flag set — proceeding despite risks'));
        }
      } else if (hasRisks) {
        proceed = await _prompt(
          chalk.bold.yellow('  ⚠ Risks detected. Proceed with install? [y/N] '),
        );
      } else {
        proceed = true;
      }

      if (!proceed) {
        console.log(chalk.red('\n  Install aborted.'));
        process.exit(1);
      }

      // ── Step 6: real install ─────────────────────────────────────────────
      console.log(chalk.dim('\n  Running npm install…'));
      _runNpmInstall(args);
    });
}

function _runNpmInstall(args: string[]): void {
  const child = spawn('npm', ['install', ...args], { stdio: 'inherit' });
  child.on('close', code => {
    process.exit(code ?? 0);
  });
}
