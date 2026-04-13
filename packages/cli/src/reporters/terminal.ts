import pkg from '../../package.json';
import type { TyposquatFinding } from '../detectors/typosquat';
import type { CveResult, CveFinding } from '../detectors/cve';
import type { LicenseResult } from '../detectors/license';
import type { MaintainerResult, MaintainerFinding } from '../detectors/maintainer';
import type { InstallScriptResult } from '../detectors/installScript';
import type { AbandonedResult } from '../detectors/abandoned';

export interface CheckReport {
  name:             string;
  requestedVersion: string | null;
  resolvedVersion:  string;
  license:          string | null;
  weeklyDownloads:  number | null;
  ageInDays:        number | null;
  publishedVersions: number | null;
  maintainerNames:  string[];
  typosquatFinding: TyposquatFinding | null;
  cveResult:        CveResult | null;
  licenseResult:    LicenseResult | null;
  maintainerResult: MaintainerResult | null;
  durationMs:       number;
  verbose?:         boolean;
}

/**
 * Terminal reporter — renders scan results as a colour-coded table.
 *
 * Uses ANSI escape codes via the chalk library. Each finding row shows:
 *   SEVERITY  package@version  description
 *
 * Severity colours:
 *   CRITICAL → red bold
 *   HIGH     → red
 *   MEDIUM   → yellow
 *   LOW      → cyan
 *   OK       → green
 */

// We use chalk v5 (ESM) via dynamic import wrapped in a factory.
// To keep this file CJS-compatible we lazy-load chalk.
type ChalkInstance = typeof import('chalk').default;
let _chalk: ChalkInstance | null = null;

async function getChalk(): Promise<ChalkInstance> {
  if (!_chalk) {
    // TypeScript (module: commonjs) transforms `await import('chalk')` into
    // `require('chalk')`, which breaks ESM-only chalk v5.
    // Using Function() prevents TypeScript from transforming this call.
    _chalk = ((await (Function('return import("chalk")')() as Promise<{ default: ChalkInstance }>)).default);
  }
  return _chalk;
}

interface ConfidenceConfig {
  label: string;
  color: string;
}

/** Maps a confidence string to a severity label + chalk colour name. */
const CONFIDENCE_MAP: Record<string, ConfidenceConfig> = {
  high:   { label: 'CRITICAL', color: 'redBright' },
  medium: { label: 'HIGH',     color: 'red'       },
  low:    { label: 'MEDIUM',   color: 'yellow'    },
};

export interface ScanResult {
  projectName:          string;
  totalScanned:         number;
  typosquatFindings:    TyposquatFinding[];
  cveResult:            CveResult | null;
  licenseResult:        LicenseResult | null;
  maintainerResult:     MaintainerResult | null;
  installScriptResult?: InstallScriptResult | null;
  abandonedResult?:     AbandonedResult | null;
  durationMs:           number;
  verbose?:             boolean;
}

/**
 * Renders a full scan report (typosquat + CVE + license + maintainer) to stdout.
 */
export async function renderFullReport(scanResult: ScanResult): Promise<void> {
  const chalk = await getChalk();

  const { projectName, totalScanned, typosquatFindings, cveResult, licenseResult, maintainerResult, installScriptResult, abandonedResult, durationMs, verbose = false } = scanResult;

  console.log('');
  console.log(
    chalk.bold.blue('  SafeDeps') +
    chalk.dim(` v${pkg.version}`) +
    chalk.dim(` — scanning ${totalScanned} dependencies in `) +
    chalk.bold(projectName)
  );
  console.log('');

  if (typosquatFindings.length === 0) {
    console.log(chalk.green('  ✓ No typosquatting issues detected.'));
    console.log('');

    if (cveResult) {
      renderCveSection(chalk, cveResult, verbose);
    }

    if (licenseResult) {
      renderLicenseSection(chalk, licenseResult, verbose);
    }

    if (maintainerResult) {
      renderMaintainerSection(chalk, maintainerResult, verbose);
    }

    if (installScriptResult) {
      renderInstallScriptSection(chalk, installScriptResult, verbose);
    }

    if (abandonedResult) {
      renderAbandonedSection(chalk, abandonedResult, verbose);
    }

    printSummary(chalk, totalScanned, typosquatFindings, cveResult, licenseResult, maintainerResult, installScriptResult ?? null, abandonedResult ?? null, durationMs);
    return;
  }

  // Column widths
  const COL_SEV = 10;
  const COL_PKG = 30;

  // Header row
  console.log(
    chalk.dim('  ' +
      'SEVERITY'.padEnd(COL_SEV) +
      'PACKAGE'.padEnd(COL_PKG) +
      'FINDING'
    )
  );
  console.log(chalk.dim('  ' + '─'.repeat(80)));

  for (const f of typosquatFindings) {
    const { label, color } = CONFIDENCE_MAP[f.confidence] ?? { label: 'LOW', color: 'cyan' };

    const colorFn     = _chalkColor(chalk, color);
    const severityCol = colorFn.bold(label.padEnd(COL_SEV));
    const packageCol  = chalk.white(f.suspicious.padEnd(COL_PKG));
    const message     = buildFindingMessage(chalk, f);

    console.log(`  ${severityCol}${packageCol}${message}`);
  }

  console.log('');

  // ── CVE section ────────────────────────────────────────────────────────
  if (cveResult) {
    renderCveSection(chalk, cveResult, verbose);
  }

  // ── License section ────────────────────────────────────────────────────
  if (licenseResult) {
    renderLicenseSection(chalk, licenseResult, verbose);
  }

  // ── Maintainer section ─────────────────────────────────────────────────
  if (maintainerResult) {
    renderMaintainerSection(chalk, maintainerResult, verbose);
  }

  // ── Install script section ─────────────────────────────────────────────
  if (installScriptResult) {
    renderInstallScriptSection(chalk, installScriptResult, verbose);
  }

  // ── Abandoned section ──────────────────────────────────────────────────
  if (abandonedResult) {
    renderAbandonedSection(chalk, abandonedResult, verbose);
  }

  printSummary(chalk, totalScanned, typosquatFindings, cveResult, licenseResult, maintainerResult, installScriptResult ?? null, abandonedResult ?? null, durationMs);
}

/** Builds the human-readable finding message for one typosquat result. */
function buildFindingMessage(chalk: ChalkInstance, finding: TyposquatFinding): string {
  const methodLabel: Record<string, string> = {
    levenshtein:          'character similarity',
    soundex:              'phonetic similarity',
    'levenshtein+soundex': 'character + phonetic similarity',
    separator:            'separator substitution',
    homoglyph:            'homoglyph substitution',
    combosquat:           'combo suffix/prefix',
  };

  return (
    chalk.yellow('Typosquatting suspected') +
    chalk.dim(' — did you mean ') +
    chalk.green.bold(`"${finding.match}"`) +
    chalk.dim(`? (${methodLabel[finding.method] ?? finding.method}, distance: ${finding.distance})`)
  );
}

/**
 * Renders the CVE vulnerability section.
 * Shows each vulnerable package and its top CVE identifiers.
 */
function renderCveSection(chalk: ChalkInstance, result: CveResult, verbose: boolean): void {
  const scannedLabel = result.scanned > 0 ? `scanned ${result.scanned}` : 'no versions resolved';
  const skippedNote  = result.skipped > 0 ? chalk.dim(`, ${result.skipped} skipped`) : '';

  console.log(
    chalk.bold.blue('  CVE Vulnerabilities') +
    chalk.dim(` — ${scannedLabel} packages`) +
    skippedNote
  );
  console.log('');

  if (result.error) {
    console.log(chalk.yellow(`  ⚠ CVE scan error: ${result.error}`));
    console.log('');
    return;
  }

  if (result.findings.length === 0) {
    console.log(chalk.green('  ✓ No known CVEs found.'));
    console.log('');
    return;
  }

  const SEVERITY_COLOR: Record<string, (s: string) => string> = {
    CRITICAL: (s) => chalk.redBright.bold(s),
    HIGH:     (s) => chalk.red(s),
    MEDIUM:   (s) => chalk.yellow(s),
    LOW:      (s) => chalk.cyan(s),
    UNKNOWN:  (s) => chalk.magenta(s),
  };

  const COL_SEV = 10;
  const COL_PKG = 30;

  console.log(
    chalk.dim('  ' +
      'SEVERITY'.padEnd(COL_SEV) +
      'PACKAGE'.padEnd(COL_PKG) +
      'VULNERABILITIES'
    )
  );
  console.log(chalk.dim('  ' + '─'.repeat(80)));

  for (const cveFinding of result.findings) {
    const colorFn    = SEVERITY_COLOR[cveFinding.topSeverity.toUpperCase()] ?? SEVERITY_COLOR['UNKNOWN'];
    const severityCol = colorFn(cveFinding.topSeverity.toUpperCase().padEnd(COL_SEV));
    const packageCol  = chalk.white(`${cveFinding.name}@${cveFinding.version}`.padEnd(COL_PKG));

    // Show up to 3 CVE IDs inline; overflow indicated with "+N more"
    const ids      = cveFinding.vulns.map(v => v.id);
    const shown    = ids.slice(0, 3);
    const overflow = ids.length > 3 ? chalk.dim(` +${ids.length - 3} more`) : '';
    const cveList  = shown.map(id => chalk.dim(id)).join(chalk.dim(', ')) + overflow;

    console.log(`  ${severityCol}${packageCol}${cveList}`);

    if (verbose) {
      // OSV permalink for the top vuln
      _indent(chalk, chalk.dim('OSV:       ') + `https://osv.dev/vulnerability/${cveFinding.vulns[0].id}`);

      // NVD link for each CVE alias
      for (const alias of (cveFinding.aliases ?? [])) {
        if (alias.startsWith('CVE-')) {
          _indent(chalk, chalk.dim('NVD:       ') + `https://nvd.nist.gov/vuln/detail/${alias}`);
        }
      }

      // CVSS score + vector
      if (cveFinding.cvssScore !== null && cveFinding.cvssScore !== undefined) {
        const vectorStr = cveFinding.cvssVector ? chalk.dim(` (${cveFinding.cvssVector})`) : '';
        _indent(chalk, chalk.dim('CVSS:      ') + chalk.white(String(cveFinding.cvssScore)) + vectorStr);
      }

      // Affected version range
      if (cveFinding.affectedRange) {
        _indent(chalk, chalk.dim('Affects:   ') + cveFinding.affectedRange);
      }

      // Fix version
      if (cveFinding.fixedIn) {
        _indent(chalk, chalk.dim('Fixed in:  ') + chalk.green(cveFinding.fixedIn));
      } else {
        _indent(chalk, chalk.dim('Fixed in:  ') + chalk.yellow('No fix available'));
      }

      // Published date (trim to YYYY-MM-DD)
      if (cveFinding.published) {
        _indent(chalk, chalk.dim('Published: ') + cveFinding.published.slice(0, 10));
      }

      // Description
      if (cveFinding.details) {
        const truncated = cveFinding.details.length > 300
          ? cveFinding.details.slice(0, 300) + '…'
          : cveFinding.details;
        _indent(chalk, chalk.dim('Details:   ') + truncated);
      }

      // Per-finding range-floor warning
      if (cveFinding.versionSource === 'range-floor') {
        _indent(chalk, chalk.yellow('⚠ Version resolved via range floor — results may over-report'));
      }

      console.log('');
    } else {
      // Non-verbose: show fix version on continuation line
      const firstFix = cveFinding.vulns.find(v => v.fixedIn.length > 0);
      if (firstFix) {
        console.log(chalk.dim(`  ${''.padEnd(COL_SEV + COL_PKG)}Fix available: `) + chalk.green(firstFix.fixedIn[0]));
      }
    }
  }

  // Aggregate range-floor warning (non-verbose only, verbose shows per-finding)
  if (!verbose) {
    const rangeFlorCount = result.findings.filter(
      (f: CveFinding) => f.versionSource === 'range-floor',
    ).length;
    if (rangeFlorCount > 0) {
      console.log(
        chalk.yellow(`  ⚠ ${rangeFlorCount} package${rangeFlorCount > 1 ? 's have' : ' has'} no lockfile version — using range floor (may over-report CVEs). Run 'npm install' for precise version resolution.`),
      );
    }
  }

  console.log('');
}

/**
 * Renders the license compliance section.
 * Only prints packages with conflict / warning / unknown status — clean
 * packages are counted in the summary line to keep output readable.
 */
function renderLicenseSection(chalk: ChalkInstance, result: LicenseResult, verbose: boolean): void {
  const devNote = result.includesDevDeps ? ' (incl. dev)' : '';
  console.log(
    chalk.bold.blue('  License Compliance') +
    chalk.dim(` — project: `) +
    chalk.white(result.projectLicense) +
    chalk.dim(`, scanned ${result.scanned} dependencies${devNote}`)
  );
  console.log('');

  const issues = result.findings.filter(f => f.status !== 'ok');

  if (issues.length === 0) {
    console.log(chalk.green('  ✓ No license issues detected.'));
    console.log('');
    return;
  }

  const COL_SEV = 10;
  const COL_PKG = 30;
  const COL_LIC = 22;

  console.log(
    chalk.dim('  ' +
      'STATUS'.padEnd(COL_SEV) +
      'PACKAGE'.padEnd(COL_PKG) +
      'LICENSE'.padEnd(COL_LIC) +
      'FINDING'
    )
  );
  console.log(chalk.dim('  ' + '─'.repeat(90)));

  for (const f of issues) {
    let statusLabel: string;
    let colorFn: (s: string) => string;

    switch (f.status) {
      case 'conflict':
        statusLabel = 'CONFLICT';
        colorFn = (s: string) => chalk.redBright.bold(s);
        break;
      case 'warning':
        statusLabel = 'WARNING';
        colorFn = (s: string) => chalk.yellow(s);
        break;
      default:
        statusLabel = 'UNKNOWN';
        colorFn = (s: string) => chalk.dim(s);
    }

    const statusCol  = colorFn(statusLabel.padEnd(COL_SEV));
    const packageCol = chalk.white(`${f.name}@${f.version}`.padEnd(COL_PKG));
    const licenseCol = chalk.cyan(f.normalizedLicense.padEnd(COL_LIC));
    const reason     = chalk.dim(f.reason);

    console.log(`  ${statusCol}${packageCol}${licenseCol}${reason}`);

    if (verbose) {
      if (f.spdxUrl) {
        _indent(chalk, chalk.dim('SPDX:         ') + f.spdxUrl);
      }
      if (f.tldrUrl) {
        _indent(chalk, chalk.dim('tl;dr Legal:  ') + f.tldrUrl);
      }
      if (f.compatibilityExplanation) {
        _indent(chalk, chalk.dim('Why:          ') + f.compatibilityExplanation);
      }
      if (f.rawLicense !== f.normalizedLicense && f.rawLicense !== 'none') {
        _indent(chalk, chalk.dim('Raw SPDX:     ') + chalk.cyan(f.rawLicense));
      }
      console.log('');
    }
  }

  if (!verbose) console.log('');
}

/**
 * Renders the maintainer health section.
 * Only prints packages with high or medium risk — healthy ones are counted in summary.
 */
function renderMaintainerSection(chalk: ChalkInstance, result: MaintainerResult, verbose: boolean): void {
  console.log(
    chalk.bold.blue('  Maintainer Health') +
    chalk.dim(` — scanned ${result.scanned} dependencies`)
  );
  console.log('');

  const atRisk = result.findings.filter(f => f.risk !== 'low');

  if (atRisk.length === 0) {
    console.log(chalk.green('  ✓ All maintainers appear healthy.'));
    console.log('');
    return;
  }

  const COL_RISK  = 10;
  const COL_PKG   = 30;
  const COL_SCORE = 10;

  console.log(
    chalk.dim('  ' +
      'RISK'.padEnd(COL_RISK) +
      'PACKAGE'.padEnd(COL_PKG) +
      'SCORE'.padEnd(COL_SCORE) +
      'SIGNALS'
    )
  );
  console.log(chalk.dim('  ' + '─'.repeat(90)));

  for (const f of atRisk) {
    const riskLabel = f.risk.toUpperCase();
    const colorFn   = f.risk === 'high'
      ? (s: string) => chalk.redBright.bold(s)
      : (s: string) => chalk.yellow(s);

    const riskCol    = colorFn(riskLabel.padEnd(COL_RISK));
    const packageCol = chalk.white(`${f.name}@${f.version}`.padEnd(COL_PKG));
    const scoreCol   = colorFn(`${f.score}/100`.padEnd(COL_SCORE));
    const signals    = chalk.dim(_buildMaintainerSignalSummary(f));

    const takeoverBadge = f.takeoverRisk === 'high'
      ? '  ' + chalk.redBright.bold('TAKEOVER RISK')
      : f.takeoverRisk === 'medium'
        ? '  ' + chalk.yellow('TAKEOVER RISK')
        : '';

    console.log(`  ${riskCol}${packageCol}${scoreCol}${signals}${takeoverBadge}`);

    if (verbose) {
      _indent(chalk, chalk.dim('npm:              ') + f.npmUrl);

      if (f.githubUrl) {
        _indent(chalk, chalk.dim('GitHub:           ') + f.githubUrl);
      }

      if (f.maintainerNames.length > 0) {
        for (const m of f.maintainerNames) {
          _indent(chalk, chalk.dim('maintainer:       ') + `https://www.npmjs.com/~${m}`);
        }
      }

      const bd = f.breakdown;
      _indent(chalk, chalk.dim('Score breakdown:  ') +
        chalk.dim(`Recency ${bd.recency}/30`) + chalk.dim(' · ') +
        chalk.dim(`Maintainers ${bd.maintainerCount}/20`) + chalk.dim(' · ') +
        chalk.dim(`Acct age ${bd.accountAge}/20`) + chalk.dim(' · ') +
        chalk.dim(`GitHub ${bd.githubActivity}/15`) + chalk.dim(' · ') +
        chalk.dim(`Issues ${bd.issueHealth}/10`) + chalk.dim(' · ') +
        chalk.dim(`Popularity ${bd.popularity}/5`)
      );

      console.log('');
    }
  }

  if (!verbose) console.log('');
}

/**
 * Renders the install script auditing section.
 * Flags packages with preinstall/install/postinstall lifecycle scripts.
 */
function renderInstallScriptSection(chalk: ChalkInstance, result: InstallScriptResult, verbose: boolean): void {
  console.log(
    chalk.bold.blue('  Install Scripts') +
    chalk.dim(` — scanned ${result.scanned} packages`)
  );
  console.log('');

  if (result.findings.length === 0) {
    console.log(chalk.green('  ✓ No lifecycle install scripts detected.'));
    console.log('');
    return;
  }

  const RISK_COLOR: Record<string, (s: string) => string> = {
    high:          (s) => chalk.redBright.bold(s),
    medium:        (s) => chalk.yellow(s),
    informational: (s) => chalk.cyan(s),
  };

  const COL_RISK = 10;
  const COL_PKG  = 30;
  const COL_HOOK = 14;

  console.log(
    chalk.dim('  ' +
      'RISK'.padEnd(COL_RISK) +
      'PACKAGE'.padEnd(COL_PKG) +
      'HOOK'.padEnd(COL_HOOK) +
      'REASON'
    )
  );
  console.log(chalk.dim('  ' + '─'.repeat(90)));

  for (const f of result.findings) {
    const colorFn    = RISK_COLOR[f.risk] ?? RISK_COLOR['informational'];
    const riskCol    = colorFn(f.risk.toUpperCase().padEnd(COL_RISK));
    const packageCol = chalk.white(`${f.name}@${f.version}`.padEnd(COL_PKG));
    const hookCol    = chalk.dim(f.scriptType.padEnd(COL_HOOK));
    const reason     = chalk.dim(f.riskReason);

    console.log(`  ${riskCol}${packageCol}${hookCol}${reason}`);

    if (verbose) {
      _indent(chalk, chalk.dim('Script: ') + f.truncated);
      _indent(chalk, chalk.dim('npm:    ') + f.npmUrl);
      console.log('');
    }
  }

  if (!verbose) console.log('');
}

/**
 * Renders the abandoned package detection section.
 * Flags packages with no recent publishes or archived repos.
 */
function renderAbandonedSection(chalk: ChalkInstance, result: AbandonedResult, verbose: boolean): void {
  console.log(
    chalk.bold.blue('  Abandoned Packages') +
    chalk.dim(` — scanned ${result.scanned} dependencies`)
  );
  console.log('');

  if (result.findings.length === 0) {
    console.log(chalk.green('  ✓ No abandoned packages detected.'));
    console.log('');
    return;
  }

  const COL_RISK = 10;
  const COL_PKG  = 30;

  console.log(
    chalk.dim('  ' +
      'RISK'.padEnd(COL_RISK) +
      'PACKAGE'.padEnd(COL_PKG) +
      'REASONS'
    )
  );
  console.log(chalk.dim('  ' + '─'.repeat(80)));

  for (const f of result.findings) {
    const colorFn = f.risk === 'high'
      ? (s: string) => chalk.redBright.bold(s)
      : (s: string) => chalk.yellow(s);

    const riskCol    = colorFn(f.risk.toUpperCase().padEnd(COL_RISK));
    const packageCol = chalk.white(`${f.name}@${f.version}`.padEnd(COL_PKG));
    const reasons    = chalk.dim(f.reasons.join(' · '));

    console.log(`  ${riskCol}${packageCol}${reasons}`);

    if (verbose) {
      _indent(chalk, chalk.dim('npm:    ') + f.npmUrl);
      if (f.githubUrl) {
        _indent(chalk, chalk.dim('GitHub: ') + f.githubUrl);
      }
      console.log('');
    }
  }

  if (!verbose) console.log('');
}

/** Builds a compact signal summary string for one maintainer finding. */
function _buildMaintainerSignalSummary(f: MaintainerFinding): string {
  const parts: string[] = [];

  if (f.signals.daysSincePublish !== null) {
    const days = f.signals.daysSincePublish;
    if (days > 365) {
      const years = (days / 365).toFixed(1);
      parts.push(`Last publish: ${years}y ago`);
    } else {
      parts.push(`Last publish: ${days}d ago`);
    }
  }

  parts.push(`${f.signals.maintainerCount} maintainer${f.signals.maintainerCount !== 1 ? 's' : ''}`);

  if (f.signals.maintainerChanged) {
    parts.push(`Publisher changed (was: ${f.signals.previousPublisher ?? 'unknown'})`);
  }

  if (!f.signals.hasGitHub) {
    parts.push('No GitHub');
  } else {
    if (f.signals.isArchived) {
      parts.push('Archived repo');
    } else if (f.signals.daysSinceLastCommit !== null && f.signals.daysSinceLastCommit > 180) {
      const years = (f.signals.daysSinceLastCommit / 365).toFixed(1);
      parts.push(`Last commit: ${years}y ago`);
    }
    if (f.signals.githubStars !== null) {
      parts.push(`Stars: ${f.signals.githubStars.toLocaleString()}`);
    }
  }

  return parts.join(' · ');
}

/**
 * Safe typed chalk colour accessor.
 * Falls back to `chalk` itself (no colour) if the key doesn't exist, instead
 * of returning undefined and crashing at `.bold()`.
 */
function _chalkColor(chalk: ChalkInstance, color: string): ChalkInstance {
  const fn = (chalk as unknown as Record<string, unknown>)[color];
  return typeof fn === 'function' ? fn as ChalkInstance : chalk;
}

/** Prints a single verbose detail line indented under a finding row. */
function _indent(chalk: ChalkInstance, line: string): void {
  console.log(chalk.dim('    ↳ ') + line);
}

/** Prints the summary footer line. */
function printSummary(
  chalk: ChalkInstance,
  totalScanned: number,
  findings: TyposquatFinding[],
  cveResult: CveResult | null,
  licenseResult: LicenseResult | null,
  maintainerResult: MaintainerResult | null,
  installScriptResult: InstallScriptResult | null,
  abandonedResult: AbandonedResult | null,
  durationMs: number,
): void {
  const critical = findings.filter(f => f.confidence === 'high').length;
  const high     = findings.filter(f => f.confidence === 'medium').length;
  const medium   = findings.filter(f => f.confidence === 'low').length;
  const clean    = totalScanned - findings.length;

  const parts: string[] = [];
  if (critical > 0) parts.push(chalk.redBright.bold(`${critical} critical`));
  if (high > 0)     parts.push(chalk.red(`${high} high`));
  if (medium > 0)   parts.push(chalk.yellow(`${medium} medium`));
  parts.push(chalk.green(`${clean} clean`));

  if (cveResult && cveResult.findings.length > 0) {
    const cveCritical = cveResult.findings.filter(f => f.topSeverity.toUpperCase() === 'CRITICAL').length;
    const cveHigh     = cveResult.findings.filter(f => f.topSeverity.toUpperCase() === 'HIGH').length;
    const cveOther    = cveResult.findings.length - cveCritical - cveHigh;
    if (cveCritical > 0) parts.push(chalk.redBright.bold(`${cveCritical} critical CVE${cveCritical > 1 ? 's' : ''}`));
    if (cveHigh > 0)     parts.push(chalk.red(`${cveHigh} high CVE${cveHigh > 1 ? 's' : ''}`));
    if (cveOther > 0)    parts.push(chalk.yellow(`${cveOther} CVE${cveOther > 1 ? 's' : ''}`));
  }

  if (licenseResult) {
    if (licenseResult.conflicts > 0) {
      parts.push(chalk.redBright.bold(`${licenseResult.conflicts} license conflict${licenseResult.conflicts > 1 ? 's' : ''}`));
    }
    if (licenseResult.warnings > 0) {
      parts.push(chalk.yellow(`${licenseResult.warnings} license warning${licenseResult.warnings > 1 ? 's' : ''}`));
    }
  }

  if (maintainerResult) {
    if (maintainerResult.highRisk > 0) {
      parts.push(chalk.redBright.bold(`${maintainerResult.highRisk} high-risk maintainer${maintainerResult.highRisk > 1 ? 's' : ''}`));
    }
    if (maintainerResult.mediumRisk > 0) {
      parts.push(chalk.yellow(`${maintainerResult.mediumRisk} medium-risk maintainer${maintainerResult.mediumRisk > 1 ? 's' : ''}`));
    }
  }

  if (installScriptResult) {
    if (installScriptResult.highRisk > 0) {
      parts.push(chalk.redBright.bold(`${installScriptResult.highRisk} high-risk script${installScriptResult.highRisk > 1 ? 's' : ''}`));
    }
    if (installScriptResult.mediumRisk > 0) {
      parts.push(chalk.yellow(`${installScriptResult.mediumRisk} medium-risk script${installScriptResult.mediumRisk > 1 ? 's' : ''}`));
    }
  }

  if (abandonedResult) {
    if (abandonedResult.highRisk > 0) {
      parts.push(chalk.redBright.bold(`${abandonedResult.highRisk} abandoned (high)`));
    }
    if (abandonedResult.mediumRisk > 0) {
      parts.push(chalk.yellow(`${abandonedResult.mediumRisk} abandoned (medium)`));
    }
  }

  console.log(
    chalk.dim('  Summary: ') +
    parts.join(chalk.dim(' · ')) +
    chalk.dim(`  (${durationMs}ms)`)
  );
  console.log('');
}

// ─── Check command renderer ────────────────────────────────────────────────

/**
 * Renders a full `safedeps check` report for a single package.
 */
export async function renderCheckReport(report: CheckReport): Promise<void> {
  const chalk = await getChalk();

  const {
    name, requestedVersion, resolvedVersion, license,
    weeklyDownloads, ageInDays, publishedVersions, maintainerNames,
    typosquatFinding, cveResult, licenseResult, maintainerResult, durationMs, verbose = false,
  } = report;

  const displayVersion = requestedVersion ?? resolvedVersion;

  console.log('');
  console.log(
    chalk.bold.blue('  SafeDeps') +
    chalk.dim(` v${pkg.version}`) +
    chalk.dim(' — checking: ') +
    chalk.bold(`${name}@${displayVersion}`)
  );
  if (requestedVersion && requestedVersion !== resolvedVersion) {
    console.log(chalk.dim(`             resolved → ${resolvedVersion}`));
  }
  console.log('');

  // ── Package Information ────────────────────────────────────────────────
  console.log(chalk.bold.blue('  Package Information'));
  console.log('');

  const kv = (key: string, value: string) =>
    `  ${chalk.dim(key.padEnd(22))}${chalk.white(value)}`;

  console.log(kv('Name', name));
  console.log(kv('Version', resolvedVersion));
  if (license) {
    console.log(kv('License', license));
  }
  if (weeklyDownloads !== null) {
    console.log(kv('Weekly downloads', weeklyDownloads.toLocaleString()));
  }
  if (ageInDays !== null) {
    const years  = Math.floor(ageInDays / 365);
    const months = Math.floor((ageInDays % 365) / 30);
    const ageStr = years > 0
      ? `${years}y ${months}m ago`
      : months > 0 ? `${months}m ago` : `${ageInDays}d ago`;
    console.log(kv('First published', ageStr));
  }
  if (publishedVersions !== null) {
    console.log(kv('Published versions', String(publishedVersions)));
  }
  if (maintainerNames.length > 0) {
    console.log(kv('Maintainers', maintainerNames.join(', ')));
  }
  console.log('');

  // ── Typosquat Analysis ────────────────────────────────────────────────
  console.log(chalk.bold.blue('  Typosquat Analysis'));
  console.log('');

  if (!typosquatFinding) {
    console.log(chalk.green('  ✓ Not similar to any known top package.'));
  } else {
    const auth = typosquatFinding.authenticity;

    if (auth?.existsOnNpm === false) {
      const { label, color } = CONFIDENCE_MAP[typosquatFinding.confidence] ?? { label: 'CRITICAL', color: 'redBright' };
      const colorFn = _chalkColor(chalk, color);
      console.log(
        `  ${colorFn.bold(label)} ` +
        chalk.white(`"${name}"`) +
        chalk.dim(` — package does not exist on npm (potential placeholder/malicious registration)`)
      );
    } else if (auth?.dismissed) {
      console.log(chalk.green(
        `  ✓ Name is similar to "${typosquatFinding.match}" but dismissed as false positive.`
      ));
      console.log(chalk.dim(
        `    Reason: ${(auth.weeklyDownloads ?? 0).toLocaleString()} downloads/week indicates high npm adoption.`
      ));
    } else {
      const { label, color } = CONFIDENCE_MAP[typosquatFinding.confidence] ?? { label: 'MEDIUM', color: 'yellow' };
      const colorFn = _chalkColor(chalk, color);

      console.log(
        `  ${colorFn.bold(label)} ` +
        chalk.white(`"${name}"`) +
        chalk.dim(' — did you mean ') +
        chalk.green.bold(`"${typosquatFinding.match}"`) +
        chalk.dim(`? (${typosquatFinding.method}, distance: ${typosquatFinding.distance})`)
      );

      if (auth) {
        const verdictColor =
          auth.verdict === 'likely-legitimate' ? chalk.green
          : auth.verdict === 'uncertain'       ? chalk.yellow
          : chalk.redBright;

        const signals: string[] = [];
        if (auth.weeklyDownloads !== null) {
          signals.push(`${auth.weeklyDownloads.toLocaleString()} downloads/week`);
        }
        if (auth.ageInDays !== null) {
          const y = Math.floor(auth.ageInDays / 365);
          const m = Math.floor((auth.ageInDays % 365) / 30);
          signals.push(y > 0 ? `${y}y ${m}m old` : `${auth.ageInDays}d old`);
        }
        const signalStr = signals.length > 0 ? chalk.dim(` (${signals.join(', ')})`) : '';
        console.log(`    Authenticity: ${verdictColor(auth.verdict)}${signalStr}`);
      }
    }
  }
  console.log('');

  // ── CVE Vulnerabilities ───────────────────────────────────────────────
  if (cveResult) {
    renderCveSection(chalk, cveResult, verbose);
  }

  // ── License Compliance ────────────────────────────────────────────────
  if (licenseResult) {
    renderLicenseSection(chalk, licenseResult, verbose);
  }

  // ── Maintainer Health ─────────────────────────────────────────────────
  if (maintainerResult) {
    renderMaintainerSection(chalk, maintainerResult, verbose);
  }

  console.log(chalk.dim(`  Completed in ${durationMs}ms`));
  console.log('');
}
