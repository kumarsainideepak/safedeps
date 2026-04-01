import pkg from '../../package.json';
import type { TyposquatFinding } from '../detectors/typosquat';
import type { CveResult } from '../detectors/cve';
import type { LicenseResult } from '../detectors/license';
import type { MaintainerResult, MaintainerFinding } from '../detectors/maintainer';

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
  maintainerResult: MaintainerResult | null;
  durationMs:       number;
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
    _chalk = (await import('chalk')).default;
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
  projectName:       string;
  totalScanned:      number;
  typosquatFindings: TyposquatFinding[];
  cveResult:         CveResult | null;
  licenseResult:     LicenseResult | null;
  maintainerResult:  MaintainerResult | null;
  durationMs:        number;
}

/**
 * Renders a full scan report (typosquat + CVE + license + maintainer) to stdout.
 */
export async function renderFullReport(scanResult: ScanResult): Promise<void> {
  const chalk = await getChalk();

  const { projectName, totalScanned, typosquatFindings, cveResult, licenseResult, maintainerResult, durationMs } = scanResult;

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
      renderCveSection(chalk, cveResult);
    }

    if (licenseResult) {
      renderLicenseSection(chalk, licenseResult);
    }

    if (maintainerResult) {
      renderMaintainerSection(chalk, maintainerResult);
    }

    printSummary(chalk, totalScanned, typosquatFindings, cveResult, licenseResult, maintainerResult, durationMs);
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
    renderCveSection(chalk, cveResult);
  }

  // ── License section ────────────────────────────────────────────────────
  if (licenseResult) {
    renderLicenseSection(chalk, licenseResult);
  }

  // ── Maintainer section ─────────────────────────────────────────────────
  if (maintainerResult) {
    renderMaintainerSection(chalk, maintainerResult);
  }

  printSummary(chalk, totalScanned, typosquatFindings, cveResult, licenseResult, maintainerResult, durationMs);
}

/** Builds the human-readable finding message for one typosquat result. */
function buildFindingMessage(chalk: ChalkInstance, finding: TyposquatFinding): string {
  const methodLabel: Record<string, string> = {
    levenshtein: 'character similarity',
    soundex:     'phonetic similarity',
    both:        'character + phonetic similarity',
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
function renderCveSection(chalk: ChalkInstance, result: CveResult): void {
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
    UNKNOWN:  (s) => chalk.dim(s),
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

    // Show fix version if available
    const firstFix = cveFinding.vulns.find(v => v.fixedIn.length > 0);
    if (firstFix) {
      console.log(chalk.dim(`  ${''.padEnd(COL_SEV + COL_PKG)}Fix available: `) + chalk.green(firstFix.fixedIn[0]));
    }
  }

  console.log('');
}

/**
 * Renders the license compliance section.
 * Only prints packages with conflict / warning / unknown status — clean
 * packages are counted in the summary line to keep output readable.
 */
function renderLicenseSection(chalk: ChalkInstance, result: LicenseResult): void {
  console.log(
    chalk.bold.blue('  License Compliance') +
    chalk.dim(` — project: `) +
    chalk.white(result.projectLicense) +
    chalk.dim(`, scanned ${result.scanned} dependencies`)
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
  }

  console.log('');
}

/**
 * Renders the maintainer health section.
 * Only prints packages with high or medium risk — healthy ones are counted in summary.
 */
function renderMaintainerSection(chalk: ChalkInstance, result: MaintainerResult): void {
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

    console.log(`  ${riskCol}${packageCol}${scoreCol}${signals}`);
  }

  console.log('');
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

/** Prints the summary footer line. */
function printSummary(
  chalk: ChalkInstance,
  totalScanned: number,
  findings: TyposquatFinding[],
  cveResult: CveResult | null,
  licenseResult: LicenseResult | null,
  maintainerResult: MaintainerResult | null,
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
    typosquatFinding, cveResult, maintainerResult, durationMs,
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

    if (auth?.dismissed) {
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
    renderCveSection(chalk, cveResult);
  }

  // ── Maintainer Health ─────────────────────────────────────────────────
  if (maintainerResult) {
    renderMaintainerSection(chalk, maintainerResult);
  }

  console.log(chalk.dim(`  Completed in ${durationMs}ms`));
  console.log('');
}
