import { queryOSV } from '../sources/osv';
import type { OsvPackage, OsvResult } from '../sources/osv';
import { parseLockfile } from '../utils/lockfileParser';
import { normaliseVuln } from '../utils/severity';
import type { NormalisedVuln } from '../utils/severity';
import type { ParsedPackageJson } from '../utils/packageParser';

export interface CveFinding {
  name:          string;
  version:       string;
  versionSource: 'lockfile' | 'range-floor' | 'unknown';
  vulnCount:     number;
  topSeverity:   string;
  vulns:         NormalisedVuln[];
  // Verbose-enrichment fields (derived from top-severity vuln, always populated)
  aliases?:       string[];
  cvssScore?:     number | null;
  cvssVector?:    string | null;
  affectedRange?: string | null;
  fixedIn?:       string | null;
  published?:     string | null;
  details?:       string | null;
}

export interface CveResult {
  findings: CveFinding[];
  scanned: number;
  skipped: number;
  error?: string;
}

export interface ScanCveOptions {
  projectPath?:   string;
  minSeverity?:   string;
  lockVersions?:  Map<string, string>;
  /**
   * Full list of installed packages (direct + transitive) from the lockfile.
   * When provided, CVE scanning covers all of node_modules — not just the
   * packages listed in package.json — matching the behaviour of `npm audit`.
   */
  lockfilePackages?: Array<{ name: string; version: string }>;
  /** Injectable OSV query function — used in tests to avoid real HTTP calls. */
  queryFn?:       (packages: OsvPackage[]) => Promise<OsvResult[]>;
}

/**
 * CVE Vulnerability Detector
 *
 * Scans all project dependencies against the OSV.dev vulnerability database.
 *
 * Strategy:
 *   1. Read resolved versions from package-lock.json (most accurate)
 *   2. Fall back to version ranges from package.json if no lockfile
 *   3. Batch-query OSV.dev API (single HTTP request for all packages)
 *   4. Normalise and return structured findings
 */
export async function scanCVEs(
  parsedPackageJson: ParsedPackageJson,
  options: ScanCveOptions = {}
): Promise<CveResult> {
  const {
    projectPath = process.cwd(),
    minSeverity = 'low',
    lockVersions: lockVersionsOpt,
    lockfilePackages,
    queryFn = queryOSV,
  } = options;

  const toScan: OsvPackage[] = [];
  const skipped: string[]    = [];
  const versionSourceMap     = new Map<string, CveFinding['versionSource']>();

  if (lockfilePackages && lockfilePackages.length > 0) {
    // Fast path: full lockfile list provided — all packages have exact versions
    for (const { name, version } of lockfilePackages) {
      versionSourceMap.set(name, 'lockfile');
      toScan.push({ name, version });
    }
  } else {
    // Fallback: resolve versions for direct deps only (no lockfile available)
    const lockVersions = lockVersionsOpt ?? parseLockfile(projectPath);
    const allPackageNames = parsedPackageJson.allPackages;
    const allDeps: Record<string, string> = {
      ...parsedPackageJson.dependencies,
      ...parsedPackageJson.devDependencies,
      ...parsedPackageJson.peerDependencies,
      ...parsedPackageJson.optionalDependencies,
    };

    for (const name of allPackageNames) {
      const lockVersion = lockVersions.get(name);
      let version: string | undefined;
      let source: CveFinding['versionSource'];

      if (lockVersion) {
        version = lockVersion;
        source  = 'lockfile';
      } else {
        const rawVersion = allDeps[name] ?? '';
        const resolved   = _resolveVersionRange(rawVersion) ?? undefined;
        version = resolved;
        source  = resolved ? 'range-floor' : 'unknown';
      }

      if (!version) {
        skipped.push(name);
        continue;
      }

      versionSourceMap.set(name, source);
      toScan.push({ name, version });
    }
  }

  if (toScan.length === 0) {
    return { findings: [], scanned: 0, skipped: skipped.length };
  }

  // 2. Query OSV.dev in a single batch request
  let osvResults;
  try {
    osvResults = await queryFn(toScan);
  } catch (err) {
    throw new Error(`CVE scan failed: ${(err as Error).message}`);
  }

  // 3. Build findings from OSV results
  const severityOrder = ['critical', 'high', 'medium', 'low', 'unknown'];
  const minIdx        = severityOrder.indexOf(minSeverity.toLowerCase());

  const findings: CveFinding[] = [];

  for (const result of osvResults) {
    if (!result.vulns || result.vulns.length === 0) continue;

    // Normalise each vulnerability
    const normalisedVulns = result.vulns.map(normaliseVuln);

    // Filter by minSeverity
    // UNKNOWN vulns (MAL-*, many GHSA advisories) always pass — severity is indeterminate
    const filtered = normalisedVulns.filter(v => {
      const sev = v.severity.toLowerCase();
      if (sev === 'unknown') return true;
      const idx = severityOrder.indexOf(sev);
      return idx !== -1 && idx <= minIdx;
    });

    if (filtered.length === 0) continue;

    // Sort vulns by severity (critical first)
    filtered.sort((a, b) =>
      severityOrder.indexOf(a.severity.toLowerCase()) -
      severityOrder.indexOf(b.severity.toLowerCase())
    );

    const topVuln = filtered[0];
    findings.push({
      name:          result.name,
      version:       result.version,
      versionSource: versionSourceMap.get(result.name) ?? 'unknown',
      vulnCount:     filtered.length,
      topSeverity:   topVuln.severity,
      vulns:         filtered,
      aliases:       topVuln.aliases.length > 0 ? topVuln.aliases : undefined,
      cvssScore:     topVuln.cvssScore,
      cvssVector:    topVuln.cvssVector,
      affectedRange: topVuln.affectedRange,
      fixedIn:       topVuln.fixedIn[0] ?? null,
      published:     topVuln.published,
      details:       topVuln.details,
    });
  }

  // Sort findings by severity (critical packages first)
  findings.sort((a, b) =>
    severityOrder.indexOf(a.topSeverity.toLowerCase()) -
    severityOrder.indexOf(b.topSeverity.toLowerCase())
  );

  return {
    findings,
    scanned: toScan.length,
    skipped: skipped.length,
  };
}

/**
 * Resolves a package.json version range string to a concrete semver version
 * suitable for querying OSV.dev.
 *
 * Handles the common forms found in package.json:
 *   ^1.2.3  ~1.2.3  >=1.2.3  1.2.3           → 1.2.3
 *   1.x  1.x.x  1.2.x                         → 1.0.0 / 1.2.0
 *   >=1.0.0 <2.0.0  ^1.0.0 || ^2.0.0          → first clean version found
 *   workspace:^1.0.0                           → strip workspace: prefix first
 *   file:../pkg  git+https://...  link:../pkg  → returns null (skip)
 *   *  ""                                      → returns null (skip)
 *
 * Returns null when the range cannot be resolved to a valid version — the
 * caller should skip that package rather than send garbage to OSV.
 */
export function _resolveVersionRange(raw: string): string | null {
  if (!raw || raw.trim() === '') return null;

  let s = raw.trim();

  // Strip workspace: protocol (yarn/pnpm workspaces)
  if (s.startsWith('workspace:')) s = s.slice('workspace:'.length).trim();

  // Skip protocols that are not semver ranges
  if (/^(file:|link:|portal:|git\+|git:|github:|https?:|[a-zA-Z]:\\|\.\/|\.\.\/)/.test(s)) return null;

  // Skip npm package aliases: "npm:other-package@^1.0"
  if (s.startsWith('npm:')) {
    const atIdx = s.lastIndexOf('@');
    if (atIdx > 4) s = s.slice(atIdx + 1);
    else return null;
  }

  // Wildcard / any
  if (s === '*' || s === 'x' || s === '') return null;

  // Split OR expressions and take the first resolvable term
  if (s.includes('||')) {
    for (const term of s.split('||')) {
      const resolved = _resolveVersionRange(term.trim());
      if (resolved) return resolved;
    }
    return null;
  }

  // Take the first space-separated token (handles ">=1.0.0 <2.0.0" → ">=1.0.0")
  const firstToken = s.split(/\s+/)[0];

  // Strip leading range specifiers
  const stripped = firstToken.replace(/^[~^>=<!]+/, '').trim();

  // Replace wildcard segments: 1.x → 1.0.0, 1.2.x → 1.2.0, 1.x.x → 1.0.0
  const resolved = stripped
    .replace(/\.x\.x$/i, '.0.0')
    .replace(/^(\d+)\.x$/i, '$1.0.0')
    .replace(/\.x$/i,    '.0')
    .replace(/^(\d+)\.x$/i, '$1.0.0');

  // Must start with at least one digit and look like a semver
  if (!/^\d/.test(resolved) || resolved === '') return null;

  // Must have at least major.minor (two numeric segments)
  if (!/^\d+\.\d+/.test(resolved)) return null;

  return resolved;
}
