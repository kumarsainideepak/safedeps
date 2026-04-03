import fs from 'fs';
import path from 'path';
import { parseLockfile } from '../utils/lockfileParser';
import {
  normaliseLicense,
  classifyLicense,
  checkCompatibility,
} from '../utils/spdxCompatibility';
import { batchFetchLicenses } from '../sources/npmRegistry';
import type { ParsedPackageJson } from '../utils/packageParser';
import type { LicenseCategory, CompatibilityStatus } from '../utils/spdxCompatibility';

/**
 * License Compliance Detector
 *
 * For each production dependency:
 *   1. Reads the license from node_modules/<name>/package.json  (fast, offline, exact)
 *   2. Falls back to the npm registry API if the package isn't installed locally
 *   3. Normalises the raw string to a canonical SPDX identifier
 *   4. Checks compatibility against the project's declared license
 *
 * Only `dependencies` are scanned by default — devDependencies are not
 * distributed with the published package, so they don't create license obligations.
 */

// ─── Public types ──────────────────────────────────────────────────────────

export interface LicenseFinding {
  name:                      string;
  version:                   string;
  rawLicense:                string;
  normalizedLicense:         string;
  category:                  LicenseCategory;
  status:                    CompatibilityStatus;
  reason:                    string;
  // Verbose-enrichment fields
  spdxUrl?:                  string | null;
  tldrUrl?:                  string | null;
  compatibilityExplanation?: string | null;
}

export interface LicenseResult {
  projectLicense:  string;
  findings:        LicenseFinding[];
  scanned:         number;
  conflicts:       number;
  warnings:        number;
  unknowns:        number;
  includesDevDeps: boolean;
  error?:          string;
}

export interface ScanLicenseOptions {
  projectPath?:    string;
  projectLicense?: string;  // override from --license flag
  lockVersions?:   Map<string, string>;
  /** When true, include devDependencies in the scan. Default: false. */
  includeDevDeps?: boolean;
}

// ─── Internal helpers ──────────────────────────────────────────────────────

/**
 * Reads a package's license from its installed node_modules/package.json.
 * Returns null if the package is not installed or the file can't be parsed.
 *
 * Handles three historical package.json license formats:
 *   - String:   "MIT"
 *   - Object:   { "type": "MIT", "url": "..." }   (deprecated)
 *   - Array:    [{ "type": "MIT" }]               (very old npm packages)
 */
function readLocalLicense(projectPath: string, packageName: string): string | null {
  const nodeModulesDir = path.resolve(projectPath, 'node_modules');
  const pkgPath = path.resolve(nodeModulesDir, packageName, 'package.json');
  // Guard against path traversal via package names like "../../.env"
  if (!pkgPath.startsWith(nodeModulesDir + path.sep)) return null;
  if (!fs.existsSync(pkgPath)) return null;

  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }

  if (typeof raw.license === 'string')  return raw.license || null;

  if (raw.license && typeof raw.license === 'object' && !Array.isArray(raw.license)) {
    return (raw.license as { type?: string }).type ?? null;
  }

  if (Array.isArray(raw.licenses) && raw.licenses.length > 0) {
    const first = raw.licenses[0] as Record<string, string>;
    return first.type ?? first.name ?? null;
  }

  return null;
}

// ─── Verbose-enrichment helpers ────────────────────────────────────────────

/** Maps well-known SPDX IDs to their tldrlegal.com slug. */
const TLDR_SLUGS: Record<string, string> = {
  'MIT':                  'mit-license',
  'Apache-2.0':           'apache-license-2.0-apache',
  'GPL-2.0-only':         'gnu-gpl-v2',
  'GPL-2.0-or-later':     'gnu-gpl-v2',
  'GPL-3.0-only':         'gnu-gpl-v3',
  'GPL-3.0-or-later':     'gnu-gpl-v3',
  'LGPL-2.0-only':        'gnu-lgpl-v2',
  'LGPL-2.1-only':        'gnu-lesser-general-public-license-v2-1-lgpl-2-1',
  'LGPL-3.0-only':        'gnu-lgpl-v3',
  'AGPL-3.0-only':        'gnu-affero-general-public-license-v3-agpl-3-0',
  'ISC':                  'isc-license',
  'BSD-2-Clause':         'bsd-2-clause-license-simplified',
  'BSD-3-Clause':         'bsd-3-clause-license-revised',
  'MPL-2.0':              'mozilla-public-license-2-0-mpl-2',
  'CDDL-1.0':             'common-development-and-distribution-license-cddl-1',
  'EPL-1.0':              'eclipse-public-license-1-0',
  'EPL-2.0':              'eclipse-public-license-2-0',
  'CC0-1.0':              'creative-commons-cc0-1-0-universal',
  'Unlicense':            'the-unlicense-wtfpl',
  'WTFPL':                'do-what-the-fuck-you-want-to-public-license-wtfpl',
  'EUPL-1.2':             'european-union-public-licence-eupl-v-1-2',
};

function _buildSpdxUrl(normalizedLicense: string): string | null {
  if (normalizedLicense === 'UNKNOWN' || normalizedLicense === 'none') return null;
  // Strip expressions like "MIT OR Apache-2.0" — only link single identifiers
  if (/\s+(OR|AND)\s+/i.test(normalizedLicense)) return null;
  const id = normalizedLicense.replace(/[()]/g, '').trim();
  return `https://spdx.org/licenses/${encodeURIComponent(id)}.html`;
}

function _buildTldrUrl(normalizedLicense: string): string | null {
  const slug = TLDR_SLUGS[normalizedLicense];
  return slug ? `https://www.tldrlegal.com/license/${slug}` : null;
}

/**
 * Returns a plain-English explanation of why a license conflict or warning exists.
 * Keyed by (projectCategory, depCategory) pair. Returns null for 'ok' status.
 */
function _buildCompatibilityExplanation(
  projectLicense: string,
  depLicense: string,
  projectCategory: LicenseCategory,
  depCategory: LicenseCategory,
  status: CompatibilityStatus,
): string | null {
  if (status === 'ok') return null;

  if (status === 'unknown') {
    return `The license "${depLicense}" could not be classified. Manual review is required to confirm compatibility with your project license (${projectLicense}).`;
  }

  const key = `${projectCategory}:${depCategory}` as const;

  const EXPLANATIONS: Record<string, string> = {
    'permissive:strong-copyleft':
      `"${depLicense}" is a strong copyleft license. Linking it into a project licensed under "${projectLicense}" (permissive) may require you to relicense the combined work under "${depLicense}". Consult your legal team before distributing.`,
    'permissive:network-copyleft':
      `"${depLicense}" is a network-copyleft license (e.g. AGPL). If your "${projectLicense}"-licensed service uses this dependency and is accessible over a network, you may be required to publish your complete source code.`,
    'permissive:weak-copyleft':
      `"${depLicense}" is a weak copyleft license. Modifications to the library itself must be shared, but it can generally be used as a dependency in a "${projectLicense}"-licensed project. Verify with your legal team.`,
    'weak-copyleft:strong-copyleft':
      `"${depLicense}" is a strong copyleft license. Using it in a "${projectLicense}"-licensed project may require the entire combined work to be relicensed. Consult your legal team.`,
    'weak-copyleft:network-copyleft':
      `"${depLicense}" is a network-copyleft (AGPL-family) license. If this service is accessible over a network, you may be required to release all source code, including your "${projectLicense}"-licensed code.`,
    'strong-copyleft:network-copyleft':
      `"${depLicense}" imposes network-copyleft obligations that extend beyond what "${projectLicense}" requires. The combination may conflict — seek legal advice.`,
    'network-copyleft:strong-copyleft':
      `"${depLicense}" is a strong copyleft license but does not include the network-use trigger of your project license ("${projectLicense}"). The combination may conflict — seek legal advice.`,
  };

  return EXPLANATIONS[key] ?? `"${depLicense}" (${depCategory}) may be incompatible with your project license "${projectLicense}" (${projectCategory}). Status: ${status}. Consult your legal team.`;
}

// ─── Main scanner ──────────────────────────────────────────────────────────

export async function scanLicenses(
  parsedPackageJson: ParsedPackageJson,
  options: ScanLicenseOptions = {},
): Promise<LicenseResult> {
  const {
    projectPath    = process.cwd(),
    projectLicense: licenseOverride,
    lockVersions:  lockVersionsOpt,
    includeDevDeps = false,
  } = options;

  // Determine the project's own license (CLI flag wins over package.json)
  const projectLicense = normaliseLicense(licenseOverride ?? parsedPackageJson.license);

  // Only scan production dependencies by default; devDeps don't ship with the package
  const packagesToScan = includeDevDeps
    ? Object.keys({ ...parsedPackageJson.dependencies, ...parsedPackageJson.devDependencies })
    : Object.keys(parsedPackageJson.dependencies);

  if (packagesToScan.length === 0) {
    return { projectLicense, findings: [], scanned: 0, conflicts: 0, warnings: 0, unknowns: 0, includesDevDeps: includeDevDeps };
  }

  const lockVersions = lockVersionsOpt ?? parseLockfile(projectPath);

  // ── Phase 1: Read from node_modules (no network) ────────────────────────
  const licenseMap = new Map<string, string | null>();
  const needNetwork: Array<{ name: string; version?: string }> = [];

  for (const name of packagesToScan) {
    const local = readLocalLicense(projectPath, name);
    if (local !== null) {
      licenseMap.set(name, local);
    } else {
      needNetwork.push({ name, version: lockVersions.get(name) });
    }
  }

  // ── Phase 2: Fetch remaining from npm registry ───────────────────────────
  if (needNetwork.length > 0) {
    try {
      const fetched = await batchFetchLicenses(needNetwork);
      for (const [name, license] of fetched) {
        licenseMap.set(name, license);
      }
    } catch {
      // Network failure — mark unresolved packages as null (shown as unknown)
      for (const { name } of needNetwork) {
        if (!licenseMap.has(name)) licenseMap.set(name, null);
      }
    }
  }

  // ── Phase 3: Build findings ─────────────────────────────────────────────
  const findings: LicenseFinding[] = [];

  for (const name of packagesToScan) {
    const rawLicense        = licenseMap.get(name) ?? null;
    const normalizedLicense = normaliseLicense(rawLicense);
    const category          = classifyLicense(normalizedLicense);
    const version           = lockVersions.get(name) ?? '(unknown)';
    let { status, reason } = checkCompatibility(projectLicense, normalizedLicense);

    // If the raw license is an OR expression and we picked the permissive term,
    // annotate the reason so reviewers know the full picture.
    if (rawLicense && /\s+OR\s+/i.test(rawLicense) && status === 'ok') {
      const terms = rawLicense.split(/\s+OR\s+/i).map(t => t.replace(/[()]/g, '').trim());
      if (terms.length > 1) {
        reason = `Dual-licensed: ${rawLicense} — compatible via ${normalizedLicense}; verify with your legal team`;
      }
    }

    findings.push({
      name,
      version,
      rawLicense:               rawLicense ?? 'none',
      normalizedLicense,
      category,
      status,
      reason,
      spdxUrl:                  _buildSpdxUrl(normalizedLicense),
      tldrUrl:                  _buildTldrUrl(normalizedLicense),
      compatibilityExplanation: _buildCompatibilityExplanation(
        projectLicense, normalizedLicense,
        classifyLicense(projectLicense), category,
        status,
      ),
    });
  }

  // Sort: conflicts → warnings → unknowns → ok
  const ORDER: Record<CompatibilityStatus, number> = {
    conflict: 0,
    warning:  1,
    unknown:  2,
    ok:       3,
  };
  findings.sort((a, b) => ORDER[a.status] - ORDER[b.status]);

  const conflicts = findings.filter(f => f.status === 'conflict').length;
  const warnings  = findings.filter(f => f.status === 'warning').length;
  const unknowns  = findings.filter(f => f.status === 'unknown').length;

  return { projectLicense, findings, scanned: packagesToScan.length, conflicts, warnings, unknowns, includesDevDeps: includeDevDeps };
}
