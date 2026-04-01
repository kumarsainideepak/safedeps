/**
 * Severity normaliser
 *
 * OSV vulnerability data includes CVSS scores and severity strings from
 * multiple sources (NVD, GitHub Advisory, etc.) in varying formats.
 * This module normalises them all into a consistent severity level:
 *
 *   CRITICAL  → CVSS 9.0–10.0
 *   HIGH      → CVSS 7.0–8.9
 *   MEDIUM    → CVSS 4.0–6.9
 *   LOW       → CVSS 0.1–3.9
 *   UNKNOWN   → No score available
 */

export const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const;
export type SeverityLevel = typeof SEVERITY_LEVELS[number];

export interface OsvSeverityEntry {
  type: string;
  score: string;
}

export interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
}

export interface OsvRange {
  type: string;
  events?: OsvRangeEvent[];
}

export interface OsvAffected {
  ranges?: OsvRange[];
  versions?: string[];
  ecosystem_specific?: { severity?: string };
}

export interface OsvReference {
  type: string;
  url?: string;
}

export interface OsvVuln {
  id?: string;
  summary?: string;
  details?: string;
  severity?: OsvSeverityEntry[];
  affected?: OsvAffected[];
  references?: OsvReference[];
  database_specific?: { severity?: string };
}

export interface NormalisedVuln {
  id: string;
  title: string;
  severity: string;
  cvssScore: number | null;
  fixedIn: string[];
  url: string;
}

export function normaliseVuln(vuln: OsvVuln): NormalisedVuln {
  const id      = vuln.id ?? 'UNKNOWN';
  const title   = vuln.summary ?? vuln.details?.slice(0, 100) ?? 'No description available';
  const fixedIn = _extractFixVersions(vuln);
  const url     = _extractAdvisoryUrl(vuln, id);

  const { severity, cvssScore } = _extractSeverity(vuln);

  return { id, title, severity, cvssScore, fixedIn, url };
}

/**
 * Extracts and normalises severity + CVSS score from an OSV vuln.
 *
 * Priority order:
 *   1. CVSS V3/V2 vector string → parse base score
 *   2. database_specific.severity string → map to level
 *   3. Fall back to UNKNOWN
 */
function _extractSeverity(vuln: OsvVuln): { severity: string; cvssScore: number | null } {
  // Try CVSS vector strings first (most precise)
  if (Array.isArray(vuln.severity)) {
    for (const s of vuln.severity) {
      if (s.score) {
        const score = _parseCvssScore(s.score);
        if (score !== null) {
          return { severity: _cvssScoreToLevel(score), cvssScore: score };
        }
      }
    }
  }

  // Fall back to database_specific.severity string
  const dbSeverity = vuln.database_specific?.severity?.toUpperCase();
  if (dbSeverity && (SEVERITY_LEVELS as readonly string[]).includes(dbSeverity)) {
    return { severity: dbSeverity, cvssScore: null };
  }

  // Last resort — check ecosystem_specific
  const ecoSeverity = vuln.affected?.[0]?.ecosystem_specific?.severity?.toUpperCase();
  if (ecoSeverity && (SEVERITY_LEVELS as readonly string[]).includes(ecoSeverity)) {
    return { severity: ecoSeverity, cvssScore: null };
  }

  return { severity: 'UNKNOWN', cvssScore: null };
}

/**
 * Parses a CVSS base score from a CVSS vector string.
 *
 * Handles two formats:
 *   1. Prefixed:  "9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 *   2. Plain:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 *
 * Plain vectors are parsed using the CVSS v3.1 base score formula.
 */
function _parseCvssScore(vectorString: string): number | null {
  if (!vectorString) return null;

  // Format 1: numeric prefix "9.8 CVSS:3.1/..."
  const prefixed = vectorString.match(/^(\d+(?:\.\d+)?)\s+CVSS:/);
  if (prefixed) return parseFloat(prefixed[1]);

  // Format 2: plain CVSS:3.x vector string
  if (vectorString.startsWith('CVSS:3.')) {
    return _computeCvssV3Score(vectorString);
  }

  return null;
}

/**
 * Computes the CVSS v3.1 base score from a vector string.
 * Implements the official formula from https://www.first.org/cvss/v3.1/specification-document
 */
function _computeCvssV3Score(vectorString: string): number | null {
  // Parse metric map from "CVSS:3.1/AV:N/AC:L/..." → { AV:'N', AC:'L', ... }
  const metrics: Record<string, string> = {};
  for (const part of vectorString.split('/').slice(1)) {
    const colon = part.indexOf(':');
    if (colon !== -1) metrics[part.slice(0, colon)] = part.slice(colon + 1);
  }

  // Metric weight tables (CVSS v3.1 spec §7.1)
  const AV:  Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2  };
  const AC:  Record<string, number> = { L: 0.77, H: 0.44 };
  const UI:  Record<string, number> = { N: 0.85, R: 0.62 };
  const CIA: Record<string, number> = { N: 0.0,  L: 0.22, H: 0.56 };
  const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
  const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.50 };

  const scope = metrics['S'];
  const av    = AV[metrics['AV']];
  const ac    = AC[metrics['AC']];
  const pr    = scope === 'C' ? PR_C[metrics['PR']] : PR_U[metrics['PR']];
  const ui    = UI[metrics['UI']];
  const c     = CIA[metrics['C']];
  const i     = CIA[metrics['I']];
  const a     = CIA[metrics['A']];

  if ([av, ac, pr, ui, c, i, a].some(v => v === undefined || v === null)) return null;

  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);

  let impact: number;
  if (scope === 'U') {
    impact = 6.42 * iscBase;
  } else {
    impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }

  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;

  let raw: number;
  if (scope === 'U') {
    raw = Math.min(impact + exploitability, 10);
  } else {
    raw = Math.min(1.08 * (impact + exploitability), 10);
  }

  // Roundup: round up to 1 decimal place (CVSS spec §7.4)
  return Math.ceil(raw * 10) / 10;
}

function _cvssScoreToLevel(score: number): string {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0)    return 'LOW';
  return 'UNKNOWN';
}

/**
 * Extracts the list of versions that fix a vulnerability.
 *
 * OSV `affected[].ranges` has entries like:
 *   { type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }
 */
function _extractFixVersions(vuln: OsvVuln): string[] {
  const fixes = new Set<string>();

  for (const affected of (vuln.affected ?? [])) {
    for (const range of (affected.ranges ?? [])) {
      for (const event of (range.events ?? [])) {
        if (event.fixed) fixes.add(event.fixed);
      }
    }
  }

  return [...fixes];
}

/**
 * Builds the best advisory URL for a vulnerability.
 *
 * Preference order: GitHub Advisory > NVD > first reference URL
 */
function _extractAdvisoryUrl(vuln: OsvVuln, id: string): string {
  const refs = vuln.references ?? [];

  // Prefer GitHub Security Advisory URL
  const ghsa = refs.find(r => r.url?.includes('github.com/advisories'));
  if (ghsa?.url) return ghsa.url;

  // Then NVD
  const nvd = refs.find(r => r.url?.includes('nvd.nist.gov'));
  if (nvd?.url) return nvd.url;

  // Then any ADVISORY type
  const advisory = refs.find(r => r.type === 'ADVISORY');
  if (advisory?.url) return advisory.url;

  // Fall back: construct URL from ID
  if (id.startsWith('GHSA-')) {
    return `https://github.com/advisories/${id}`;
  }
  if (id.startsWith('CVE-')) {
    return `https://nvd.nist.gov/vuln/detail/${id}`;
  }

  return refs[0]?.url ?? '';
}

export function highestSeverity(levels: string[]): string {
  if (!levels || levels.length === 0) return 'UNKNOWN';
  for (const level of SEVERITY_LEVELS) {
    if (levels.includes(level)) return level;
  }
  return 'UNKNOWN';
}
