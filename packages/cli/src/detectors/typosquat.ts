import { levenshtein } from '../utils/levenshtein';
import { soundexMatch } from '../utils/soundex';
import { batchFetchDownloads } from '../sources/npmDownloads';
import topPackages from '../../data/top-packages.json';

/**
 * Maximum Levenshtein distance to flag as a potential typosquat.
 *
 * Distance 1 = one character edit   → very high confidence
 * Distance 2 = two character edits  → high confidence
 * Distance 3 = three character edits → medium confidence (more false positives)
 */
export const LEVENSHTEIN_THRESHOLD = 2;

/**
 * Minimum package name length to run typosquat checks against.
 * Very short names (1-2 chars) produce too many false positives.
 */
const MIN_NAME_LENGTH = 3;

/**
 * Authenticity signals fetched from npm to validate flagged packages.
 * Populated by `enrichWithAuthenticity()` after the offline typosquat scan.
 */
export interface NpmAuthenticity {
  weeklyDownloads: number | null;
  ageInDays:       number | null;  // days since first published (null = not fetched)
  /** High-level verdict after weighing the signals. */
  verdict:   'likely-legitimate' | 'uncertain' | 'suspicious';
  /** When true, the package has enough npm adoption to be dismissed as a false positive. */
  dismissed: boolean;
}

export interface TyposquatFinding {
  suspicious:    string;
  match:         string;
  distance:      number;
  method:        'levenshtein' | 'soundex' | 'both';
  confidence:    'high' | 'medium' | 'low';
  /** Populated after calling enrichWithAuthenticity(). */
  authenticity?: NpmAuthenticity;
}

export interface ScanPackagesOptions {
  knownPackages?: string[];
}

/**
 * Analyses a single package name for potential typosquatting.
 *
 * Detection strategy (two layers):
 *   1. Levenshtein distance — catches character swaps, insertions,
 *      deletions, and substitutions (e.g. lodahs ↔ lodash)
 *   2. Soundex phonetic match — catches phonetically similar names
 *      that may have different spelling (e.g. recat ↔ react)
 */
export function analysePackage(
  packageName: string,
  knownPackages: string[] = topPackages as string[]
): TyposquatFinding | null {
  const knownSet = new Set(knownPackages);
  return _analyseWithSet(packageName, knownPackages, knownSet);
}

/**
 * Internal implementation that accepts a pre-built Set for O(1) lookup.
 * Called directly from scanPackages() to avoid rebuilding the Set per package.
 */
function _analyseWithSet(
  packageName: string,
  knownPackages: string[],
  knownSet: Set<string>,
): TyposquatFinding | null {
  // Names shorter than MIN_NAME_LENGTH are excluded intentionally: a 1–2 character
  // name like "fs" or "ax" sits within Levenshtein distance 1–2 of dozens of other
  // short names, making every hit a false positive with no actionable signal.
  if (!packageName || packageName.length < MIN_NAME_LENGTH) return null;

  const name = packageName.toLowerCase().trim();

  // O(1) lookup — Set is built once per scan, not per package
  if (knownSet.has(name)) return null;

  // Scoped packages (@scope/name) live in a separate namespace — never compare
  // them against non-scoped packages to avoid false positives like @types/cors → typescript.
  const isScoped = name.startsWith('@');

  let closestMatch: string | null = null;
  let closestDist = Infinity;
  let soundexHit = false;

  for (const known of knownPackages) {
    // Skip cross-scope comparisons: scoped vs non-scoped is always a different namespace
    if (isScoped !== known.startsWith('@')) continue;

    // Skip packages that are too different in length to be a typosquat.
    if (Math.abs(name.length - known.length) > LEVENSHTEIN_THRESHOLD) continue;

    const dist = levenshtein(name, known);

    if (dist <= LEVENSHTEIN_THRESHOLD && dist < closestDist) {
      closestDist  = dist;
      closestMatch = known;
    }

    // Soundex check (only for similar-length names to cut false positives)
    if (!soundexHit && Math.abs(name.length - known.length) <= 1) {
      if (soundexMatch(name, known) && name !== known) {
        soundexHit = true;
        if (!closestMatch) {
          closestMatch = known;
          closestDist  = dist;  // `dist` was already computed at the top of this iteration
        }
      }
    }
  }

  if (!closestMatch) return null;

  // Determine detection method
  const levenshteinHit = closestDist <= LEVENSHTEIN_THRESHOLD;
  let method: 'levenshtein' | 'soundex' | 'both';
  if (levenshteinHit && soundexHit) method = 'both';
  else if (levenshteinHit)           method = 'levenshtein';
  else                               method = 'soundex';

  // Confidence based on distance
  let confidence: 'high' | 'medium' | 'low';
  if (closestDist === 1)      confidence = 'high';
  else if (closestDist === 2) confidence = 'medium';
  else                        confidence = 'low';

  return {
    suspicious: packageName,
    match:      closestMatch,
    distance:   closestDist,
    method,
    confidence,
  };
}

/**
 * Scans an array of package names for typosquatting.
 * Builds the known-packages Set once for the whole batch (O(m) instead of O(n*m)).
 */
export function scanPackages(
  packageNames: string[],
  options: ScanPackagesOptions = {}
): TyposquatFinding[] {
  // The static `data/top-packages.json` list is used by default.
  // Typosquat detection is intentionally offline-first — no network call is made here.
  // Callers can inject a custom or freshly-fetched list via `options.knownPackages`.
  const { knownPackages = topPackages as string[] } = options;
  const knownSet = new Set(knownPackages);  // built once for all packages
  const findings: TyposquatFinding[] = [];

  for (const name of packageNames) {
    const result = _analyseWithSet(name, knownPackages, knownSet);
    if (result) findings.push(result);
  }

  return findings;
}

/**
 * Enriches typosquat findings with npm authenticity signals (network call).
 *
 * For each flagged package, fetches weekly download count from the npm downloads
 * API and uses it to compute an authenticity verdict:
 *
 *   ≥ 100,000 downloads/week → dismissed (almost certainly a real package)
 *   ≥  10,000 downloads/week → likely-legitimate (low false-positive risk)
 *   ≥   1,000 downloads/week → uncertain
 *      <  1,000 downloads/week → suspicious (new/unknown package)
 *
 * Findings marked `dismissed: true` should be excluded from the final report.
 * Callers may optionally supply `ageInDays` (e.g. from a packument) for richer display.
 */
export async function enrichWithAuthenticity(
  findings: TyposquatFinding[],
  options: { concurrency?: number; ageMap?: Map<string, number> } = {},
): Promise<TyposquatFinding[]> {
  if (findings.length === 0) return findings;

  const { concurrency = 8, ageMap } = options;
  const names = findings.map(f => f.suspicious);
  const downloadsMap = await batchFetchDownloads(names, concurrency);

  return findings.map(f => {
    const weeklyDownloads = downloadsMap.get(f.suspicious) ?? null;
    const ageInDays       = ageMap?.get(f.suspicious) ?? null;

    let verdict: NpmAuthenticity['verdict'];
    let dismissed = false;

    if (weeklyDownloads === null) {
      // Could not fetch (network error or package doesn't exist on npm)
      verdict   = 'suspicious';
      dismissed = false;
    } else if (weeklyDownloads >= 100_000) {
      verdict   = 'likely-legitimate';
      dismissed = true;   // major package — suppress false positive
    } else if (weeklyDownloads >= 10_000) {
      verdict   = 'likely-legitimate';
      dismissed = false;
    } else if (weeklyDownloads >= 1_000) {
      verdict   = 'uncertain';
      dismissed = false;
    } else {
      verdict   = 'suspicious';
      dismissed = false;
    }

    return { ...f, authenticity: { weeklyDownloads, ageInDays, verdict, dismissed } };
  });
}
