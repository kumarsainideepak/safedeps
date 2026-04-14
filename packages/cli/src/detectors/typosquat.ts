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

// ── Combosquat lists ──────────────────────────────────────────────────────────

const COMBO_SUFFIXES = [
  '-js', '-node', '-cli', '-core', '-utils', '-util', '-helper', '-helpers',
  '-lib', '-api', '-dev', '-tool', '-tools', '-plugin', '-config',
  '-server', '-client', '-app', '-test', '-es', '-es6', '-next',
  '-new', '-v2', '-2', '-pro', '-plus', '-lite', '-min',
];

const COMBO_PREFIXES = [
  'node-', 'js-', 'get-', 'is-', 'my-', 'the-', 'super-', 'simple-',
  'easy-', 'fast-', 'mini-', 'micro-', 'nano-', 'ng-', 'vue-', 'react-',
];

// ── Homoglyph map ─────────────────────────────────────────────────────────────

const CONFUSABLES: Record<string, string> = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0443': 'y', '\u0456': 'i', '\u04BB': 'h',
  '\u2113': 'l', '\uFF10': '0', '\uFF11': '1',
};

export function _normalizeHomoglyphs(name: string): string {
  return [...name].map(ch => CONFUSABLES[ch] ?? ch).join('');
}

export function _normalizeSeparators(name: string): string {
  return name.replace(/[-_.]/g, '').toLowerCase();
}

/**
 * Authenticity signals fetched from npm to validate flagged packages.
 * Populated by `enrichWithAuthenticity()` after the offline typosquat scan.
 */
export interface NpmAuthenticity {
  score:             number;
  weeklyDownloads:   number | null;
  ageInDays:         number | null;
  publishedVersions: number | null;
  hasGitHubRepo:     boolean;
  existsOnNpm:       boolean | null;
  /** High-level verdict after weighing all signals. */
  verdict:   'likely-legitimate' | 'uncertain' | 'suspicious';
  /** When true, the package has enough npm adoption to be dismissed as a false positive. */
  dismissed: boolean;
}

export interface TyposquatFinding {
  suspicious:    string;
  match:         string;
  distance:      number;
  method:        'levenshtein' | 'soundex' | 'levenshtein+soundex' | 'separator' | 'homoglyph' | 'combosquat';
  confidence:    'high' | 'medium' | 'low';
  /** Populated after calling enrichWithAuthenticity(). */
  authenticity?: NpmAuthenticity;
}

export interface ScanPackagesOptions {
  knownPackages?: string[];
}

export interface EnrichOptions {
  concurrency?:    number;
  ageMap?:         Map<string, number>;
  signalRegistry?: import('../utils/signalRegistry').SignalRegistry;
}

/**
 * Analyses a single package name for potential typosquatting.
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
 */
export function _analyseWithSet(
  packageName: string,
  knownPackages: string[],
  knownSet: Set<string>,
): TyposquatFinding | null {
  if (!packageName || packageName.length < MIN_NAME_LENGTH) return null;

  const name = packageName.toLowerCase().trim();

  // 1. Exact match — safe
  if (knownSet.has(name)) return null;

  const isScoped = name.startsWith('@');

  // ── 2. Homoglyph detection (highest priority) ─────────────────────────────
  const normalized = _normalizeHomoglyphs(name);
  if (normalized !== name && knownSet.has(normalized)) {
    return {
      suspicious: packageName,
      match:      normalized,
      distance:   1,
      method:     'homoglyph',
      confidence: 'high',
    };
  }

  // ── 3. Separator substitution ─────────────────────────────────────────────
  // Build separator-normalized map lazily per call — O(m) once, then O(1) lookup
  const sepNorm = _normalizeSeparators(name);
  let separatorCandidate: TyposquatFinding | null = null;
  for (const known of knownPackages) {
    if (isScoped !== known.startsWith('@')) continue;
    if (_normalizeSeparators(known) === sepNorm && known !== name) {
      separatorCandidate = {
        suspicious: packageName,
        match:      known,
        distance:   1,
        method:     'separator',
        confidence: 'medium',
      };
      break;
    }
  }

  // ── 4. Levenshtein + Soundex ──────────────────────────────────────────────
  let closestMatch: string | null = null;
  let closestDist = Infinity;
  let soundexHit = false;

  for (const known of knownPackages) {
    if (isScoped !== known.startsWith('@')) continue;
    if (Math.abs(name.length - known.length) > LEVENSHTEIN_THRESHOLD) continue;

    const dist = levenshtein(name, known);

    if (dist <= LEVENSHTEIN_THRESHOLD && dist < closestDist) {
      closestDist  = dist;
      closestMatch = known;
    }

    if (!soundexHit && Math.abs(name.length - known.length) <= 1) {
      if (soundexMatch(name, known) && name !== known) {
        soundexHit = true;
        if (!closestMatch) {
          closestMatch = known;
          closestDist  = dist;
        }
      }
    }
  }

  let levenshteinCandidate: TyposquatFinding | null = null;
  if (closestMatch) {
    const levenshteinHit = closestDist <= LEVENSHTEIN_THRESHOLD;
    let method: TyposquatFinding['method'];
    if (levenshteinHit && soundexHit) method = 'levenshtein+soundex';
    else if (levenshteinHit)           method = 'levenshtein';
    else                               method = 'soundex';

    let confidence: 'high' | 'medium' | 'low';
    if (closestDist === 1)      confidence = 'high';
    else if (closestDist === 2) confidence = 'medium';
    else                        confidence = 'low';

    levenshteinCandidate = {
      suspicious: packageName,
      match:      closestMatch,
      distance:   closestDist,
      method,
      confidence,
    };
  }

  // ── 5. Combosquat detection ───────────────────────────────────────────────
  let comboCandidate: TyposquatFinding | null = null;
  for (const suffix of COMBO_SUFFIXES) {
    if (name.endsWith(suffix)) {
      const remainder = name.slice(0, name.length - suffix.length);
      if (remainder.length >= MIN_NAME_LENGTH && knownSet.has(remainder)) {
        comboCandidate = {
          suspicious: packageName,
          match:      remainder,
          distance:   suffix.length,
          method:     'combosquat',
          confidence: 'low',
        };
        break;
      }
    }
  }
  if (!comboCandidate) {
    for (const prefix of COMBO_PREFIXES) {
      if (name.startsWith(prefix)) {
        const remainder = name.slice(prefix.length);
        if (remainder.length >= MIN_NAME_LENGTH && knownSet.has(remainder)) {
          comboCandidate = {
            suspicious: packageName,
            match:      remainder,
            distance:   prefix.length,
            method:     'combosquat',
            confidence: 'low',
          };
          break;
        }
      }
    }
  }

  // ── 6. Return highest-confidence candidate ────────────────────────────────
  // Priority: levenshtein/soundex (may be high/medium) > separator (medium) > combo (low)
  const CONF_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };

  const candidates = [levenshteinCandidate, separatorCandidate, comboCandidate].filter(
    (c): c is TyposquatFinding => c !== null,
  );

  if (candidates.length === 0) return null;

  return candidates.reduce((best, c) =>
    CONF_RANK[c.confidence] > CONF_RANK[best.confidence] ? c : best,
  );
}

/**
 * Scans an array of package names for typosquatting.
 */
export function scanPackages(
  packageNames: string[],
  options: ScanPackagesOptions = {}
): TyposquatFinding[] {
  const { knownPackages = topPackages as string[] } = options;
  const knownSet = new Set(knownPackages);
  const findings: TyposquatFinding[] = [];

  for (const name of packageNames) {
    const result = _analyseWithSet(name, knownPackages, knownSet);
    if (result) findings.push(result);
  }

  return findings;
}

// ── Authenticity scoring helpers ──────────────────────────────────────────────

function _scoreDownloads(downloads: number | null): number {
  if (downloads === null) return 0;
  if (downloads >= 100_000) return 35;
  if (downloads >= 10_000)  return 28;
  if (downloads >= 1_000)   return 18;
  if (downloads >= 100)     return 8;
  return 0;
}

function _scoreAge(ageInDays: number | null): number {
  if (ageInDays === null) return 0;
  const MS_IN_DAY = 1;  // already in days
  if (ageInDays >= 3 * 365) return 25;
  if (ageInDays >= 365)      return 20;
  if (ageInDays >= 90)       return 12;
  if (ageInDays >= 30)       return 5;
  return 0;
}

function _scoreVersions(versions: number | null): number {
  if (versions === null) return 0;
  if (versions >= 50) return 15;
  if (versions >= 10) return 10;
  if (versions >= 3)  return 5;
  return 0;
}

function _scoreGitHub(hasRepo: boolean, stars: number | null): number {
  let score = 0;
  if (hasRepo) score += 5;
  if (stars !== null && stars >= 100) score += 5;
  return score;
}

function _scoreMaintainerAge(accountAgeDays: number | null): number {
  if (accountAgeDays === null) return 0;
  if (accountAgeDays >= 3 * 365) return 15;
  if (accountAgeDays >= 365)      return 10;
  if (accountAgeDays >= 90)       return 5;
  return 0;
}

function _computeAuthenticityScore(
  weeklyDownloads: number | null,
  ageInDays: number | null,
  publishedVersions: number | null,
  hasGitHubRepo: boolean,
  githubStars: number | null,
  accountAgeDays: number | null,
): number {
  return (
    _scoreDownloads(weeklyDownloads) +
    _scoreAge(ageInDays) +
    _scoreVersions(publishedVersions) +
    _scoreGitHub(hasGitHubRepo, githubStars) +
    _scoreMaintainerAge(accountAgeDays)
  );
}

function _toVerdict(score: number): NpmAuthenticity['verdict'] {
  if (score >= 70) return 'likely-legitimate';
  if (score >= 25) return 'uncertain';
  return 'suspicious';
}

/**
 * Enriches typosquat findings with npm authenticity signals (network call).
 */
export async function enrichWithAuthenticity(
  findings: TyposquatFinding[],
  options: EnrichOptions = {},
): Promise<TyposquatFinding[]> {
  if (findings.length === 0) return findings;

  const { concurrency = 8, ageMap, signalRegistry } = options;
  const names = findings.map(f => f.suspicious);
  const downloadsMap = await batchFetchDownloads(names, concurrency);

  return findings.map(f => {
    const stats            = downloadsMap.get(f.suspicious);
    const weeklyDownloads  = stats?.weeklyDownloads ?? null;
    const existsOnNpm      = stats?.existsOnNpm ?? null;
    const ageInDays        = ageMap?.get(f.suspicious) ?? null;

    // Pull extra signals from registry if available
    const reg                = signalRegistry?.get(f.suspicious);
    const publishedVersions  = reg?.publishedVersions ?? null;
    const hasGitHubRepo      = reg?.hasGitHubRepo ?? false;
    const githubStars        = reg?.githubStars ?? null;
    const accountAgeDays     = reg?.accountAgeDays ?? null;

    // Package not on npm → score 0, suspicious, upgrade confidence to high
    if (existsOnNpm === false) {
      const authenticity: NpmAuthenticity = {
        score:             0,
        weeklyDownloads:   null,
        ageInDays,
        publishedVersions,
        hasGitHubRepo,
        existsOnNpm:       false,
        verdict:           'suspicious',
        dismissed:         false,
      };
      return { ...f, confidence: 'high' as const, authenticity };
    }

    const score = _computeAuthenticityScore(
      weeklyDownloads, ageInDays, publishedVersions,
      hasGitHubRepo, githubStars, accountAgeDays,
    );

    const verdict   = _toVerdict(score);
    const dismissed = score >= 70;

    const authenticity: NpmAuthenticity = {
      score,
      weeklyDownloads,
      ageInDays,
      publishedVersions,
      hasGitHubRepo,
      existsOnNpm,
      verdict,
      dismissed,
    };

    return { ...f, authenticity };
  });
}
