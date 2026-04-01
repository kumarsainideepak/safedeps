/**
 * Maintainer Health Score Detector
 *
 * Generates a 0–100 trust score for each production dependency based on
 * signals pulled from the npm registry and GitHub API:
 *
 *   Signal                   Weight   Source
 *   ───────────────────────────────────────────────────────
 *   Days since last publish     30%   npm packument (time.modified)
 *   Number of maintainers       20%   npm packument (maintainers[])
 *   Maintainer account age      20%   npm user endpoint (best-effort)
 *   GitHub activity             15%   GitHub API (pushed_at / archived)
 *   Issue health                10%   GitHub API (open_issues / stars ratio)
 *   Popularity                   5%   GitHub API (stargazers_count)
 *
 * Score < 30  → HIGH RISK  (flagged regardless of other factors)
 * Score 30–69 → MEDIUM RISK
 * Score ≥ 70  → LOW RISK (healthy)
 *
 * Network strategy:
 *   - All npm packument calls run with concurrency 8
 *   - GitHub calls run with concurrency 5 (lower, respects unauthenticated limit)
 *   - GitHub rate-limit errors are caught; affected packages get neutral GitHub scores
 *   - Set GITHUB_TOKEN env var for 5,000 req/hr instead of 60 req/hr
 */

import { parseLockfile } from '../utils/lockfileParser';
import {
  fetchNpmPackumentInfo,
  fetchNpmAccountAge,
} from '../sources/npmRegistry';
import { extractGitHubRepo, fetchGitHubRepoInfo } from '../sources/githubApi';
import type { NpmPackumentInfo } from '../sources/npmRegistry';
import type { GitHubRepoInfo } from '../sources/githubApi';
import type { ParsedPackageJson } from '../utils/packageParser';

// ─── Public types ──────────────────────────────────────────────────────────

export type MaintainerRisk = 'low' | 'medium' | 'high';

export interface MaintainerSignals {
  daysSincePublish:    number | null;
  maintainerCount:     number;
  accountAgeDays:      number | null;  // age of primary maintainer's account
  daysSinceLastCommit: number | null;  // from GitHub pushed_at
  githubStars:         number | null;
  openIssues:          number | null;
  isArchived:          boolean;
  hasGitHub:           boolean;
}

export interface ScoreBreakdown {
  recency:         number;   // 0–30
  maintainerCount: number;   // 0–20
  accountAge:      number;   // 0–20
  githubActivity:  number;   // 0–15
  issueHealth:     number;   // 0–10
  popularity:      number;   // 0–5
}

export interface MaintainerFinding {
  name:        string;
  version:     string;
  score:       number;       // 0–100
  risk:        MaintainerRisk;
  signals:     MaintainerSignals;
  breakdown:   ScoreBreakdown;
  npmUrl:      string;
  githubUrl:   string | null;
}

export interface MaintainerResult {
  findings:   MaintainerFinding[];
  scanned:    number;
  highRisk:   number;
  mediumRisk: number;
  error?:     string;
}

export interface ScanMaintainerOptions {
  projectPath?:  string;
  lockVersions?: Map<string, string>;
}

// ─── Scoring (pure functions — fully testable) ─────────────────────────────

/** Converts a signal set into a 0–100 health score. */
export function computeScore(signals: MaintainerSignals): ScoreBreakdown {
  return {
    recency:         _scoreRecency(signals.daysSincePublish),
    maintainerCount: _scoreMaintainerCount(signals.maintainerCount),
    accountAge:      _scoreAccountAge(signals.accountAgeDays),
    githubActivity:  _scoreGitHubActivity(signals),
    issueHealth:     _scoreIssueHealth(signals),
    popularity:      _scorePopularity(signals),
  };
}

export function totalScore(breakdown: ScoreBreakdown): number {
  return (
    breakdown.recency +
    breakdown.maintainerCount +
    breakdown.accountAge +
    breakdown.githubActivity +
    breakdown.issueHealth +
    breakdown.popularity
  );
}

export function toRiskLevel(score: number): MaintainerRisk {
  if (score < 30) return 'high';
  if (score < 70) return 'medium';
  return 'low';
}

// Individual scoring functions (exported for unit tests)

export function _scoreRecency(days: number | null): number {
  if (days === null) return 15;  // unknown → neutral
  if (days <= 90)   return 30;
  if (days <= 180)  return 25;
  if (days <= 365)  return 18;
  if (days <= 730)  return 10;
  if (days <= 1095) return 4;
  return 0;
}

export function _scoreMaintainerCount(count: number): number {
  if (count >= 3) return 20;
  if (count === 2) return 12;
  return 5;   // 1 or 0
}

export function _scoreAccountAge(days: number | null): number {
  if (days === null) return 10;    // unknown → neutral
  if (days >= 1825) return 20;     // ≥ 5 years
  if (days >= 1095) return 17;     // ≥ 3 years
  if (days >= 730)  return 12;     // ≥ 2 years
  if (days >= 365)  return 7;      // ≥ 1 year
  return 2;                        // < 1 year — new account
}

export function _scoreGitHubActivity(s: MaintainerSignals): number {
  if (!s.hasGitHub) return 7;      // no GitHub → neutral
  if (s.isArchived) return 0;      // archived repo = stale
  if (s.daysSinceLastCommit === null) return 5;
  if (s.daysSinceLastCommit <= 30)  return 15;
  if (s.daysSinceLastCommit <= 90)  return 12;
  if (s.daysSinceLastCommit <= 180) return 8;
  if (s.daysSinceLastCommit <= 365) return 4;
  return 0;
}

export function _scoreIssueHealth(s: MaintainerSignals): number {
  if (!s.hasGitHub) return 5;      // no GitHub → neutral
  if (s.openIssues === null) return 5;

  const stars    = s.githubStars ?? 0;
  const issues   = s.openIssues;

  if (stars === 0 && issues === 0) return 8;
  if (stars === 0)                 return 3;

  const ratio = issues / stars;
  if (ratio < 0.01) return 10;
  if (ratio < 0.05) return 7;
  if (ratio < 0.20) return 4;
  return 1;
}

export function _scorePopularity(s: MaintainerSignals): number {
  if (!s.hasGitHub) return 2;      // no GitHub → slight neutral
  const stars = s.githubStars ?? 0;
  if (stars >= 10_000) return 5;
  if (stars >= 1_000)  return 4;
  if (stars >= 100)    return 3;
  if (stars >= 10)     return 2;
  if (stars >= 1)      return 1;
  return 0;
}

// ─── Signal helpers ────────────────────────────────────────────────────────

function _daysSince(date: Date | null): number | null {
  if (!date) return null;
  return Math.floor((Date.now() - date.getTime()) / (1000 * 60 * 60 * 24));
}

async function _resolveGitHub(
  repoUrl: string | null,
): Promise<GitHubRepoInfo | null> {
  const coords = extractGitHubRepo(repoUrl);
  if (!coords) return null;
  try {
    return await fetchGitHubRepoInfo(coords.owner, coords.repo);
  } catch {
    return null;
  }
}

async function _resolveMaintainerAge(
  maintainers: NpmPackumentInfo['maintainers'],
): Promise<number | null> {
  if (maintainers.length === 0) return null;
  // Fetch only the primary maintainer to keep requests bounded
  const date = await fetchNpmAccountAge(maintainers[0].name);
  return _daysSince(date);
}

// ─── Concurrency helper ────────────────────────────────────────────────────

async function _withConcurrency<T>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  for (let i = 0; i < items.length; i += concurrency) {
    await Promise.allSettled(items.slice(i, i + concurrency).map(fn));
  }
}

// ─── Main scanner ──────────────────────────────────────────────────────────

export async function scanMaintainerHealth(
  parsedPackageJson: ParsedPackageJson,
  options: ScanMaintainerOptions = {},
): Promise<MaintainerResult> {
  const { projectPath = process.cwd(), lockVersions: lockVersionsOpt } = options;

  // Only scan production dependencies
  const packagesToScan = Object.keys(parsedPackageJson.dependencies);

  if (packagesToScan.length === 0) {
    return { findings: [], scanned: 0, highRisk: 0, mediumRisk: 0 };
  }

  const lockVersions = lockVersionsOpt ?? parseLockfile(projectPath);

  // ── Phase 1: Fetch npm packument info (concurrency 8) ───────────────────
  const packumentMap = new Map<string, NpmPackumentInfo | null>();

  await _withConcurrency(packagesToScan, 8, async (name) => {
    try {
      packumentMap.set(name, await fetchNpmPackumentInfo(name));
    } catch {
      packumentMap.set(name, null);
    }
  });

  // ── Phase 2: Fetch GitHub data for packages that have a repo URL ─────────
  const githubMap = new Map<string, GitHubRepoInfo | null>();

  const withGitHub = packagesToScan
    .map(name => ({ name, packument: packumentMap.get(name) }))
    .filter(p => p.packument?.repositoryUrl != null);

  await _withConcurrency(withGitHub, 5, async ({ name, packument }) => {
    githubMap.set(name, await _resolveGitHub(packument!.repositoryUrl));
  });

  // ── Phase 3: Fetch maintainer account ages (best-effort, concurrency 5) ──
  const accountAgeMap = new Map<string, number | null>();

  await _withConcurrency(packagesToScan, 5, async (name) => {
    const packument = packumentMap.get(name);
    if (!packument || packument.maintainers.length === 0) {
      accountAgeMap.set(name, null);
      return;
    }
    accountAgeMap.set(name, await _resolveMaintainerAge(packument.maintainers));
  });

  // ── Phase 4: Build findings ──────────────────────────────────────────────
  const findings: MaintainerFinding[] = [];

  for (const name of packagesToScan) {
    const packument  = packumentMap.get(name);
    const github     = githubMap.get(name) ?? null;
    const accountAge = accountAgeMap.get(name) ?? null;
    const version    = lockVersions.get(name) ?? (packument?.latestVersion ?? '(unknown)');

    const signals: MaintainerSignals = {
      daysSincePublish:    _daysSince(packument?.lastPublished ?? null),
      maintainerCount:     packument?.maintainers.length ?? 0,
      accountAgeDays:      accountAge,
      daysSinceLastCommit: _daysSince(github?.pushedAt ?? null),
      githubStars:         github?.stars ?? null,
      openIssues:          github?.openIssues ?? null,
      isArchived:          github?.isArchived ?? false,
      hasGitHub:           github !== null,
    };

    const breakdown = computeScore(signals);
    const score     = Math.max(0, Math.min(100, totalScore(breakdown)));
    const risk      = toRiskLevel(score);

    findings.push({
      name,
      version,
      score,
      risk,
      signals,
      breakdown,
      npmUrl:    `https://www.npmjs.com/package/${name}`,
      githubUrl: github?.htmlUrl ?? null,
    });
  }

  // Sort: highest risk first (lowest score first)
  findings.sort((a, b) => a.score - b.score);

  const highRisk   = findings.filter(f => f.risk === 'high').length;
  const mediumRisk = findings.filter(f => f.risk === 'medium').length;

  return { findings, scanned: packagesToScan.length, highRisk, mediumRisk };
}
