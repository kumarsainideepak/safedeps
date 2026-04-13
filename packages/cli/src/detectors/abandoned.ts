/**
 * Abandoned Package Detector
 *
 * Pure function that analyses maintainer health findings to identify
 * dependencies that appear abandoned — no recent publishes, archived
 * repos, or missing GitHub presence.
 *
 * No network calls — operates entirely on data already fetched by
 * the maintainer detector.
 */

import type { MaintainerFinding } from './maintainer';

// ─── Public types ──────────────────────────────────────────────────────────

export type AbandonedRisk = 'high' | 'medium';

export interface AbandonedFinding {
  name:             string;
  version:          string;
  risk:             AbandonedRisk;
  reasons:          string[];
  daysSincePublish: number | null;
  isArchived:       boolean;
  hasGitHub:        boolean;
  npmUrl:           string;
  githubUrl:        string | null;
}

export interface AbandonedResult {
  findings:   AbandonedFinding[];
  scanned:    number;
  highRisk:   number;
  mediumRisk: number;
  error?:     string;
}

export interface ScanAbandonedOptions {
  thresholdDays?: number;  // default 730 (2 years)
}

// ─── Main function ─────────────────────────────────────────────────────────

/**
 * Analyses maintainer findings to detect abandoned packages.
 *
 * Risk classification:
 *   HIGH:   No publish in ≥ thresholdDays AND (archived OR no GitHub repo)
 *   MEDIUM: No publish in ≥ thresholdDays AND has active GitHub repo
 *
 * Packages published within the threshold are not flagged.
 */
export function scanAbandoned(
  maintainerFindings: MaintainerFinding[],
  options: ScanAbandonedOptions = {},
): AbandonedResult {
  const threshold = options.thresholdDays ?? 730;

  const findings: AbandonedFinding[] = [];

  for (const mf of maintainerFindings) {
    const days       = mf.signals.daysSincePublish;
    const isArchived = mf.signals.isArchived;
    const hasGitHub  = mf.signals.hasGitHub;

    // Skip if we can't determine last publish date or it's within threshold
    if (days === null || days < threshold) continue;

    const reasons: string[] = [];
    let risk: AbandonedRisk;

    // Build human-readable reasons
    const years = (days / 365).toFixed(1);
    reasons.push(`No publish in ${years} years`);

    if (isArchived) {
      reasons.push('GitHub repository archived');
      risk = 'high';
    } else if (!hasGitHub) {
      reasons.push('No linked GitHub repository');
      risk = 'high';
    } else {
      // Has active GitHub repo but no recent npm publish
      risk = 'medium';

      if (mf.signals.daysSinceLastCommit !== null && mf.signals.daysSinceLastCommit >= threshold) {
        const commitYears = (mf.signals.daysSinceLastCommit / 365).toFixed(1);
        reasons.push(`Last GitHub commit ${commitYears} years ago`);
      }
    }

    findings.push({
      name:             mf.name,
      version:          mf.version,
      risk,
      reasons,
      daysSincePublish: days,
      isArchived,
      hasGitHub,
      npmUrl:           mf.npmUrl,
      githubUrl:        mf.githubUrl,
    });
  }

  // Sort: high risk first
  findings.sort((a, b) => {
    if (a.risk === b.risk) return (b.daysSincePublish ?? 0) - (a.daysSincePublish ?? 0);
    return a.risk === 'high' ? -1 : 1;
  });

  return {
    findings,
    scanned:    maintainerFindings.length,
    highRisk:   findings.filter(f => f.risk === 'high').length,
    mediumRisk: findings.filter(f => f.risk === 'medium').length,
  };
}
