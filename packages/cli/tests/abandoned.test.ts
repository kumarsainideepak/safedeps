import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanAbandoned } from '../src/detectors/abandoned';
import type { MaintainerFinding, MaintainerSignals, ScoreBreakdown } from '../src/detectors/maintainer';

function makeFinding(overrides: { name: string; version?: string; score?: number; risk?: 'low' | 'medium' | 'high'; signals?: Partial<MaintainerSignals>; githubUrl?: string | null; maintainerNames?: string[] }): MaintainerFinding {
  const defaults: MaintainerSignals = {
    daysSincePublish:    100,
    maintainerCount:     2,
    accountAgeDays:      1000,
    daysSinceLastCommit: 30,
    githubStars:         500,
    openIssues:          10,
    isArchived:          false,
    hasGitHub:           true,
    maintainerChanged:   false,
    previousPublisher:   null,
  };

  const breakdown: ScoreBreakdown = {
    recency: 25, maintainerCount: 12, accountAge: 17,
    githubActivity: 12, issueHealth: 7, popularity: 4,
  };

  const signals: MaintainerSignals = { ...defaults, ...(overrides.signals ?? {}) };

  return {
    name:            overrides.name,
    version:         overrides.version ?? '1.0.0',
    score:           overrides.score ?? 77,
    risk:            overrides.risk ?? 'low',
    signals,
    breakdown,
    npmUrl:          `https://www.npmjs.com/package/${overrides.name}`,
    githubUrl:       overrides.githubUrl ?? `https://github.com/org/${overrides.name}`,
    maintainerNames: overrides.maintainerNames ?? ['user1'],
    takeoverRisk:    'none',
  };
}

describe('scanAbandoned()', () => {

  it('returns empty findings for recently published packages', () => {
    const findings = [
      makeFinding({ name: 'fresh-pkg', signals: { daysSincePublish: 30 } }),
      makeFinding({ name: 'recent-pkg', signals: { daysSincePublish: 365 } }),
    ];
    const result = scanAbandoned(findings as MaintainerFinding[]);
    assert.equal(result.findings.length, 0);
    assert.equal(result.scanned, 2);
  });

  it('flags HIGH risk: old publish + archived repo', () => {
    const findings = [
      makeFinding({
        name: 'old-archived',
        signals: { daysSincePublish: 1000, isArchived: true, hasGitHub: true },
      }),
    ];
    const result = scanAbandoned(findings as MaintainerFinding[]);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].risk, 'high');
    assert.ok(result.findings[0].reasons.some(r => r.includes('archived')));
    assert.equal(result.highRisk, 1);
  });

  it('flags HIGH risk: old publish + no GitHub', () => {
    const findings = [
      makeFinding({
        name: 'no-github',
        signals: { daysSincePublish: 800, hasGitHub: false },
        githubUrl: null,
      }),
    ];
    const result = scanAbandoned(findings as MaintainerFinding[]);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].risk, 'high');
    assert.ok(result.findings[0].reasons.some(r => r.includes('No linked GitHub')));
  });

  it('flags MEDIUM risk: old publish + active GitHub repo', () => {
    const findings = [
      makeFinding({
        name: 'stale-npm',
        signals: { daysSincePublish: 800, hasGitHub: true, isArchived: false },
      }),
    ];
    const result = scanAbandoned(findings as MaintainerFinding[]);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].risk, 'medium');
    assert.equal(result.mediumRisk, 1);
  });

  it('does not flag packages with null daysSincePublish', () => {
    const findings = [
      makeFinding({ name: 'unknown-age', signals: { daysSincePublish: null } }),
    ];
    const result = scanAbandoned(findings as MaintainerFinding[]);
    assert.equal(result.findings.length, 0);
  });

  it('respects custom thresholdDays', () => {
    const findings = [
      makeFinding({ name: 'old-pkg', signals: { daysSincePublish: 400 } }),
    ];
    // Default 730 → not flagged
    assert.equal(scanAbandoned(findings as MaintainerFinding[]).findings.length, 0);
    // Custom 365 → flagged
    assert.equal(scanAbandoned(findings as MaintainerFinding[], { thresholdDays: 365 }).findings.length, 1);
  });

  it('sorts high risk before medium risk', () => {
    const findings = [
      makeFinding({
        name: 'medium-one',
        signals: { daysSincePublish: 800, hasGitHub: true, isArchived: false },
      }),
      makeFinding({
        name: 'high-one',
        signals: { daysSincePublish: 900, hasGitHub: false },
        githubUrl: null,
      }),
    ];
    const result = scanAbandoned(findings as MaintainerFinding[]);
    assert.equal(result.findings[0].name, 'high-one');
    assert.equal(result.findings[0].risk, 'high');
    assert.equal(result.findings[1].risk, 'medium');
  });

  it('includes stale GitHub commit in reasons for medium risk', () => {
    const findings = [
      makeFinding({
        name: 'stale-all',
        signals: {
          daysSincePublish: 800,
          hasGitHub: true,
          isArchived: false,
          daysSinceLastCommit: 900,
        },
      }),
    ];
    const result = scanAbandoned(findings as MaintainerFinding[]);
    assert.equal(result.findings[0].risk, 'medium');
    assert.ok(result.findings[0].reasons.some(r => r.includes('GitHub commit')));
  });

  it('returns correct scanned count', () => {
    const findings = [
      makeFinding({ name: 'a', signals: { daysSincePublish: 30 } }),
      makeFinding({ name: 'b', signals: { daysSincePublish: 800, isArchived: true } }),
      makeFinding({ name: 'c', signals: { daysSincePublish: 500 } }),
    ];
    const result = scanAbandoned(findings as MaintainerFinding[]);
    assert.equal(result.scanned, 3);
    assert.equal(result.findings.length, 1);
  });
});
