import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  _scoreRecency,
  _scoreMaintainerCount,
  _scoreAccountAge,
  _scoreGitHubActivity,
  _scoreIssueHealth,
  _scorePopularity,
  computeScore,
  totalScore,
  toRiskLevel,
} from '../src/detectors/maintainer';
import { extractGitHubRepo } from '../src/sources/githubApi';
import type { MaintainerSignals } from '../src/detectors/maintainer';

// ─── Signal fixtures ───────────────────────────────────────────────────────

const HEALTHY_SIGNALS: MaintainerSignals = {
  daysSincePublish:    30,
  maintainerCount:     3,
  accountAgeDays:      2000,
  daysSinceLastCommit: 14,
  githubStars:         5000,
  openIssues:          20,
  isArchived:          false,
  hasGitHub:           true,
};

const STALE_SIGNALS: MaintainerSignals = {
  daysSincePublish:    1500,   // > 3 years
  maintainerCount:     1,
  accountAgeDays:      200,    // < 1 year old account
  daysSinceLastCommit: 1200,   // > 1 year since commit
  githubStars:         3,
  openIssues:          50,
  isArchived:          false,
  hasGitHub:           true,
};

const NO_GITHUB_SIGNALS: MaintainerSignals = {
  daysSincePublish:    60,
  maintainerCount:     2,
  accountAgeDays:      800,
  daysSinceLastCommit: null,
  githubStars:         null,
  openIssues:          null,
  isArchived:          false,
  hasGitHub:           false,
};

// ─── _scoreRecency ─────────────────────────────────────────────────────────

describe('_scoreRecency', () => {
  it('returns 30 for very recent publish (≤ 90 days)', () => {
    assert.equal(_scoreRecency(0),  30);
    assert.equal(_scoreRecency(90), 30);
  });

  it('returns 25 for publish within 6 months', () => {
    assert.equal(_scoreRecency(91),  25);
    assert.equal(_scoreRecency(180), 25);
  });

  it('returns 18 for publish within a year', () => {
    assert.equal(_scoreRecency(181), 18);
    assert.equal(_scoreRecency(365), 18);
  });

  it('returns 10 for publish within 2 years', () => {
    assert.equal(_scoreRecency(366), 10);
    assert.equal(_scoreRecency(730), 10);
  });

  it('returns 4 for publish within 3 years', () => {
    assert.equal(_scoreRecency(731),  4);
    assert.equal(_scoreRecency(1095), 4);
  });

  it('returns 0 for publish older than 3 years', () => {
    assert.equal(_scoreRecency(1096), 0);
    assert.equal(_scoreRecency(2000), 0);
  });

  it('returns 15 for unknown (null)', () => {
    assert.equal(_scoreRecency(null), 15);
  });
});

// ─── _scoreMaintainerCount ─────────────────────────────────────────────────

describe('_scoreMaintainerCount', () => {
  it('returns 5 for single maintainer', () => {
    assert.equal(_scoreMaintainerCount(1), 5);
  });

  it('returns 5 for zero maintainers', () => {
    assert.equal(_scoreMaintainerCount(0), 5);
  });

  it('returns 12 for two maintainers', () => {
    assert.equal(_scoreMaintainerCount(2), 12);
  });

  it('returns 20 for three or more maintainers', () => {
    assert.equal(_scoreMaintainerCount(3),  20);
    assert.equal(_scoreMaintainerCount(10), 20);
  });
});

// ─── _scoreAccountAge ──────────────────────────────────────────────────────

describe('_scoreAccountAge', () => {
  it('returns 10 for unknown age (null)', () => {
    assert.equal(_scoreAccountAge(null), 10);
  });

  it('returns 2 for very new accounts (< 1 year)', () => {
    assert.equal(_scoreAccountAge(0),   2);
    assert.equal(_scoreAccountAge(364), 2);
  });

  it('returns 7 for accounts 1–2 years old', () => {
    assert.equal(_scoreAccountAge(365), 7);
    assert.equal(_scoreAccountAge(729), 7);
  });

  it('returns 12 for accounts 2–3 years old', () => {
    assert.equal(_scoreAccountAge(730),  12);
    assert.equal(_scoreAccountAge(1094), 12);
  });

  it('returns 17 for accounts 3–5 years old', () => {
    assert.equal(_scoreAccountAge(1095), 17);
    assert.equal(_scoreAccountAge(1824), 17);
  });

  it('returns 20 for accounts older than 5 years', () => {
    assert.equal(_scoreAccountAge(1825), 20);
    assert.equal(_scoreAccountAge(3650), 20);
  });
});

// ─── _scoreGitHubActivity ──────────────────────────────────────────────────

describe('_scoreGitHubActivity', () => {
  it('returns 7 (neutral) when no GitHub', () => {
    assert.equal(_scoreGitHubActivity({ ...HEALTHY_SIGNALS, hasGitHub: false }), 7);
  });

  it('returns 0 for archived repo', () => {
    assert.equal(_scoreGitHubActivity({ ...HEALTHY_SIGNALS, isArchived: true }), 0);
  });

  it('returns 15 for commit within 30 days', () => {
    assert.equal(_scoreGitHubActivity({ ...HEALTHY_SIGNALS, daysSinceLastCommit: 30 }), 15);
  });

  it('returns 12 for commit within 90 days', () => {
    assert.equal(_scoreGitHubActivity({ ...HEALTHY_SIGNALS, daysSinceLastCommit: 90 }), 12);
  });

  it('returns 8 for commit within 180 days', () => {
    assert.equal(_scoreGitHubActivity({ ...HEALTHY_SIGNALS, daysSinceLastCommit: 180 }), 8);
  });

  it('returns 4 for commit within 1 year', () => {
    assert.equal(_scoreGitHubActivity({ ...HEALTHY_SIGNALS, daysSinceLastCommit: 365 }), 4);
  });

  it('returns 0 for commit older than 1 year', () => {
    assert.equal(_scoreGitHubActivity({ ...HEALTHY_SIGNALS, daysSinceLastCommit: 366 }), 0);
  });
});

// ─── _scoreIssueHealth ─────────────────────────────────────────────────────

describe('_scoreIssueHealth', () => {
  it('returns 5 (neutral) when no GitHub', () => {
    assert.equal(_scoreIssueHealth({ ...HEALTHY_SIGNALS, hasGitHub: false }), 5);
  });

  it('returns 10 for very low issue/star ratio (< 1%)', () => {
    assert.equal(_scoreIssueHealth({ ...HEALTHY_SIGNALS, githubStars: 1000, openIssues: 5 }), 10);
  });

  it('returns 7 for moderate ratio (1–5%)', () => {
    assert.equal(_scoreIssueHealth({ ...HEALTHY_SIGNALS, githubStars: 1000, openIssues: 30 }), 7);
  });

  it('returns 4 for elevated ratio (5–20%)', () => {
    assert.equal(_scoreIssueHealth({ ...HEALTHY_SIGNALS, githubStars: 1000, openIssues: 100 }), 4);
  });

  it('returns 1 for high ratio (≥ 20%)', () => {
    assert.equal(_scoreIssueHealth({ ...HEALTHY_SIGNALS, githubStars: 100, openIssues: 50 }), 1);
  });

  it('returns 8 for zero stars and zero issues', () => {
    assert.equal(_scoreIssueHealth({ ...HEALTHY_SIGNALS, githubStars: 0, openIssues: 0 }), 8);
  });

  it('returns 3 for zero stars with open issues', () => {
    assert.equal(_scoreIssueHealth({ ...HEALTHY_SIGNALS, githubStars: 0, openIssues: 10 }), 3);
  });
});

// ─── _scorePopularity ─────────────────────────────────────────────────────

describe('_scorePopularity', () => {
  it('returns 2 (neutral) when no GitHub', () => {
    assert.equal(_scorePopularity({ ...HEALTHY_SIGNALS, hasGitHub: false }), 2);
  });

  it('returns 5 for ≥ 10k stars', () => {
    assert.equal(_scorePopularity({ ...HEALTHY_SIGNALS, githubStars: 10000 }), 5);
    assert.equal(_scorePopularity({ ...HEALTHY_SIGNALS, githubStars: 50000 }), 5);
  });

  it('returns 4 for 1k–10k stars', () => {
    assert.equal(_scorePopularity({ ...HEALTHY_SIGNALS, githubStars: 1000 }), 4);
    assert.equal(_scorePopularity({ ...HEALTHY_SIGNALS, githubStars: 9999 }), 4);
  });

  it('returns 3 for 100–999 stars', () => {
    assert.equal(_scorePopularity({ ...HEALTHY_SIGNALS, githubStars: 100 }), 3);
  });

  it('returns 2 for 10–99 stars', () => {
    assert.equal(_scorePopularity({ ...HEALTHY_SIGNALS, githubStars: 10 }), 2);
  });

  it('returns 1 for 1–9 stars', () => {
    assert.equal(_scorePopularity({ ...HEALTHY_SIGNALS, githubStars: 1 }), 1);
  });

  it('returns 0 for zero stars', () => {
    assert.equal(_scorePopularity({ ...HEALTHY_SIGNALS, githubStars: 0 }), 0);
  });
});

// ─── computeScore + totalScore ─────────────────────────────────────────────

describe('computeScore', () => {
  it('produces max score for ideal healthy signals', () => {
    const breakdown = computeScore(HEALTHY_SIGNALS);
    const score = totalScore(breakdown);
    // Ideal: 30 + 20 + 20 + 15 + 10 + 5 = 100, but issue ratio may not be perfect
    assert.ok(score >= 90, `Expected score ≥ 90, got ${score}`);
  });

  it('produces low score for stale/risky signals', () => {
    const breakdown = computeScore(STALE_SIGNALS);
    const score = totalScore(breakdown);
    assert.ok(score < 30, `Expected score < 30, got ${score}`);
  });

  it('score for no-GitHub package is in mid range', () => {
    const breakdown = computeScore(NO_GITHUB_SIGNALS);
    const score = totalScore(breakdown);
    assert.ok(score >= 30 && score <= 80, `Expected 30–80, got ${score}`);
  });

  it('breakdown components sum to total', () => {
    const b = computeScore(HEALTHY_SIGNALS);
    const manual = b.recency + b.maintainerCount + b.accountAge + b.githubActivity + b.issueHealth + b.popularity;
    assert.equal(totalScore(b), manual);
  });

  it('all breakdown values are non-negative', () => {
    const b = computeScore(STALE_SIGNALS);
    assert.ok(b.recency >= 0);
    assert.ok(b.maintainerCount >= 0);
    assert.ok(b.accountAge >= 0);
    assert.ok(b.githubActivity >= 0);
    assert.ok(b.issueHealth >= 0);
    assert.ok(b.popularity >= 0);
  });
});

// ─── toRiskLevel ───────────────────────────────────────────────────────────

describe('toRiskLevel', () => {
  it('returns high for score < 30', () => {
    assert.equal(toRiskLevel(0),  'high');
    assert.equal(toRiskLevel(29), 'high');
  });

  it('returns medium for score 30–69', () => {
    assert.equal(toRiskLevel(30), 'medium');
    assert.equal(toRiskLevel(69), 'medium');
  });

  it('returns low for score ≥ 70', () => {
    assert.equal(toRiskLevel(70),  'low');
    assert.equal(toRiskLevel(100), 'low');
  });
});

// ─── extractGitHubRepo ─────────────────────────────────────────────────────

describe('extractGitHubRepo', () => {
  it('parses https URLs', () => {
    const result = extractGitHubRepo('https://github.com/lodash/lodash');
    assert.deepEqual(result, { owner: 'lodash', repo: 'lodash' });
  });

  it('strips .git suffix', () => {
    const result = extractGitHubRepo('https://github.com/expressjs/express.git');
    assert.deepEqual(result, { owner: 'expressjs', repo: 'express' });
  });

  it('parses git+https URLs', () => {
    const result = extractGitHubRepo('git+https://github.com/chalk/chalk.git');
    assert.deepEqual(result, { owner: 'chalk', repo: 'chalk' });
  });

  it('parses SSH URLs', () => {
    const result = extractGitHubRepo('git@github.com:facebook/react.git');
    assert.deepEqual(result, { owner: 'facebook', repo: 'react' });
  });

  it('parses github: shorthand', () => {
    const result = extractGitHubRepo('github:owner/repo');
    assert.deepEqual(result, { owner: 'owner', repo: 'repo' });
  });

  it('parses bare owner/repo shorthand', () => {
    const result = extractGitHubRepo('owner/my-repo');
    assert.deepEqual(result, { owner: 'owner', repo: 'my-repo' });
  });

  it('returns null for non-GitHub URLs', () => {
    assert.equal(extractGitHubRepo('https://gitlab.com/owner/repo'), null);
    assert.equal(extractGitHubRepo('https://bitbucket.org/owner/repo'), null);
  });

  it('returns null for null/undefined input', () => {
    assert.equal(extractGitHubRepo(null),      null);
    assert.equal(extractGitHubRepo(undefined),  null);
    assert.equal(extractGitHubRepo(''),         null);
  });
});
