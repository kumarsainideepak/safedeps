import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateCycloneDxBom, buildPurl, parseSriToHashes } from '../src/generators/cyclonedx';
import type { ParsedPackageJson } from '../src/utils/packageParser';

// ─── Fixtures ──────────────────────────────────────────────────────────────

function makeParsed(overrides: Partial<ParsedPackageJson> = {}): ParsedPackageJson {
  return {
    name:                 'my-app',
    version:              '1.0.0',
    license:              'MIT',
    allPackages:          ['express', 'lodash'],
    dependencies:         { express: '^4.18.0', lodash: '^4.17.21' },
    devDependencies:      { typescript: '^5.0.0' },
    peerDependencies:     {},
    optionalDependencies: {},
    ...overrides,
  };
}

const LOCK_VERSIONS = new Map<string, string>([
  ['express', '4.18.2'],
  ['lodash',  '4.17.21'],
  ['typescript', '5.0.4'],
]);

// ─── buildPurl ─────────────────────────────────────────────────────────────

describe('buildPurl()', () => {
  it('builds PURL for unscoped package', () => {
    assert.equal(buildPurl('express', '4.18.2'), 'pkg:npm/express@4.18.2');
  });

  it('builds PURL for scoped package', () => {
    const purl = buildPurl('@nestjs/core', '10.0.0');
    assert.ok(purl.startsWith('pkg:npm/'), `Should start with pkg:npm/: ${purl}`);
    assert.ok(purl.includes('10.0.0'), `Should include version: ${purl}`);
    assert.ok(purl.includes('%40nestjs'), `Should encode @: ${purl}`);
  });

  it('PURL ends with @version', () => {
    const purl = buildPurl('chalk', '5.3.0');
    assert.ok(purl.endsWith('@5.3.0'));
  });
});

// ─── parseSriToHashes ──────────────────────────────────────────────────────

describe('parseSriToHashes()', () => {
  it('parses sha512 integrity string', () => {
    const sri = 'sha512-abc123def456==';
    const hashes = parseSriToHashes(sri);
    assert.equal(hashes.length, 1);
    assert.equal(hashes[0].alg,     'SHA-512');
    assert.equal(hashes[0].content, 'abc123def456==');
  });

  it('parses sha256 integrity string', () => {
    const hashes = parseSriToHashes('sha256-xyz789==');
    assert.equal(hashes[0].alg, 'SHA-256');
  });

  it('parses multiple algorithms in one string', () => {
    const sri = 'sha512-aaa sha256-bbb';
    const hashes = parseSriToHashes(sri);
    assert.equal(hashes.length, 2);
    assert.ok(hashes.some(h => h.alg === 'SHA-512'));
    assert.ok(hashes.some(h => h.alg === 'SHA-256'));
  });

  it('ignores unknown algorithm prefixes', () => {
    const hashes = parseSriToHashes('md5-abc123');
    assert.equal(hashes.length, 0);
  });

  it('returns empty array for empty string', () => {
    assert.deepEqual(parseSriToHashes(''), []);
  });
});

// ─── generateCycloneDxBom ──────────────────────────────────────────────────

describe('generateCycloneDxBom()', () => {

  it('produces correct BOM format and specVersion', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS);
    assert.equal(bom.bomFormat,   'CycloneDX');
    assert.equal(bom.specVersion, '1.5');
  });

  it('serialNumber is a urn:uuid string', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS);
    assert.ok(bom.serialNumber.startsWith('urn:uuid:'));
    // UUID format: urn:uuid:<8>-<4>-<4>-<4>-<12>
    assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  });

  it('version is 1', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS);
    assert.equal(bom.version, 1);
  });

  it('includes metadata timestamp in ISO format', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS);
    assert.ok(!isNaN(new Date(bom.metadata.timestamp).getTime()));
  });

  it('includes safedeps in tools list', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS, { toolVersion: '1.2.0' });
    const tool = bom.metadata.tools.find(t => t.name === 'safedeps');
    assert.ok(tool, 'safedeps tool entry missing');
    assert.equal(tool!.version, '1.2.0');
  });

  it('metadata component reflects project name and version', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS, {
      projectName:    'my-app',
      projectVersion: '2.0.0',
    });
    assert.equal(bom.metadata.component.name,    'my-app');
    assert.equal(bom.metadata.component.version, '2.0.0');
    assert.equal(bom.metadata.component.type,    'application');
  });

  it('includes only production dependencies by default', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS);
    const names = bom.components.map(c => c.name);
    assert.ok(names.includes('express'));
    assert.ok(names.includes('lodash'));
    assert.ok(!names.includes('typescript'), 'devDep should be excluded by default');
  });

  it('includes devDependencies when includeDev is true', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS, { includeDev: true });
    const names = bom.components.map(c => c.name);
    assert.ok(names.includes('typescript'));
  });

  it('each component has type library', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS);
    for (const c of bom.components) {
      assert.equal(c.type, 'library');
    }
  });

  it('component versions come from lockfile', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS);
    const express = bom.components.find(c => c.name === 'express');
    assert.equal(express?.version, '4.18.2');
  });

  it('component PURL is present and correct format', () => {
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS);
    const lodash = bom.components.find(c => c.name === 'lodash');
    assert.ok(lodash?.purl?.startsWith('pkg:npm/lodash@'));
    assert.ok(lodash?.purl?.includes('4.17.21'));
  });

  it('includes license when packageMeta provides it', () => {
    const packageMeta = new Map([
      ['express', { license: 'MIT'   }],
      ['lodash',  { license: 'MIT'   }],
    ]);
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS, { packageMeta });
    const express = bom.components.find(c => c.name === 'express');
    assert.deepEqual(express?.licenses, [{ license: { id: 'MIT' } }]);
  });

  it('omits license field when license is null', () => {
    const packageMeta = new Map([['express', { license: null }]]);
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS, { packageMeta });
    const express = bom.components.find(c => c.name === 'express');
    assert.equal(express?.licenses, undefined);
  });

  it('includes hashes from integrityMap', () => {
    const integrityMap = new Map([
      ['express', 'sha512-abc123=='],
    ]);
    const bom = generateCycloneDxBom(makeParsed(), LOCK_VERSIONS, { integrityMap });
    const express = bom.components.find(c => c.name === 'express');
    assert.ok(Array.isArray(express?.hashes));
    assert.equal(express?.hashes?.[0].alg, 'SHA-512');
  });

  it('components are sorted alphabetically', () => {
    const parsed = makeParsed({
      dependencies: { zlib: '^1.0.0', axios: '^1.0.0', express: '^4.0.0' },
    });
    const locks = new Map([['zlib', '1.0.0'], ['axios', '1.0.0'], ['express', '4.0.0']]);
    const bom = generateCycloneDxBom(parsed, locks);
    const names = bom.components.map(c => c.name);
    assert.deepEqual(names, [...names].sort());
  });

  it('handles empty dependencies gracefully', () => {
    const parsed = makeParsed({ dependencies: {}, allPackages: [] });
    const bom = generateCycloneDxBom(parsed, new Map());
    assert.equal(bom.components.length, 0);
  });

  it('uses (unknown) version when package not in lockfile', () => {
    const bom = generateCycloneDxBom(makeParsed(), new Map());
    const express = bom.components.find(c => c.name === 'express');
    assert.equal(express?.version, '(unknown)');
  });
});
