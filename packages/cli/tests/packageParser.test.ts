import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { parsePackageJson } from '../src/utils/packageParser';

function withPackageJson<T>(content: unknown, fn: (dir: string) => T): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safedeps-pkg-test-'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(content));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

describe('parsePackageJson()', () => {

  it('parses a normal package.json correctly', () => {
    const pkg = {
      name: 'my-app', version: '1.2.3', license: 'MIT',
      dependencies:         { lodash: '^4.17.21', express: '^4.18.0' },
      devDependencies:      { jest: '^29.0.0' },
      peerDependencies:     { react: '>=17.0.0' },
      optionalDependencies: { fsevents: '^2.0.0' },
    };
    withPackageJson(pkg, dir => {
      const result = parsePackageJson(dir);
      assert.equal(result.name, 'my-app');
      assert.equal(result.version, '1.2.3');
      assert.equal(result.license, 'MIT');
      assert.deepEqual(result.dependencies, { lodash: '^4.17.21', express: '^4.18.0' });
      assert.deepEqual(result.devDependencies, { jest: '^29.0.0' });
      assert.deepEqual(result.peerDependencies, { react: '>=17.0.0' });
      assert.deepEqual(result.optionalDependencies, { fsevents: '^2.0.0' });
    });
  });

  it('builds a deduplicated allPackages list', () => {
    const pkg = {
      name: 'test', version: '1.0.0',
      dependencies:    { lodash: '4.17.21', react: '18.0.0' },
      devDependencies: { react: '18.0.0', jest: '29.0.0' },  // react duplicated
    };
    withPackageJson(pkg, dir => {
      const result = parsePackageJson(dir);
      assert.ok(result.allPackages.includes('lodash'));
      assert.ok(result.allPackages.includes('react'));
      assert.ok(result.allPackages.includes('jest'));
      // react must appear only once despite being in both deps
      assert.equal(result.allPackages.filter(p => p === 'react').length, 1);
    });
  });

  it('defaults name to "unknown" when missing', () => {
    withPackageJson({ version: '1.0.0' }, dir => {
      const result = parsePackageJson(dir);
      assert.equal(result.name, 'unknown');
    });
  });

  it('defaults version to "0.0.0" when missing', () => {
    withPackageJson({ name: 'app' }, dir => {
      const result = parsePackageJson(dir);
      assert.equal(result.version, '0.0.0');
    });
  });

  it('returns null license when field is missing', () => {
    withPackageJson({ name: 'app', version: '1.0.0' }, dir => {
      const result = parsePackageJson(dir);
      assert.equal(result.license, null);
    });
  });

  it('returns empty dep maps when dependency fields are absent', () => {
    withPackageJson({ name: 'app', version: '1.0.0' }, dir => {
      const result = parsePackageJson(dir);
      assert.deepEqual(result.dependencies, {});
      assert.deepEqual(result.devDependencies, {});
      assert.deepEqual(result.peerDependencies, {});
      assert.deepEqual(result.optionalDependencies, {});
      assert.equal(result.allPackages.length, 0);
    });
  });

  it('skips non-string dependency values without throwing', () => {
    withPackageJson({
      name: 'app', version: '1.0.0',
      dependencies: { lodash: '^4.17.21', bad: 123, another: null },
    }, dir => {
      const result = parsePackageJson(dir);
      // Only string values survive
      assert.equal(result.dependencies['lodash'], '^4.17.21');
      assert.ok(!('bad' in result.dependencies));
      assert.ok(!('another' in result.dependencies));
    });
  });

  it('skips non-object dependency groups without throwing', () => {
    withPackageJson({
      name: 'app', version: '1.0.0',
      dependencies: 'invalid-string',
      devDependencies: [1, 2, 3],
    }, dir => {
      const result = parsePackageJson(dir);
      assert.deepEqual(result.dependencies, {});
      assert.deepEqual(result.devDependencies, {});
    });
  });

  it('throws when package.json does not exist', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safedeps-no-pkg-'));
    try {
      assert.throws(() => parsePackageJson(dir), /No package\.json found/);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('throws when package.json contains invalid JSON', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safedeps-bad-pkg-'));
    fs.writeFileSync(path.join(dir, 'package.json'), 'NOT { JSON }');
    try {
      assert.throws(() => parsePackageJson(dir), /Failed to parse package\.json/);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('handles numeric name/version fields defensively', () => {
    withPackageJson({ name: 42, version: 100, license: true }, dir => {
      const result = parsePackageJson(dir);
      assert.equal(result.name, 'unknown');
      assert.equal(result.version, '0.0.0');
      assert.equal(result.license, null);
    });
  });

});
