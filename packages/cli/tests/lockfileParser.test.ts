import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { parseLockfile } from '../src/utils/lockfileParser';

// Helpers to create temp directories with fixture lockfiles
function withLockfile<T>(content: object, fn: (dir: string) => T): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safedeps-test-'));
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify(content));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

describe('parseLockfile()', () => {

  it('returns empty Map when no lockfile found', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safedeps-empty-'));
    try {
      const result = parseLockfile(dir);
      assert.ok(result instanceof Map);
      assert.equal(result.size, 0);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('parses v2 lockfile (npm 7+ format)', () => {
    const lockfile = {
      lockfileVersion: 2,
      packages: {
        '':                          { name: 'my-app', version: '1.0.0' },
        'node_modules/lodash':       { version: '4.17.21' },
        'node_modules/express':      { version: '4.18.2' },
        'node_modules/@scope/thing': { version: '2.0.0' },
      },
    };
    withLockfile(lockfile, dir => {
      const map = parseLockfile(dir);
      assert.equal(map.get('lodash'), '4.17.21');
      assert.equal(map.get('express'), '4.18.2');
      assert.equal(map.get('@scope/thing'), '2.0.0');
      // Root entry should be skipped
      assert.ok(!map.has(''));
    });
  });

  it('parses v1 lockfile (npm 6 format)', () => {
    const lockfile = {
      lockfileVersion: 1,
      dependencies: {
        lodash:  { version: '4.17.20' },
        express: { version: '4.17.1', dependencies: {
          'body-parser': { version: '1.20.0' },
        }},
      },
    };
    withLockfile(lockfile, dir => {
      const map = parseLockfile(dir);
      assert.equal(map.get('lodash'), '4.17.20');
      assert.equal(map.get('express'), '4.17.1');
      // Nested dependency should also be extracted
      assert.equal(map.get('body-parser'), '1.20.0');
    });
  });

  it('extracts nested deduped packages from v2 lockfile (first-wins)', () => {
    const lockfile = {
      lockfileVersion: 2,
      packages: {
        '':                                                  { name: 'my-app', version: '1.0.0' },
        'node_modules/body-parser':                          { version: '1.20.1' },
        'node_modules/express':                              { version: '4.18.2' },
        'node_modules/express/node_modules/body-parser':     { version: '1.19.0' },
        'node_modules/@scope/pkg':                           { version: '3.0.0' },
        'node_modules/express/node_modules/@scope/pkg':      { version: '2.0.0' },
      },
    };
    withLockfile(lockfile, dir => {
      const map = parseLockfile(dir);
      // Top-level version wins over nested duplicate
      assert.equal(map.get('body-parser'), '1.20.1');
      assert.equal(map.get('@scope/pkg'), '3.0.0');
      assert.equal(map.get('express'), '4.18.2');
      // Bad key like "express/node_modules/body-parser" must NOT be present
      assert.ok(!map.has('express/node_modules/body-parser'));
    });
  });

  it('handles malformed JSON gracefully', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safedeps-bad-'));
    fs.writeFileSync(path.join(dir, 'package-lock.json'), 'NOT JSON {{{{');
    try {
      const map = parseLockfile(dir);
      assert.ok(map instanceof Map);
      assert.equal(map.size, 0);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

});
