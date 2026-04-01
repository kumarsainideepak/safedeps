import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analysePackage, scanPackages } from '../src/detectors/typosquat';

// Small known-package list for predictable test results
const KNOWN = ['lodash', 'react', 'express', 'axios', 'chalk', 'commander'];

describe('analysePackage()', () => {

  it('returns null for a known-safe package', () => {
    assert.equal(analysePackage('lodash', KNOWN), null);
    assert.equal(analysePackage('react', KNOWN), null);
  });

  it('flags lodahs as a typosquat of lodash', () => {
    const result = analysePackage('lodahs', KNOWN);
    assert.ok(result !== null, 'should return a finding');
    assert.equal(result!.match, 'lodash');
    assert.ok(result!.distance <= 2);
  });

  it('flags recat as a typosquat of react', () => {
    const result = analysePackage('recat', KNOWN);
    assert.ok(result !== null);
    assert.equal(result!.match, 'react');
  });

  it('flags expres as a typosquat of express', () => {
    const result = analysePackage('expres', KNOWN);
    assert.ok(result !== null);
    assert.equal(result!.match, 'express');
    assert.equal(result!.distance, 1);
    assert.equal(result!.confidence, 'high');
  });

  it('does not flag a completely unrelated package', () => {
    const result = analysePackage('mongodb', KNOWN);
    assert.equal(result, null);
  });

  it('returns null for very short names', () => {
    assert.equal(analysePackage('ax', KNOWN), null);
    assert.equal(analysePackage('ab', KNOWN), null);
  });

  it('includes method and confidence in result', () => {
    const result = analysePackage('expres', KNOWN);
    assert.ok(['levenshtein', 'soundex', 'both'].includes(result!.method));
    assert.ok(['high', 'medium', 'low'].includes(result!.confidence));
  });

});

describe('scanPackages()', () => {

  it('returns empty array when all packages are clean', () => {
    const findings = scanPackages(['lodash', 'react', 'axios'], { knownPackages: KNOWN });
    assert.equal(findings.length, 0);
  });

  it('returns findings for suspicious packages', () => {
    const findings = scanPackages(
      ['lodash', 'lodahs', 'recat', 'axios'],
      { knownPackages: KNOWN }
    );
    assert.equal(findings.length, 2);
  });

  it('handles empty package list', () => {
    const findings = scanPackages([], { knownPackages: KNOWN });
    assert.equal(findings.length, 0);
  });

  it('returns correct suspicious name in finding', () => {
    const findings = scanPackages(['lodahs'], { knownPackages: KNOWN });
    assert.equal(findings[0].suspicious, 'lodahs');
  });

});
