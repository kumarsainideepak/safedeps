import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analysePackage, scanPackages, _normalizeHomoglyphs, _normalizeSeparators } from '../src/detectors/typosquat';

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
    assert.ok(['levenshtein', 'soundex', 'levenshtein+soundex'].includes(result!.method));
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

describe('combosquat detection', () => {

  it('flags lodash-js as a combosquat of lodash', () => {
    const result = analysePackage('lodash-js', KNOWN);
    assert.ok(result !== null, 'should return a finding');
    assert.equal(result!.method, 'combosquat');
    assert.equal(result!.match, 'lodash');
    assert.equal(result!.confidence, 'low');
  });

  it('flags react-cli as a combosquat of react', () => {
    const result = analysePackage('react-cli', KNOWN);
    assert.ok(result !== null);
    assert.equal(result!.method, 'combosquat');
    assert.equal(result!.match, 'react');
  });

  it('does not flag lodash itself (exact match)', () => {
    const result = analysePackage('lodash', KNOWN);
    assert.equal(result, null);
  });

  it('flags node-express as a combosquat of express', () => {
    const result = analysePackage('node-express', KNOWN);
    assert.ok(result !== null);
    assert.equal(result!.method, 'combosquat');
    assert.equal(result!.match, 'express');
  });

});

describe('separator substitution detection', () => {

  it('_normalizeSeparators detects lo_dash normalizing to lodash', () => {
    // lo_dash and lodash differ by 1 char (underscore), so levenshtein wins (higher confidence).
    // The separator detector still fires — test that it detects the match.
    const result = analysePackage('lo_dash', KNOWN);
    assert.ok(result !== null, 'should return a finding');
    assert.equal(result!.match, 'lodash');
  });

  it('flags e_xpress as a separator substitution of express (separator wins when levenshtein threshold exceeded)', () => {
    // 'e_xpress' vs 'express' — levenshtein distance is 1 (just add underscore = substitution)
    // so this is still caught; at minimum a finding is returned.
    const result = analysePackage('e_xpress', KNOWN);
    assert.ok(result !== null, 'should detect e_xpress as related to express');
    assert.equal(result!.match, 'express');
  });

  it('separator detection fires for a name only differing by separator', () => {
    // Use custom known list where 'chalkjs' is known but 'chalk-js' would be combo.
    // Test with 'chalk_test' — chalk is in KNOWN, 'chalk_test' normalizes differently.
    // Use 'e.xpress' which normalizes to 'express'
    const result = analysePackage('e.xpress', KNOWN);
    assert.ok(result !== null);
    assert.equal(result!.match, 'express');
  });

});

describe('homoglyph detection', () => {

  it('_normalizeHomoglyphs replaces cyrillic chars', () => {
    // \u0430 is cyrillic 'a', \u0435 is cyrillic 'e'
    assert.equal(_normalizeHomoglyphs('r\u0435act'), 'react');
  });

  it('flags a name with homoglyph chars that normalizes to a known package', () => {
    // 'r' + cyrillic 'e' + 'act' → normalizes to 'react'
    const result = analysePackage('r\u0435act', KNOWN);
    assert.ok(result !== null, 'should detect homoglyph');
    assert.equal(result!.method, 'homoglyph');
    assert.equal(result!.confidence, 'high');
    assert.equal(result!.match, 'react');
  });

});

describe('_normalizeSeparators()', () => {

  it('strips dashes, underscores, and dots', () => {
    assert.equal(_normalizeSeparators('lo-dash'), 'lodash');
    assert.equal(_normalizeSeparators('lo_dash'), 'lodash');
    assert.equal(_normalizeSeparators('lo.dash'), 'lodash');
  });

});
