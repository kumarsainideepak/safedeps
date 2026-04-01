import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { levenshtein } from '../src/utils/levenshtein';

describe('levenshtein()', () => {

  it('returns 0 for identical strings', () => {
    assert.equal(levenshtein('lodash', 'lodash'), 0);
    assert.equal(levenshtein('react', 'react'), 0);
    assert.equal(levenshtein('', ''), 0);
  });

  it('returns full length when one string is empty', () => {
    assert.equal(levenshtein('', 'react'), 5);
    assert.equal(levenshtein('react', ''), 5);
  });

  it('detects single character swap (lodash typosquat)', () => {
    // lodahs = swap last two chars of lodash
    assert.equal(levenshtein('lodash', 'lodahs'), 2);
  });

  it('detects single character swap (react typosquat)', () => {
    // recat = swap 'a' and 'c'
    assert.equal(levenshtein('react', 'recat'), 2);
  });

  it('detects one missing character (express typosquat)', () => {
    assert.equal(levenshtein('express', 'expres'), 1);
  });

  it('detects one extra character', () => {
    assert.equal(levenshtein('lodash', 'lodashh'), 1);
  });

  it('detects one substitution', () => {
    assert.equal(levenshtein('lodash', 'lodish'), 1);
  });

  it('handles completely different strings', () => {
    assert.ok(levenshtein('react', 'mongodb') > 4);
  });

  it('is symmetric', () => {
    assert.equal(
      levenshtein('lodash', 'lodahs'),
      levenshtein('lodahs', 'lodash')
    );
  });

});
