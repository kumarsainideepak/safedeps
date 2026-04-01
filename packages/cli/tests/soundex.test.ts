import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { soundex, soundexMatch } from '../src/utils/soundex';

describe('soundex()', () => {

  it('produces a 4-character code', () => {
    assert.equal(soundex('react').length, 4);
    assert.equal(soundex('lodash').length, 4);
  });

  it('returns same code for react and recat', () => {
    assert.equal(soundex('react'), soundex('recat'));
  });

  it('returns same code for lodash and lodahs', () => {
    assert.equal(soundex('lodash'), soundex('lodahs'));
  });

  it('pads short names with zeros', () => {
    assert.equal(soundex('ax'), 'A200');
  });

  it('handles empty string gracefully', () => {
    assert.equal(soundex(''), '');
  });

});

describe('soundexMatch()', () => {

  it('matches phonetically similar names', () => {
    assert.ok(soundexMatch('react', 'recat'));
    assert.ok(soundexMatch('lodash', 'lodahs'));
  });

  it('does not match unrelated names', () => {
    assert.ok(!soundexMatch('react', 'express'));
    assert.ok(!soundexMatch('lodash', 'axios'));
  });

});
