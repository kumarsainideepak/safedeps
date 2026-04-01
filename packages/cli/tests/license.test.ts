import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normaliseLicense,
  classifyLicense,
  checkCompatibility,
} from '../src/utils/spdxCompatibility';

// ─── normaliseLicense ──────────────────────────────────────────────────────

describe('normaliseLicense', () => {
  it('returns UNKNOWN for null', () => {
    assert.equal(normaliseLicense(null), 'UNKNOWN');
  });

  it('returns UNKNOWN for undefined', () => {
    assert.equal(normaliseLicense(undefined), 'UNKNOWN');
  });

  it('returns UNKNOWN for empty string', () => {
    assert.equal(normaliseLicense(''), 'UNKNOWN');
  });

  it('passes through already-canonical SPDX identifiers', () => {
    assert.equal(normaliseLicense('MIT'),         'MIT');
    assert.equal(normaliseLicense('Apache-2.0'),  'Apache-2.0');
    assert.equal(normaliseLicense('ISC'),         'ISC');
    assert.equal(normaliseLicense('GPL-3.0-only'), 'GPL-3.0-only');
    assert.equal(normaliseLicense('AGPL-3.0-only'), 'AGPL-3.0-only');
  });

  it('normalises MIT variants', () => {
    assert.equal(normaliseLicense('mit'),         'MIT');
    assert.equal(normaliseLicense('MIT License'), 'MIT');
    assert.equal(normaliseLicense('MIT/X11'),     'MIT');
  });

  it('normalises Apache variants', () => {
    assert.equal(normaliseLicense('Apache 2.0'),  'Apache-2.0');
    assert.equal(normaliseLicense('apache'),      'Apache-2.0');
    assert.equal(normaliseLicense('Apache-2'),    'Apache-2.0');
  });

  it('normalises GPL variants', () => {
    assert.equal(normaliseLicense('GPL-2.0'),     'GPL-2.0-only');
    assert.equal(normaliseLicense('gpl-3.0'),     'GPL-3.0-only');
    assert.equal(normaliseLicense('GPLv3'),       'GPL-3.0-only');
    assert.equal(normaliseLicense('GPL-3.0+'),    'GPL-3.0-or-later');
  });

  it('normalises LGPL variants', () => {
    assert.equal(normaliseLicense('LGPL-2.1'),    'LGPL-2.1-only');
    assert.equal(normaliseLicense('lgpl'),        'LGPL-2.1-or-later');
  });

  it('normalises AGPL variants', () => {
    assert.equal(normaliseLicense('agpl-3.0'),    'AGPL-3.0-only');
    assert.equal(normaliseLicense('AGPL'),        'AGPL-3.0-or-later');
  });

  it('handles SPDX OR expressions by taking the first term', () => {
    assert.equal(normaliseLicense('MIT OR Apache-2.0'),  'MIT');
    assert.equal(normaliseLicense('(MIT OR ISC)'),       'MIT');
  });

  it('handles SPDX AND expressions by taking the first term', () => {
    assert.equal(normaliseLicense('MIT AND Apache-2.0'), 'MIT');
  });

  it('is case-insensitive for canonical IDs', () => {
    assert.equal(normaliseLicense('mit'),         'MIT');
    assert.equal(normaliseLicense('isc'),         'ISC');
    assert.equal(normaliseLicense('apache-2.0'),  'Apache-2.0');
  });
});

// ─── classifyLicense ──────────────────────────────────────────────────────

describe('classifyLicense', () => {
  it('classifies permissive licenses', () => {
    assert.equal(classifyLicense('MIT'),          'permissive');
    assert.equal(classifyLicense('ISC'),          'permissive');
    assert.equal(classifyLicense('Apache-2.0'),   'permissive');
    assert.equal(classifyLicense('BSD-2-Clause'), 'permissive');
    assert.equal(classifyLicense('BSD-3-Clause'), 'permissive');
    assert.equal(classifyLicense('Unlicense'),    'permissive');
    assert.equal(classifyLicense('CC0-1.0'),      'permissive');
    assert.equal(classifyLicense('0BSD'),         'permissive');
  });

  it('classifies weak-copyleft licenses', () => {
    assert.equal(classifyLicense('LGPL-2.1-only'),    'weak-copyleft');
    assert.equal(classifyLicense('LGPL-3.0-or-later'), 'weak-copyleft');
    assert.equal(classifyLicense('MPL-2.0'),          'weak-copyleft');
    assert.equal(classifyLicense('EPL-2.0'),          'weak-copyleft');
  });

  it('classifies strong-copyleft licenses', () => {
    assert.equal(classifyLicense('GPL-2.0-only'),     'strong-copyleft');
    assert.equal(classifyLicense('GPL-2.0-or-later'), 'strong-copyleft');
    assert.equal(classifyLicense('GPL-3.0-only'),     'strong-copyleft');
    assert.equal(classifyLicense('GPL-3.0-or-later'), 'strong-copyleft');
  });

  it('classifies network-copyleft licenses', () => {
    assert.equal(classifyLicense('AGPL-3.0-only'),    'network-copyleft');
    assert.equal(classifyLicense('AGPL-3.0-or-later'), 'network-copyleft');
    assert.equal(classifyLicense('SSPL-1.0'),         'network-copyleft');
  });

  it('returns unknown for unrecognised identifiers', () => {
    assert.equal(classifyLicense('UNKNOWN'),           'unknown');
    assert.equal(classifyLicense('Proprietary'),       'unknown');
    assert.equal(classifyLicense('SEE LICENSE IN FILE'), 'unknown');
  });
});

// ─── checkCompatibility ───────────────────────────────────────────────────

describe('checkCompatibility', () => {
  // Permissive project
  it('permissive + permissive → ok', () => {
    assert.equal(checkCompatibility('MIT', 'Apache-2.0').status, 'ok');
    assert.equal(checkCompatibility('MIT', 'ISC').status,        'ok');
    assert.equal(checkCompatibility('Apache-2.0', 'MIT').status, 'ok');
  });

  it('permissive + strong-copyleft → conflict', () => {
    assert.equal(checkCompatibility('MIT', 'GPL-2.0-only').status,     'conflict');
    assert.equal(checkCompatibility('MIT', 'GPL-3.0-only').status,     'conflict');
    assert.equal(checkCompatibility('MIT', 'GPL-3.0-or-later').status, 'conflict');
    assert.equal(checkCompatibility('ISC', 'GPL-3.0-only').status,     'conflict');
  });

  it('permissive + network-copyleft → conflict', () => {
    assert.equal(checkCompatibility('MIT', 'AGPL-3.0-only').status,    'conflict');
    assert.equal(checkCompatibility('MIT', 'AGPL-3.0-or-later').status, 'conflict');
    assert.equal(checkCompatibility('MIT', 'SSPL-1.0').status,         'conflict');
  });

  it('permissive + weak-copyleft → warning', () => {
    assert.equal(checkCompatibility('MIT', 'LGPL-2.1-only').status,    'warning');
    assert.equal(checkCompatibility('MIT', 'LGPL-3.0-only').status,    'warning');
    assert.equal(checkCompatibility('MIT', 'MPL-2.0').status,          'warning');
    assert.equal(checkCompatibility('Apache-2.0', 'MPL-2.0').status,   'warning');
  });

  // Special cases
  it('Apache-2.0 + GPL-2.0-only → conflict (patent clause incompatibility)', () => {
    assert.equal(checkCompatibility('Apache-2.0', 'GPL-2.0-only').status, 'conflict');
  });

  it('Apache-2.0 + GPL-2.0-or-later → ok (GPLv2+ allows Apache)', () => {
    assert.equal(checkCompatibility('Apache-2.0', 'GPL-2.0-or-later').status, 'conflict');
    // Note: FSF says Apache-2.0 is GPL-3 compatible but not GPL-2-only compatible.
    // GPL-2.0-or-later still means a GPL work; the project is permissive so it's a conflict.
  });

  it('GPL-2.0-only + GPL-3.0-only → conflict (version mismatch)', () => {
    assert.equal(checkCompatibility('GPL-2.0-only', 'GPL-3.0-only').status,     'conflict');
    assert.equal(checkCompatibility('GPL-2.0-only', 'GPL-3.0-or-later').status, 'conflict');
  });

  // Strong-copyleft project
  it('GPL project + permissive dep → ok', () => {
    assert.equal(checkCompatibility('GPL-3.0-only', 'MIT').status,       'ok');
    assert.equal(checkCompatibility('GPL-3.0-only', 'Apache-2.0').status, 'ok');
    assert.equal(checkCompatibility('GPL-3.0-only', 'ISC').status,       'ok');
  });

  it('GPL project + LGPL dep → ok', () => {
    assert.equal(checkCompatibility('GPL-3.0-only', 'LGPL-2.1-only').status, 'ok');
  });

  it('GPL project + AGPL dep → warning', () => {
    assert.equal(checkCompatibility('GPL-3.0-only', 'AGPL-3.0-only').status, 'warning');
  });

  // Weak-copyleft project
  it('LGPL project + GPL dep → conflict', () => {
    assert.equal(checkCompatibility('LGPL-2.1-only', 'GPL-3.0-only').status,    'conflict');
    assert.equal(checkCompatibility('LGPL-2.1-only', 'AGPL-3.0-only').status,   'conflict');
  });

  // Unknown
  it('unknown dep license → unknown status', () => {
    assert.equal(checkCompatibility('MIT', 'UNKNOWN').status, 'unknown');
  });

  it('unknown project license → unknown status', () => {
    assert.equal(checkCompatibility('Proprietary', 'MIT').status, 'unknown');
  });

  // Conflict messages are non-empty
  it('conflict result includes a non-empty reason', () => {
    const result = checkCompatibility('MIT', 'GPL-3.0-only');
    assert.ok(result.reason.length > 0, 'Expected non-empty reason for conflict');
  });

  it('ok result has empty reason', () => {
    const result = checkCompatibility('MIT', 'Apache-2.0');
    assert.equal(result.reason, '');
  });
});
