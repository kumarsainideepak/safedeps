import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normaliseVuln, highestSeverity } from '../src/utils/severity';
import type { OsvVuln } from '../src/utils/severity';

// Minimal OSV vuln fixture
const makeVuln = (overrides: Partial<OsvVuln> = {}): OsvVuln => ({
  id:      'GHSA-test-0000-0000',
  summary: 'Test vulnerability',
  severity: [],
  affected: [],
  references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-test-0000-0000' }],
  database_specific: {},
  ...overrides,
});

describe('normaliseVuln()', () => {

  it('extracts id and title', () => {
    const v = normaliseVuln(makeVuln({ id: 'CVE-2023-12345', summary: 'Prototype pollution' }));
    assert.equal(v.id, 'CVE-2023-12345');
    assert.equal(v.title, 'Prototype pollution');
  });

  it('uses database_specific.severity when no CVSS score', () => {
    const v = normaliseVuln(makeVuln({
      database_specific: { severity: 'HIGH' },
    }));
    assert.equal(v.severity, 'HIGH');
  });

  it('parses CVSS score prefix correctly', () => {
    const v = normaliseVuln(makeVuln({
      severity: [{ type: 'CVSS_V3', score: '9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    }));
    assert.equal(v.severity, 'CRITICAL');
    assert.equal(v.cvssScore, 9.8);
  });

  it('falls back to UNKNOWN when no severity info', () => {
    const v = normaliseVuln(makeVuln());
    assert.equal(v.severity, 'UNKNOWN');
    assert.equal(v.cvssScore, null);
  });

  it('extracts fix version from affected ranges', () => {
    const v = normaliseVuln(makeVuln({
      affected: [{
        ranges: [{
          type: 'ECOSYSTEM',
          events: [{ introduced: '0' }, { fixed: '4.17.21' }],
        }],
      }],
    }));
    assert.ok(v.fixedIn.includes('4.17.21'));
  });

  it('returns empty fixedIn when no fix available', () => {
    const v = normaliseVuln(makeVuln());
    assert.deepEqual(v.fixedIn, []);
  });

  it('prefers GitHub Advisory URL', () => {
    const v = normaliseVuln(makeVuln({
      references: [
        { type: 'WEB',      url: 'https://example.com/blog' },
        { type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-test-0000-0000' },
      ],
    }));
    assert.ok(v.url.includes('github.com/advisories'));
  });

  it('constructs NVD URL from CVE id when no refs', () => {
    const v = normaliseVuln(makeVuln({ id: 'CVE-2023-99999', references: [] }));
    assert.ok(v.url.includes('nvd.nist.gov'));
  });

});

describe('highestSeverity()', () => {

  it('returns CRITICAL when present', () => {
    assert.equal(highestSeverity(['LOW', 'CRITICAL', 'HIGH']), 'CRITICAL');
  });

  it('returns HIGH when no CRITICAL', () => {
    assert.equal(highestSeverity(['LOW', 'MEDIUM', 'HIGH']), 'HIGH');
  });

  it('returns UNKNOWN for empty array', () => {
    assert.equal(highestSeverity([]), 'UNKNOWN');
  });

});
