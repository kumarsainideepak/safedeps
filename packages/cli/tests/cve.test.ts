import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanCVEs, _resolveVersionRange } from '../src/detectors/cve';
import type { OsvPackage, OsvResult } from '../src/sources/osv';
import type { OsvVuln } from '../src/utils/severity';

/**
 * CVE detector tests.
 *
 * scanCVEs accepts an injectable `queryFn` so tests run fully offline.
 * The real queryOSV HTTP call is never made here.
 */

// ── Fixtures ─────────────────────────────────────────────────────────────────

const MOCK_OSV_RESPONSES: Record<string, OsvVuln[]> = {
  'malware-pkg@1.0.0': [
    {
      id: 'MAL-2024-1234',
      summary: 'Malicious package detected',
      severity: [],
      affected: [{ ranges: [] }],
      references: [],
      database_specific: { severity: 'UNKNOWN' },
    },
  ],
  'lodash@4.17.20': [
    {
      id: 'GHSA-jf85-cpcp-j695',
      summary: 'Prototype Pollution in lodash',
      severity: [{ type: 'CVSS_V3', score: '7.4 CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N' }],
      affected: [{
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
      }],
      references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-jf85-cpcp-j695' }],
      database_specific: { severity: 'HIGH' },
    },
  ],
  'axios@0.21.1': [
    {
      id: 'GHSA-42xw-2xvc-qx8m',
      summary: 'Server-Side Request Forgery in axios',
      severity: [],
      affected: [{
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '0.21.2' }] }],
      }],
      references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-42xw-2xvc-qx8m' }],
      database_specific: { severity: 'MEDIUM' },
    },
  ],
};

async function mockQueryOSV(packages: OsvPackage[]): Promise<OsvResult[]> {
  return packages.map(pkg => ({
    name:  pkg.name,
    version: pkg.version,
    vulns: MOCK_OSV_RESPONSES[`${pkg.name}@${pkg.version}`] ?? [],
  }));
}

function makePkg(deps: Record<string, string>) {
  return {
    name: 'test-project',
    version: '1.0.0',
    license: null,
    allPackages: Object.keys(deps),
    dependencies: deps,
    devDependencies: {},
    peerDependencies: {},
    optionalDependencies: {},
  };
}

// ── scanCVEs() ────────────────────────────────────────────────────────────────

describe('scanCVEs() — with mocked OSV API', () => {

  it('returns empty findings for clean packages', async () => {
    const result = await scanCVEs(
      makePkg({ react: '18.0.0', chalk: '5.0.0' }),
      { queryFn: mockQueryOSV },
    );
    assert.equal(result.findings.length, 0);
    assert.equal(result.scanned, 2);
  });

  it('detects CVE in lodash@4.17.20', async () => {
    const result = await scanCVEs(
      makePkg({ lodash: '4.17.20' }),
      { queryFn: mockQueryOSV },
    );
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].name, 'lodash');
    assert.equal(result.findings[0].topSeverity, 'HIGH');
    assert.ok(result.findings[0].vulns[0].id.includes('GHSA'));
  });

  it('extracts fix version correctly', async () => {
    const result = await scanCVEs(
      makePkg({ lodash: '4.17.20' }),
      { queryFn: mockQueryOSV },
    );
    assert.ok(result.findings[0].vulns[0].fixedIn.includes('4.17.21'));
  });

  it('detects multiple vulnerable packages', async () => {
    const result = await scanCVEs(
      makePkg({ lodash: '4.17.20', axios: '0.21.1', react: '18.0.0' }),
      { queryFn: mockQueryOSV },
    );
    assert.equal(result.findings.length, 2);
  });

  it('sorts findings by severity (critical first)', async () => {
    const result = await scanCVEs(
      makePkg({ axios: '0.21.1', lodash: '4.17.20' }),
      { queryFn: mockQueryOSV },
    );
    assert.equal(result.findings[0].topSeverity, 'HIGH');
    assert.equal(result.findings[1].topSeverity, 'MEDIUM');
  });

  it('handles empty package list', async () => {
    const result = await scanCVEs(
      makePkg({}),
      { queryFn: mockQueryOSV },
    );
    assert.equal(result.findings.length, 0);
    assert.equal(result.scanned, 0);
  });

  it('respects minSeverity filter — skips MEDIUM when threshold is high', async () => {
    const result = await scanCVEs(
      makePkg({ axios: '0.21.1', lodash: '4.17.20' }),
      { minSeverity: 'high', queryFn: mockQueryOSV },
    );
    // axios is MEDIUM, lodash is HIGH — only lodash passes the filter
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].name, 'lodash');
  });

  it('skips packages with unresolvable versions', async () => {
    const result = await scanCVEs(
      makePkg({ lodash: '*', axios: '0.21.1' }),
      { queryFn: mockQueryOSV },
    );
    assert.equal(result.skipped, 1);
    assert.equal(result.scanned, 1);
  });

  it('counts scanned vs skipped correctly', async () => {
    const result = await scanCVEs(
      makePkg({ lodash: '4.17.20', bad: 'file:../local', axios: '0.21.1' }),
      { queryFn: mockQueryOSV },
    );
    assert.equal(result.scanned, 2);
    assert.equal(result.skipped, 1);
  });

  it('includes UNKNOWN severity vulns regardless of minSeverity filter', async () => {
    const result = await scanCVEs(
      makePkg({ 'malware-pkg': '1.0.0' }),
      { minSeverity: 'high', queryFn: mockQueryOSV },
    );
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].name, 'malware-pkg');
    assert.equal(result.findings[0].topSeverity, 'UNKNOWN');
  });

  it('propagates OSV query errors as thrown Error', async () => {
    const failingQuery = async () => { throw new Error('Network down'); };
    await assert.rejects(
      () => scanCVEs(makePkg({ lodash: '4.17.20' }), { queryFn: failingQuery }),
      /CVE scan failed/,
    );
  });

});

// ── _resolveVersionRange() ────────────────────────────────────────────────────

describe('_resolveVersionRange()', () => {

  it('returns null for empty / wildcard', () => {
    assert.equal(_resolveVersionRange(''), null);
    assert.equal(_resolveVersionRange('*'), null);
    assert.equal(_resolveVersionRange('x'), null);
  });

  it('strips caret and tilde', () => {
    assert.equal(_resolveVersionRange('^4.17.21'), '4.17.21');
    assert.equal(_resolveVersionRange('~1.2.3'),   '1.2.3');
  });

  it('strips >= range specifiers', () => {
    assert.equal(_resolveVersionRange('>=1.0.0'), '1.0.0');
    assert.equal(_resolveVersionRange('>=1.0.0 <2.0.0'), '1.0.0');
  });

  it('handles x-range wildcards', () => {
    assert.equal(_resolveVersionRange('1.x'),   '1.0.0');
    assert.equal(_resolveVersionRange('1.2.x'), '1.2.0');
  });

  it('strips workspace: protocol', () => {
    assert.equal(_resolveVersionRange('workspace:^1.0.0'), '1.0.0');
    assert.equal(_resolveVersionRange('workspace:*'), null);
  });

  it('returns null for file: and git: protocols', () => {
    assert.equal(_resolveVersionRange('file:../local'), null);
    assert.equal(_resolveVersionRange('git+https://github.com/foo/bar'), null);
  });

  it('resolves OR expressions to first valid term', () => {
    assert.equal(_resolveVersionRange('^1.0.0 || ^2.0.0'), '1.0.0');
  });

  it('handles npm: package alias', () => {
    assert.equal(_resolveVersionRange('npm:other-pkg@^1.2.3'), '1.2.3');
  });

  it('returns concrete versions as-is', () => {
    assert.equal(_resolveVersionRange('4.17.21'), '4.17.21');
    assert.equal(_resolveVersionRange('0.0.1'),   '0.0.1');
  });

});
