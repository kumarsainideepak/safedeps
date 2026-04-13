/**
 * CycloneDX 1.5 BOM Generator
 *
 * Produces a CycloneDX 1.5 JSON Software Bill of Materials (SBOM) for an
 * npm project. The BOM includes all production (and optionally dev)
 * dependencies with:
 *   - Package name + version
 *   - PURL (pkg:npm/<name>@<version>)
 *   - License identifier (from node_modules or lockfile)
 *   - SRI integrity hash (from lockfile)
 *
 * Spec: https://cyclonedx.org/specification/overview/
 */

import { randomUUID } from 'crypto';
import type { ParsedPackageJson } from '../utils/packageParser';

// ─── CycloneDX types ───────────────────────────────────────────────────────

export interface CdxLicense {
  license: { id: string };
}

export interface CdxHash {
  alg:     string;
  content: string;
}

export interface CdxComponent {
  type:      'library';
  name:      string;
  version:   string;
  purl?:     string;
  licenses?: CdxLicense[];
  hashes?:   CdxHash[];
}

export interface CdxMetadata {
  timestamp: string;
  tools: Array<{ name: string; version: string; vendor: string }>;
  component: {
    type:    'application';
    name:    string;
    version: string;
  };
}

export interface CdxBom {
  bomFormat:    'CycloneDX';
  specVersion:  '1.5';
  serialNumber: string;       // urn:uuid:<uuid>
  version:      number;
  metadata:     CdxMetadata;
  components:   CdxComponent[];
}

// ─── PURL builder ──────────────────────────────────────────────────────────

/**
 * Builds a Package URL (PURL) for an npm package.
 * Spec: https://github.com/package-url/purl-spec
 *
 * Scoped packages: @scope/name → pkg:npm/%40scope%2Fname@version
 * The PURL spec encodes the leading '@' in scoped names.
 */
export function buildPurl(name: string, version: string): string {
  if (name.startsWith('@')) {
    // Encode '@scope/name' → '%40scope%2Fname' per PURL spec
    const encoded = encodeURIComponent(name);
    return `pkg:npm/${encoded}@${version}`;
  }
  return `pkg:npm/${name}@${version}`;
}

// ─── Hash parsing ──────────────────────────────────────────────────────────

/**
 * Converts a lockfile SRI integrity string into CycloneDX hash entries.
 * SRI format: "sha512-<base64> sha256-<base64>"
 * CycloneDX alg names: SHA-512, SHA-256
 */
export function parseSriToHashes(integrity: string): CdxHash[] {
  const ALG_MAP: Record<string, string> = {
    sha512: 'SHA-512',
    sha256: 'SHA-256',
    sha384: 'SHA-384',
    sha1:   'SHA-1',
  };

  return integrity
    .split(/\s+/)
    .filter(Boolean)
    .map(entry => {
      const dashIdx = entry.indexOf('-');
      if (dashIdx === -1) return null;
      const alg     = entry.slice(0, dashIdx).toLowerCase();
      const content = entry.slice(dashIdx + 1);
      const cdxAlg  = ALG_MAP[alg];
      if (!cdxAlg || !content) return null;
      return { alg: cdxAlg, content };
    })
    .filter((h): h is CdxHash => h !== null);
}

// ─── BOM generator ─────────────────────────────────────────────────────────

export interface GenerateBomOptions {
  /** Map of package name → license string (null if unknown) */
  packageMeta?: Map<string, { license: string | null; integrity?: string }>;
  /** Map of package name → SRI integrity hash (from lockfile) */
  integrityMap?: Map<string, string>;
  /** Include devDependencies? (default false) */
  includeDev?: boolean;
  /** Project name for metadata component */
  projectName?: string;
  /** Project version for metadata component */
  projectVersion?: string;
  /** safedeps version for tools metadata */
  toolVersion?: string;
}

export function generateCycloneDxBom(
  parsedPackageJson: ParsedPackageJson,
  lockVersions: Map<string, string>,
  options: GenerateBomOptions = {},
): CdxBom {
  const {
    packageMeta   = new Map(),
    integrityMap  = new Map(),
    includeDev    = false,
    projectName   = 'unknown',
    projectVersion = '0.0.0',
    toolVersion   = '1.1.0',
  } = options;

  // Determine which packages to include
  const depNames = new Set<string>(Object.keys(parsedPackageJson.dependencies));
  if (includeDev) {
    for (const name of Object.keys(parsedPackageJson.devDependencies ?? {})) {
      depNames.add(name);
    }
  }

  const components: CdxComponent[] = [];

  for (const name of depNames) {
    const version = lockVersions.get(name) ?? '(unknown)';
    const meta    = packageMeta.get(name);
    const integ   = meta?.integrity ?? integrityMap.get(name);

    const component: CdxComponent = {
      type:    'library',
      name,
      version,
      purl:    buildPurl(name, version),
    };

    const license = meta?.license;
    if (license) {
      component.licenses = [{ license: { id: license } }];
    }

    if (integ) {
      const hashes = parseSriToHashes(integ);
      if (hashes.length > 0) {
        component.hashes = hashes;
      }
    }

    components.push(component);
  }

  // Sort alphabetically for deterministic output
  components.sort((a, b) => a.name.localeCompare(b.name));

  return {
    bomFormat:    'CycloneDX',
    specVersion:  '1.5',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version:      1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: 'safedeps', version: toolVersion, vendor: 'SafeDeps' }],
      component: {
        type:    'application',
        name:    projectName,
        version: projectVersion,
      },
    },
    components,
  };
}
