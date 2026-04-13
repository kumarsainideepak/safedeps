/**
 * npm Registry API client
 *
 * Used as a fallback when a package's license cannot be read from the local
 * node_modules directory (e.g. package is not installed, monorepo layout, etc.)
 *
 * Endpoint: GET https://registry.npmjs.org/<name>/<version>
 *   — Returns the package manifest for a specific version.
 *   — No API key required.
 *   — No published rate limit (fair-use; well-behaved clients are fine).
 *
 * Scoped packages (@scope/name) are handled by percent-encoding the slash
 * in the scope segment: @scope%2Fname.
 */

import { USER_AGENT } from '../utils/constants';
import { fetchWithRetry } from '../utils/httpRetry';

const REGISTRY_BASE = 'https://registry.npmjs.org';
const TIMEOUT_MS    = 8_000;

export interface NpmPackageMetadata {
  name:    string;
  version: string;
  license: string | null;
}

/**
 * Builds the registry URL for a package version.
 * Handles scoped packages by encoding only the inner slash (@scope%2Fname).
 */
function registryUrl(name: string, version = 'latest'): string {
  if (name.startsWith('@')) {
    // @scope/pkg → @scope%2Fpkg  (encode only the slash between scope and name)
    const encoded = '@' + encodeURIComponent(name.slice(1));
    return `${REGISTRY_BASE}/${encoded}/${version}`;
  }
  return `${REGISTRY_BASE}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
}

/**
 * Fetches the license field for a single npm package from the registry.
 *
 * The license field in package.json can be:
 *   - A string: "MIT"
 *   - An object (deprecated format): { "type": "MIT", "url": "..." }
 *   - An array of objects (rare): [{ "type": "MIT" }]
 *   - Missing / null
 */
export async function fetchNpmLicense(
  name: string,
  version = 'latest',
): Promise<NpmPackageMetadata> {
  const url = registryUrl(name, version);

  let response: Response;
  try {
    response = await fetchWithRetry(
      url,
      { headers: { Accept: 'application/json', 'User-Agent': USER_AGENT } },
      { timeoutMs: TIMEOUT_MS },
    );
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      throw new Error(`npm registry timed out for ${name}`);
    }
    throw new Error(`npm registry network error for ${name}: ${(err as Error).message}`);
  }

  if (!response.ok) {
    throw new Error(`npm registry returned HTTP ${response.status} for ${name}`);
  }

  const data = await response.json() as Record<string, unknown>;
  const license = _extractLicense(data);

  return {
    name,
    version: (data.version as string) ?? version,
    license,
  };
}

/** Extracts the license value from a raw package.json manifest object. */
function _extractLicense(data: Record<string, unknown>): string | null {
  const raw = data.license;

  if (typeof raw === 'string') return raw || null;

  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return (raw as { type?: string }).type ?? null;
  }

  // Old "licenses" array format
  if (Array.isArray(data.licenses) && data.licenses.length > 0) {
    const first = data.licenses[0] as Record<string, string>;
    return first.type ?? first.name ?? null;
  }

  return null;
}

// ─── Packument (full package document) ────────────────────────────────────

export interface NpmMaintainer {
  name:   string;
  email?: string;
}

export interface NpmPackumentInfo {
  name:                      string;
  latestVersion:             string;
  lastPublished:             Date | null;      // time.modified from packument
  createdAt:                 Date | null;      // time.created from packument
  publishedVersions:         number;           // total number of published versions
  maintainers:               NpmMaintainer[];
  repositoryUrl:             string | null;    // raw repository field → normalised URL
  previousVersionPublisher?: string | null;    // _npmUser.name from 2nd-to-last version
}

/**
 * Fetches the full package document (packument) from the npm registry.
 * Returns maintainers, last-published date, and repository URL.
 *
 * Uses a 15 s timeout — packuments for popular packages can be several MB.
 */
export async function fetchNpmPackumentInfo(name: string): Promise<NpmPackumentInfo> {
  const url = name.startsWith('@')
    ? `${REGISTRY_BASE}/@${encodeURIComponent(name.slice(1))}`
    : `${REGISTRY_BASE}/${name}`;

  let response: Response;
  try {
    response = await fetchWithRetry(
      url,
      { headers: { Accept: 'application/json', 'User-Agent': USER_AGENT } },
      { timeoutMs: 15_000 },
    );
  } catch (err) {
    if ((err as Error).name === 'AbortError') throw new Error(`npm registry timed out for ${name}`);
    throw new Error(`npm registry network error for ${name}: ${(err as Error).message}`);
  }

  if (!response.ok) throw new Error(`npm registry returned HTTP ${response.status} for ${name}`);

  const data = await response.json() as Record<string, unknown>;

  // Timestamps — top-level `time` map in packument
  const timeMap = data.time as Record<string, string> | undefined;

  let lastPublished: Date | null = null;
  if (timeMap?.modified) {
    const d = new Date(timeMap.modified);
    if (!isNaN(d.getTime())) lastPublished = d;
  }

  let createdAt: Date | null = null;
  if (timeMap?.created) {
    const d = new Date(timeMap.created);
    if (!isNaN(d.getTime())) createdAt = d;
  }

  // Published versions count (excludes 'created' and 'modified' meta-keys)
  const publishedVersions = timeMap
    ? Object.keys(timeMap).filter(k => k !== 'created' && k !== 'modified').length
    : 0;

  // Maintainers — top-level array in packument
  const rawMaintainers = Array.isArray(data.maintainers)
    ? (data.maintainers as Array<{ name?: string; email?: string }>)
    : [];
  const maintainers: NpmMaintainer[] = rawMaintainers
    .filter(m => typeof m.name === 'string')
    .map(m => ({ name: m.name as string, email: m.email }));

  // Repository URL
  const repositoryUrl = _extractRepositoryUrl(data.repository);

  const distTags = data['dist-tags'] as Record<string, string> | undefined;

  // Extract previous version publisher from packument versions
  const previousVersionPublisher = _extractPreviousPublisher(data, timeMap, distTags?.latest);

  return {
    name,
    latestVersion:     distTags?.latest ?? '',
    lastPublished,
    createdAt,
    publishedVersions,
    maintainers,
    repositoryUrl,
    previousVersionPublisher,
  };
}

/**
 * Extracts the _npmUser.name from the second-to-last published version.
 * Used for maintainer takeover detection — comparing current vs. previous publisher.
 */
function _extractPreviousPublisher(
  data: Record<string, unknown>,
  timeMap: Record<string, string> | undefined,
  latestVersion: string | undefined,
): string | null {
  if (!timeMap || !latestVersion) return null;

  const versions = data.versions as Record<string, Record<string, unknown>> | undefined;
  if (!versions) return null;

  // Get version list sorted by publish time (newest first)
  const versionEntries = Object.keys(timeMap)
    .filter(k => k !== 'created' && k !== 'modified')
    .sort((a, b) => new Date(timeMap[b]).getTime() - new Date(timeMap[a]).getTime());

  if (versionEntries.length < 2) return null;

  // Find the second-to-last version (the one before latest)
  const previousVersion = versionEntries[1];
  const prevManifest = versions[previousVersion];
  if (!prevManifest) return null;

  const npmUser = prevManifest._npmUser as { name?: string } | undefined;
  return npmUser?.name ?? null;
}

function _extractRepositoryUrl(repo: unknown): string | null {
  if (!repo) return null;
  if (typeof repo === 'string') return repo;
  if (typeof repo === 'object') {
    const r = repo as { url?: string; directory?: string };
    return r.url ?? null;
  }
  return null;
}

/**
 * Fetches an npm account's creation date.
 * Uses the CouchDB user endpoint — publicly accessible, best-effort.
 *
 * @returns  Date the account was created, or null if unavailable.
 */
export async function fetchNpmAccountAge(username: string): Promise<Date | null> {
  const url = `${REGISTRY_BASE}/-/user/org.couchdb.user/${encodeURIComponent(username)}`;

  try {
    const response = await fetchWithRetry(
      url,
      { headers: { Accept: 'application/json', 'User-Agent': USER_AGENT } },
      { timeoutMs: 6_000 },
    );

    if (!response.ok) return null;

    const data = await response.json() as Record<string, unknown>;
    const dateStr = data.date as string | undefined;
    if (!dateStr) return null;

    const d = new Date(dateStr);
    return isNaN(d.getTime()) ? null : d;
  } catch {
    return null;
  }
}

// ─── Version manifest (for diff command) ──────────────────────────────────

export interface VersionManifestRaw {
  name:            string;
  version:         string;
  dependencies:    Record<string, string>;
  devDependencies: Record<string, string>;
  scripts:         Record<string, string>;
  publisher:       string | null;     // _npmUser.name
}

/**
 * Fetches a specific version manifest from the npm registry.
 * Used by `safedeps diff` to compare two package versions.
 */
export async function fetchVersionManifest(
  name: string,
  version: string,
): Promise<VersionManifestRaw> {
  const url = registryUrl(name, version);

  let response: Response;
  try {
    response = await fetchWithRetry(
      url,
      { headers: { Accept: 'application/json', 'User-Agent': USER_AGENT } },
      { timeoutMs: TIMEOUT_MS },
    );
  } catch (err) {
    if ((err as Error).name === 'AbortError') throw new Error(`npm registry timed out for ${name}@${version}`);
    throw new Error(`npm registry network error for ${name}@${version}: ${(err as Error).message}`);
  }

  if (!response.ok) throw new Error(`npm registry returned HTTP ${response.status} for ${name}@${version}`);

  const data = await response.json() as Record<string, unknown>;

  const npmUser = data._npmUser as { name?: string } | undefined;

  return {
    name,
    version: (data.version as string) ?? version,
    dependencies:    (data.dependencies    as Record<string, string>) ?? {},
    devDependencies: (data.devDependencies as Record<string, string>) ?? {},
    scripts:         (data.scripts         as Record<string, string>) ?? {},
    publisher:       npmUser?.name ?? null,
  };
}

// ─── Batch license fetch ───────────────────────────────────────────────────

/**
 * Batch-fetches licenses for multiple packages with a concurrency cap.
 *
 * @returns Map of package name → raw license string (null if unresolvable)
 */
export async function batchFetchLicenses(
  packages: Array<{ name: string; version?: string }>,
  concurrency = 10,
): Promise<Map<string, string | null>> {
  const results = new Map<string, string | null>();

  for (let i = 0; i < packages.length; i += concurrency) {
    const chunk   = packages.slice(i, i + concurrency);
    const settled = await Promise.allSettled(
      chunk.map(p => fetchNpmLicense(p.name, p.version ?? 'latest')),
    );

    for (let j = 0; j < chunk.length; j++) {
      const outcome = settled[j];
      if (outcome.status === 'fulfilled') {
        results.set(chunk[j].name, outcome.value.license);
      } else {
        results.set(chunk[j].name, null);
      }
    }
  }

  return results;
}
