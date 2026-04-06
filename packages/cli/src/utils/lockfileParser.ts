import fs from 'fs';
import path from 'path';

interface LockfileV1Entry {
  version: string;
  dependencies?: Record<string, LockfileV1Entry>;
}

interface LockfileV2Entry {
  version?: string;
  name?: string;
}

interface Lockfile {
  lockfileVersion?: number;
  packages?: Record<string, LockfileV2Entry>;
  dependencies?: Record<string, LockfileV1Entry>;
}

/**
 * Parses package-lock.json to extract the exact resolved version
 * for every installed package.
 *
 * Supports lockfile v1 (npm 6), v2 and v3 (npm 7+) formats.
 *
 * @returns Map of package name → resolved version.
 *   Returns empty Map if no lockfile found (graceful degradation).
 */
export function parseLockfile(projectPath: string = process.cwd()): Map<string, string> {
  const lockPath = path.resolve(projectPath, 'package-lock.json');

  if (!fs.existsSync(lockPath)) {
    // Graceful: scan continues without exact versions
    return new Map();
  }

  let raw: Lockfile;
  try {
    raw = JSON.parse(fs.readFileSync(lockPath, 'utf8')) as Lockfile;
  } catch (err) {
    console.warn(`  Warning: Could not parse package-lock.json: ${(err as Error).message}`);
    return new Map();
  }

  const versions = new Map<string, string>();
  const lockVersion = raw.lockfileVersion ?? 1;

  if (lockVersion >= 2 && raw.packages) {
    // v2/v3: flat packages map with "node_modules/package-name" keys.
    // Nested deduped packages use paths like "node_modules/express/node_modules/body-parser".
    // We extract the final package segment after the last "node_modules/" occurrence.
    // First-wins: top-level entries appear first in JSON order and take precedence over
    // deeply-nested copies of the same package.
    for (const [key, entry] of Object.entries(raw.packages)) {
      if (!key || key === '') continue;

      const lastNm = key.lastIndexOf('node_modules/');
      if (lastNm === -1) continue;

      const name = key.slice(lastNm + 'node_modules/'.length);
      if (name && entry.version && !versions.has(name)) {
        versions.set(name, entry.version);
      }
    }
  } else if (raw.dependencies) {
    // v1: nested dependencies map
    _extractV1Deps(raw.dependencies, versions);
  }

  return versions;
}

/**
 * Returns all packages installed in the lockfile (direct + transitive),
 * each with their exact resolved version.
 *
 * Used by the CVE scanner to catch vulnerabilities in transitive dependencies
 * that are not listed in package.json but are present in node_modules.
 *
 * @returns Array of { name, version } for every installed package.
 *   Returns empty array if no lockfile found.
 */
export function parseAllLockfilePackages(projectPath: string = process.cwd()): Array<{ name: string; version: string }> {
  const versions = parseLockfile(projectPath);
  return [...versions.entries()].map(([name, version]) => ({ name, version }));
}

/**
 * Recursively extracts versions from v1 lockfile dependency tree.
 */
function _extractV1Deps(deps: Record<string, LockfileV1Entry>, map: Map<string, string>): void {
  for (const [name, entry] of Object.entries(deps)) {
    // First-wins: top-level entry takes precedence over nested duplicates
    if (entry.version && !map.has(name)) {
      map.set(name, entry.version);
    }
    // v1 can have nested deps inside each dependency
    if (entry.dependencies) {
      _extractV1Deps(entry.dependencies, map);
    }
  }
}
