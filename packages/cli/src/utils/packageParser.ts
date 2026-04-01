import fs from 'fs';
import path from 'path';

export interface ParsedPackageJson {
  name: string;
  version: string;
  license: string | null;
  allPackages: string[];
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  peerDependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
}

/**
 * Reads and parses a project's package.json file.
 *
 * Extracts all dependency types:
 *   - dependencies         (runtime)
 *   - devDependencies      (development)
 *   - peerDependencies     (peer)
 *   - optionalDependencies (optional)
 *
 * @throws {Error} If package.json is missing or unparseable
 */
export function parsePackageJson(projectPath: string = process.cwd()): ParsedPackageJson {
  const pkgPath = path.resolve(projectPath, 'package.json');

  if (!fs.existsSync(pkgPath)) {
    throw new Error(`No package.json found at: ${pkgPath}`);
  }

  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as Record<string, unknown>;
  } catch (err) {
    throw new Error(`Failed to parse package.json: ${(err as Error).message}`);
  }

  const deps     = _sanitiseDeps(raw.dependencies,         'dependencies');
  const devDeps  = _sanitiseDeps(raw.devDependencies,      'devDependencies');
  const peerDeps = _sanitiseDeps(raw.peerDependencies,     'peerDependencies');
  const optDeps  = _sanitiseDeps(raw.optionalDependencies, 'optionalDependencies');

  // Build a deduplicated flat list of all package names
  const allPackages = [
    ...new Set([
      ...Object.keys(deps),
      ...Object.keys(devDeps),
      ...Object.keys(peerDeps),
      ...Object.keys(optDeps),
    ])
  ];

  // Normalise top-level scalar fields defensively
  const name    = typeof raw.name    === 'string' ? raw.name    : 'unknown';
  const version = typeof raw.version === 'string' ? raw.version : '0.0.0';
  const license = typeof raw.license === 'string' ? raw.license : null;

  return {
    name,
    version,
    license,
    allPackages,
    dependencies:         deps,
    devDependencies:      devDeps,
    peerDependencies:     peerDeps,
    optionalDependencies: optDeps,
  };
}

/**
 * Safely extracts a dependency map from a raw package.json field.
 *
 * Accepts only plain objects whose values are strings.
 * Non-object fields and entries with non-string values are skipped with a warning,
 * so a malformed package.json never injects garbage into downstream detectors.
 */
function _sanitiseDeps(raw: unknown, fieldName: string): Record<string, string> {
  if (raw == null) return {};

  if (typeof raw !== 'object' || Array.isArray(raw)) {
    console.warn(`  Warning: package.json "${fieldName}" is not an object — skipping`);
    return {};
  }

  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof value === 'string') {
      result[key] = value;
    } else {
      console.warn(`  Warning: package.json "${fieldName}.${key}" has non-string value — skipping`);
    }
  }
  return result;
}
