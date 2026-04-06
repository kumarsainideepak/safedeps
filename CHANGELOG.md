# Changelog

All notable changes to SafeDeps are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [v1.1.0] — 2026-04-06

### Added
- **Transitive dependency CVE scanning** (`src/utils/lockfileParser.ts`,
  `src/detectors/cve.ts`, `src/commands/scan.ts`): `safedeps scan` now scans
  all packages installed in `node_modules` — not just the direct dependencies
  listed in `package.json` — matching the coverage of `npm audit`.

  Previously, `safedeps scan` on a project with 33 direct dependencies would
  query OSV.dev for 33 packages. After this change it queries all 300 resolved
  packages from `package-lock.json`, surfacing vulnerabilities in transitive
  dependencies such as `body-parser`, `minimist`, `path-to-regexp`, `qs`, and
  `lodash` that were previously invisible.

  Implementation:
  - **`parseAllLockfilePackages()`** (`src/utils/lockfileParser.ts`): New export
    that converts the existing `parseLockfile()` `Map<name, version>` into a flat
    `Array<{ name, version }>` covering every entry in the lockfile.
  - **`lockfilePackages` option** (`src/detectors/cve.ts`): `ScanCveOptions`
    accepts an optional pre-built package list. When provided, `scanCVEs()` uses
    it directly (all versions are lockfile-exact); when absent, it falls back to
    the previous direct-deps-only behaviour for projects without a lockfile.
  - **`scan` command** (`src/commands/scan.ts`): Calls
    `parseAllLockfilePackages()` once alongside `parseLockfile()` and passes the
    result to `scanCVEs()`. Spinner text updated to show the total package count
    including transitive deps (e.g. `300 packages incl. transitive`).

---

## [v1.0.0] — 2026-04-05

### Fixed
- **CRITICAL — CVE findings always showed UNKNOWN severity**: The OSV `/v1/querybatch`
  endpoint returns only `{id, modified}` stubs — not full vulnerability objects. All
  severity extraction code (`_extractSeverity`, `_parseCvssScore`, `_computeCvssV3Score`)
  was receiving `undefined` for every field because the data simply wasn't in the batch
  response. Fixed with a two-phase fetch in `src/sources/osv.ts`:
  1. Querybatch to collect unique vuln IDs across all packages.
  2. Individual `/v1/vulns/{id}` fetches (concurrency 10, de-duplicated) to retrieve
     full details for each advisory.
  Running `safedeps check axios@0.21.1` now correctly shows `HIGH`; `lodash@4.17.4`
  shows `CRITICAL`. Verbose output now contains CVSS scores and advisory links.
- **"MODERATE" severity not recognised** (`src/utils/severity.ts`): GHSA advisories
  use `"Moderate"` (not `"Medium"`) in `database_specific.severity`. After
  `.toUpperCase()` the value `"MODERATE"` did not match any entry in
  `SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']` and fell
  through to `UNKNOWN`. Added `_normaliseSeverityAlias()` which maps
  `MODERATE → MEDIUM` and `NONE → LOW` before the severity level lookup.
- **`ERR_REQUIRE_ESM` crash for chalk and ora** (`src/reporters/terminal.ts`,
  `src/commands/scan.ts`): TypeScript with `module: commonjs` transforms
  `await import('chalk')` into `Promise.resolve().then(() => require('chalk'))` at
  compile time, which fails for ESM-only chalk v5 and ora v6. Fixed by using
  `Function('return import("pkg")')()` which is invisible to the TypeScript
  transformer and preserves the native dynamic `import()` at runtime.

### Changed
- **`update-packages` command completely rewritten** (`src/commands/updatePackages.ts`):
  The previous implementation used `text=boost-exact:true` as the npm search query —
  this was interpreted as a literal text search and returned irrelevant, low-download
  packages (e.g. `retux`: 37 downloads/week, `@tapgiants/graphql`: 5 downloads/week),
  which replaced the curated list and caused false-positive typosquat findings for
  packages like `redis`, `@types/jsonwebtoken`, and `@types/node-fetch`. The command
  now follows a two-phase strategy:
  - **Phase 1 — Candidate discovery**: Seeds from the current `top-packages.json`
    (ensures well-known packages are always candidates), then fetches one page per
    search term from 50 broad ecosystem terms. Requests are spaced 400ms apart to
    avoid the registry's HTTP 429 rate limit (~8 rapid requests triggers it).
  - **Phase 2 — Download verification**: Queries actual weekly download counts via
    `api.npmjs.org/downloads/point/last-week`. Unscoped packages are batched (100 per
    request); scoped packages are fetched individually (npm bulk API rejects them).
    Only packages with ≥ `--min-downloads` weekly downloads (default 1,000) are kept.
    The final list is sorted by download count descending.
  - **Safety guard**: If verification returns fewer than 50 packages (indicative of a
    network failure), the command aborts without overwriting the existing list.
  - **New `--min-downloads <n>` option**: Controls the weekly download threshold
    (default: 1,000).
- **Build script copies data file** (`package.json`): `npm run build` now executes
  `cp data/top-packages.json dist/data/top-packages.json` after `tsc`, ensuring the
  compiled package always ships the curated baseline list.

---

## [v0.0.3] — 2026-04-03

### Added
- **`-v` / `--verbose` flag for `scan` and `check`**: Enriches terminal output with
  navigable links and extended detail across all three detector sections. Populate
  fields unconditionally at detection time; the renderer gates display on the flag.
- **CVE verbose detail block**: When `--verbose` is active, each CVE finding shows:
  - OSV.dev advisory permalink
  - NVD links for every CVE alias (e.g. `CVE-2021-23337`)
  - CVSS score and full vector string
  - Affected version range (formatted from OSV ECOSYSTEM ranges)
  - Fixed-in version
  - Published date
  - Truncated advisory description (300 chars)
- **License verbose detail block**: When `--verbose` is active, each license finding shows:
  - SPDX.org license reference URL
  - tldrlegal.com plain-English summary URL (for 20 well-known licenses)
  - Plain-English compatibility explanation for conflicts and warnings
  - Raw SPDX expression when it differs from the normalised identifier
- **Maintainer verbose detail block**: When `--verbose` is active, each maintainer
  finding shows: npm package URL, GitHub repository URL, npm profile links per
  maintainer username, and score breakdown (recency / maintainerCount / accountAge /
  githubActivity / issueHealth / popularity).
- **`NormalisedVuln` enriched fields** (`src/utils/severity.ts`): Added `cvssVector`,
  `affectedRange`, `aliases`, `published`, and `details` fields. `_extractAffectedRange()`
  walks ECOSYSTEM-type OSV ranges and formats introduced/fixed pairs. `_extractAdvisoryUrl()`
  selects the best advisory URL with preference order GHSA > NVD > ADVISORY type >
  ID-based fallback. Zero additional network calls — all data was already present in
  the OSV API response.
- **`CveFinding` verbose fields** (`src/detectors/cve.ts`): Optional `aliases`,
  `cvssScore`, `cvssVector`, `affectedRange`, `fixedIn`, `published`, and `details`
  fields populated from the top-severity vulnerability in each finding.
- **`LicenseFinding` verbose fields** (`src/detectors/license.ts`): Optional `spdxUrl`,
  `tldrUrl`, and `compatibilityExplanation` fields, plus a `TLDR_SLUGS` map covering
  20 well-known SPDX identifiers.
- **`MaintainerFinding.maintainerNames`** (`src/detectors/maintainer.ts`): Array of npm
  usernames sourced from `packument.maintainers[]`, used by the verbose renderer to
  generate npm profile links.

### Changed
- **Terminal renderer** (`src/reporters/terminal.ts`): Added `_indent()` helper for
  indented sub-lines under findings. `ScanResult` and `CheckReport` interfaces now
  carry `verbose?: boolean`. `renderCheckReport()` accepts and passes `licenseResult`.

---

## [v0.0.2] — 2026-04-02

### Added
- **`safedeps update-packages` command**: New CLI command (`src/commands/updatePackages.ts`)
  to refresh `data/top-packages.json` from the npm registry search API. Accepts
  `--count <n>` (default 5000) and `--output terminal|json`. Replaces the former
  package.json script so users can update on their own schedule.
- **HTTP retry utility** (`src/utils/httpRetry.ts`): `fetchWithRetry()` adds
  exponential backoff with ±25% jitter, configurable timeout, and `Retry-After`
  header support. Retries on network errors, 429, 503, and 5xx; does not retry
  4xx responses. All four HTTP sources (`osv`, `npmRegistry`, `githubApi`,
  `npmDownloads`) migrated to use it.
- **Homoglyph typosquat detection** (`method: 'homoglyph'`, confidence: `high`):
  Detects Unicode lookalike characters (Cyrillic а/е/о/р/с/у/і, ℓ, ０/１, etc.)
  substituted into known package names. Checked with highest priority before all
  other methods.
- **Separator substitution detection** (`method: 'separator'`, confidence: `medium`):
  Detects packages that differ from a known name only in separator characters
  (`-`, `_`, `.`), e.g. `bodyparser` → `body-parser`.
- **Combosquat detection** (`method: 'combosquat'`, confidence: `low`):
  Detects packages formed by prepending/appending common suffixes or prefixes to
  a known package name (e.g. `lodash-utils`, `node-express`).
- **`SignalRegistry`** (`src/utils/signalRegistry.ts`): Shared in-memory store that
  lets detectors publish and consume package signals (downloads, age, versions,
  GitHub stars, maintainer account age) without duplicate API calls.
- **Multi-signal authenticity scoring**: `enrichWithAuthenticity()` now computes a
  composite 0–100 score from five signals — weekly downloads (35 pts), package age
  (25 pts), published versions (15 pts), GitHub presence + stars (10 pts), maintainer
  account age (15 pts). Score ≥ 70 → dismissed; 50–69 → `likely-legitimate`;
  25–49 → `uncertain`; < 25 → `suspicious`. Replaces the single-signal
  download-count heuristic from v0.0.1.
- **`existsOnNpm` signal**: npm downloads source now returns `existsOnNpm: boolean | null`.
  A 404 response sets `existsOnNpm: false`, forcing score = 0 and upgrading confidence
  to `high`.
- **`NpmAuthenticity` extended**: Added `score`, `publishedVersions`, `hasGitHubRepo`,
  and `existsOnNpm` fields alongside the existing `weeklyDownloads`, `ageInDays`,
  `verdict`, and `dismissed` fields.
- **CVE `versionSource` tracking**: Each `CveFinding` now carries
  `versionSource: 'lockfile' | 'range-floor' | 'unknown'`. A warning is printed
  when any package version was resolved via range-floor (no lockfile present), noting
  that results may over-report and suggesting `npm install` for precise resolution.
- **License scanning in `check` command**: `safedeps check <pkg>` now runs
  `scanLicenses()` in parallel with CVE and maintainer checks, and renders a full
  License Compliance section in the terminal output.
- **`--include-dev` flag for `scan`**: When passed, `scanLicenses()` includes
  `devDependencies` in the compatibility check. The section header is updated to
  indicate dev dependencies were included.
- **7 httpRetry tests** (`tests/httpRetry.test.ts`): Covers retry exhaustion, 404
  no-retry, success-on-retry, network error, and timeout behaviour.

### Changed
- **`TyposquatFinding.method`**: `'both'` renamed to `'levenshtein+soundex'`
  everywhere — type definition, assignment, terminal reporter label map, and test
  assertions. Removes ambiguity about which methods fired.
- **Detection priority order in `_analyseWithSet()`**: Homoglyph → separator
  candidate → levenshtein+soundex → combosquat. Highest-confidence candidate
  wins when multiple methods match.
- **`ScanMaintainerOptions`**: Accepts optional `signalRegistry` so the maintainer
  detector writes packument and GitHub signals into the shared registry rather than
  computing them in isolation.
- **`scan` command**: Instantiates `SignalRegistry` before `Promise.allSettled` and
  passes it to both `scanMaintainerHealth` and `enrichWithAuthenticity`, enabling
  cross-detector signal reuse.
- **Terminal license header**: Appends ` (incl. dev)` when `licenseResult.includesDevDeps`
  is true.

### Fixed
- **CRITICAL — UNKNOWN severity CVEs silently dropped**: The severity filter in
  `src/detectors/cve.ts` compared `severityOrder.indexOf('unknown')` (4) against
  `minIdx` for `'low'` (3), causing `4 <= 3 = false` — all UNKNOWN-severity
  findings (MAL-* malware advisories, many GHSA entries with no explicit CVSS)
  were silently discarded. UNKNOWN findings now always pass the filter. Running
  `safedeps check axios@0.30.4` now correctly surfaces MAL advisories.
- **UNKNOWN severity colour**: Terminal reporter now renders UNKNOWN severity in
  magenta (`chalk.magenta`) instead of dim grey, making malware advisories visually
  distinct.

---

## [v0.0.1]

### Added
- **`check` command — full scan**: `safedeps check <pkg>` now runs every detector
  (typosquat, CVE, license, maintainer health), not just typosquat. Fetches live
  package data from npm so no local install is required.
- **npm authenticity scoring**: Typosquat findings are now enriched with npm download
  counts via the npm downloads API. Packages with ≥ 100k weekly downloads are
  automatically dismissed as false positives; others receive a verdict of
  `likely-legitimate`, `uncertain`, or `suspicious`.
- **`NpmAuthenticity` type**: Exported from `detectors/typosquat.ts`. Contains
  `weeklyDownloads`, `ageInDays`, `verdict`, and `dismissed` fields.
- **`enrichWithAuthenticity()`**: New async function in `detectors/typosquat.ts`.
  Takes a list of `TyposquatFinding[]` and returns them enriched with npm signals.
- **`src/sources/npmDownloads.ts`**: New HTTP client for the npm downloads API
  (`api.npmjs.org`). Exports `fetchWeeklyDownloads` and `batchFetchDownloads`.
- **`NpmPackumentInfo.createdAt`**: npm packument client now returns the package
  creation date (`time.created`) alongside the last-published date.
- **`NpmPackumentInfo.publishedVersions`**: Total number of published versions, derived
  from the packument `time` map.
- **`renderCheckReport()`**: New terminal renderer in `reporters/terminal.ts` for
  the expanded `check` command output.
- **Claude agent skills** (`.claude/agents/`): Added seven domain-specific agent
  definitions at the monorepo root — `architecture-decision`, `feature-planner`,
  `developer`, `verifier`, `security-expert`, `user-perspective`, `project-manager`.

### Changed
- **`scan` command**: Typosquat findings are now enriched with npm authenticity data
  in parallel with CVE/license/maintainer checks. Dismissed findings are excluded
  from the report. Spinner message updated to mention authenticity checks.
- **`check` command**: Completely rewritten; now a comprehensive single-package audit
  instead of a typosquat-only check.
- **`NpmPackumentInfo`**: Added `createdAt: Date | null` and `publishedVersions: number`
  fields; all existing callers are compatible (additive change).
- **`terminal.ts` chalk access**: Replaced unsafe dynamic property access on chalk
  (`(chalk as Record)[color]`) with a typed `_chalkColor()` helper that falls back
  gracefully instead of crashing on unknown colour keys.

### Fixed
- **`lockfileParser.ts` v1 first-wins**: v1 lockfile parsing now applies the same
  first-wins strategy as v2/v3 — top-level entries are never overwritten by deeper
  nested copies of the same package. Previously the deepest nested version won,
  which could suppress true-positive CVEs.
- **`npmRegistry.ts` URL injection**: Non-scoped package names are now
  `encodeURIComponent`-encoded before being interpolated into registry URLs,
  preventing path-segment manipulation via crafted names in `package.json`.
- **`spdxCompatibility.ts` AND expression**: SPDX AND expressions now correctly
  return the most restrictive licence term (e.g. `"MIT AND GPL-3.0-only"` → GPL)
  instead of the first term. Previously packages with permissive+copyleft AND
  expressions could silently pass compatibility checks.

---

## [0.0.0] — 2026-03-01

### Added
- `safedeps scan` command — scans all project dependencies for:
  - **Typosquatting** (offline, Levenshtein + Soundex against top-5,000 packages)
  - **CVEs** via OSV.dev batch API (single network request, no API key)
  - **License compliance** (SPDX normalisation, project-level compatibility check)
  - **Maintainer health** scoring (npm packument + GitHub signals, 0–100 score)
- `safedeps check <pkg>` command — typosquat check for a single package name
- Terminal output with colour-coded severity tables (chalk v5)
- JSON output mode (`--output json`) for CI/CD pipeline integration
- `--fail-on <level>` flag — exits with code 1 for CI gates
- `--offline` flag — disables all network calls (typosquat + license only)
- `--severity <level>` flag — minimum severity filter for CVE results
- Lockfile-first versioning (`package-lock.json` v1/v2/v3 support)
- Input validation and sanitisation in `packageParser.ts`
- Shared `USER_AGENT` constant derived from `package.json` version
- `Promise.allSettled`-based detector concurrency (one failure doesn't abort scan)
- `ora` spinner (lazy ESM import) during network-bound scan phases
- Node.js built-in test runner — 159 tests, no Jest/Mocha dependency
- Top-5,000 known npm packages list in `data/top-packages.json`
- Claude agent definitions for code review, architecture strategy, and review
  resolution (`.claude/agents/`)
