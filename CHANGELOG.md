# Changelog

All notable changes to SafeDeps are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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

## [1.0.0] — 2026-03-01

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
