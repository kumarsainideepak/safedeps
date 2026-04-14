# Changelog

All notable changes to SafeDeps are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [v1.2.1] — 2026-04-14

### Fixed
- **`_toVerdict()` dead branch** (`src/detectors/typosquat.ts`): The score band
  `50–69` incorrectly returned `'likely-legitimate'` instead of `'uncertain'` due
  to a duplicate condition. Packages scoring 50–69 now correctly surface as
  `uncertain` in `safedeps check` output and JSON results. The `dismissed` flag
  (threshold `score >= 70`) was unaffected.

### Changed
- **README rewritten to match v1.2.0 reality**: Removed documentation for features
  that do not exist in the codebase:
  - `--output html` flag (was documented, never implemented)
  - `safedeps watch` command (was documented, never implemented)
  - `safedeps fix` command (was referenced in hero example, never implemented)
  - `safedeps.config.json` configuration file (entire section removed; moved to
    v1.3 roadmap as a planned item)
  - Stale `v1.0.0` version badge updated to `v1.2.0`
  - Maintainer health score weights table corrected (removed non-existent "2FA
    status" row; updated weights to match the actual scoring implementation)
  - "How It Works" diagram updated to include install script auditing and
    takeover detection; removed HTML from output options
  - Roadmap updated: v1.0–v1.2 marked complete (✅); v1.3 section added with
    accurate planned items (allowlist/config file, SARIF output, `GITHUB_TOKEN`
    warning, CVE auto-fix command)
  - Comparison table updated: removed false "Real-time alerts" claim; added
    accurate rows for `guard`, `diff`, SBOM, abandoned detection, and takeover
    detection
  - Project structure updated to reflect actual directories (removed references
    to `web-dashboard/`, `github-action/`, and `safedeps.config.json`)
  - CI example updated with `GITHUB_TOKEN` advisory note explaining the
    unauthenticated rate limit

---

## [v1.2.0] — 2026-04-13

### Added

- **Install script auditing** (`src/detectors/installScript.ts`, `tests/installScript.test.ts`):
  `safedeps scan` now reads every `preinstall`, `install`, and `postinstall` lifecycle
  script from `node_modules/<pkg>/package.json` and classifies it into three risk tiers:
  - **High** — script contains a network download tool (`curl`, `wget`), inline code
    execution (`node -e`, `eval()`, `Function()`), shell spawning (`exec`, `execSync`,
    `child_process`), shell scripts (`.sh`), Windows equivalents (`powershell`,
    `cmd /c`), or any hard-coded URL.
  - **Medium** — any `preinstall` hook (runs before package code is verified), or any
    install script longer than 200 characters (potential obfuscation).
  - **Informational** — all other lifecycle scripts (e.g. `node-gyp rebuild`).

  The detector is fully offline and runs even with `--offline`. Install script counts
  are appended to the scan summary footer. `--fail-on high` exits with code 1 if any
  high-risk script is found.

- **Abandoned package detection** (`src/detectors/abandoned.ts`, `tests/abandoned.test.ts`):
  A pure function (`scanAbandoned()`) that reuses data already fetched by the maintainer
  detector — zero additional network calls. Packages not published for ≥ 730 days
  (configurable via `thresholdDays`) are classified as:
  - **High** — no publish in ≥ 2 years AND repo is archived OR package has no GitHub link.
  - **Medium** — no publish in ≥ 2 years AND repo is still active on GitHub.

  Each finding includes a human-readable `reasons` array (e.g.
  `["No npm publish in 2.7 years", "GitHub repo archived"]`). Abandoned counts appear
  in the summary footer. The section renders after the Maintainer Health section.

- **Maintainer takeover detection** (extends `src/detectors/maintainer.ts`,
  `src/sources/npmRegistry.ts`, `src/reporters/terminal.ts`):
  Detects publisher identity changes that are a hallmark of supply chain attacks
  (e.g. the `event-stream` and `ua-parser-js` incidents). Implementation:
  - `fetchNpmPackumentInfo()` (`src/sources/npmRegistry.ts`) now extracts
    `_npmUser.name` from the second-to-last published version in the packument —
    no extra network requests, the data is already present in the packument response.
  - `MaintainerSignals` gained `maintainerChanged: boolean` and
    `previousPublisher: string | null`. When the previous publisher is not present in
    the current `maintainers[]` list, `maintainerChanged` is `true`.
  - `MaintainerFinding` gained `takeoverRisk: 'high' | 'medium' | 'none'`:
    - **High** — popular package (≥ 1,000 GitHub stars) + maintainer changed +
      latest publish ≤ 30 days ago.
    - **Medium** — maintainer changed + latest publish ≤ 90 days ago.
    - **None** — no change detected.
  - A 15-point score penalty is applied when `maintainerChanged && isPopular`,
    propagating the risk into the overall health score.
  - Terminal reporter shows a red `TAKEOVER RISK` badge (yellow for medium) next to
    affected maintainer findings.

- **`safedeps diff <pkg@v1> <pkg@v2>` command** (`src/commands/diff.ts`,
  `src/utils/packageDiff.ts`, `tests/diff.test.ts`):
  Compares two published versions of any npm package and highlights
  security-relevant changes. No free alternative exists for this.
  - Fetches both version manifests from the npm registry in parallel.
  - Computes changes across three axes: install scripts (added/removed/modified),
    production dependencies (added/removed/version-changed), and publisher identity.
  - Surfaces a `riskFlags` list: "Publisher changed", "New install hook added:
    postinstall", "3 new dependency(s) added", etc.
  - Colour-coded terminal output: red for risk flags, green for additions, dim for
    removals, yellow for modifications.
  - `src/utils/packageDiff.ts` exports `computeDiff()` — a pure function that accepts
    two `VersionManifest` objects, making it independently testable without network.
  - `fetchVersionManifest()` added to `src/sources/npmRegistry.ts`.

- **`safedeps guard [npm install args...]` command** (`src/commands/guard.ts`,
  `tests/guard.test.ts`):
  Pre-install security firewall. Intercepts an `npm install` invocation before packages
  land in `node_modules`:
  1. Runs `npm install --dry-run --json [args]` to determine what packages would be
     added or updated.
  2. Runs typosquat detection on the new package names.
  3. Fetches install scripts for each new package from the npm registry (since
     `node_modules` does not exist yet) and classifies them using the same logic as
     the install script auditor.
  4. Displays a pre-install risk report.
  5. Prompts the user (`[y/N]`) when high-risk findings are present. `--yes` skips the
     prompt for CI use.
  6. Proceeds with the real `npm install` (stdio inherited) if confirmed, or exits 1 if
     aborted.

- **`safedeps sbom` command** (`src/commands/sbom.ts`, `src/generators/cyclonedx.ts`,
  `tests/sbom.test.ts`):
  Generates a [CycloneDX 1.5](https://cyclonedx.org) JSON Software Bill of Materials
  for the project's npm dependencies.
  - Each component includes: package name, resolved version (from lockfile),
    PURL (`pkg:npm/<name>@<version>`), SPDX license identifier (from `node_modules`),
    and SRI integrity hash (from `package-lock.json`).
  - Scoped packages are PURL-encoded per spec (`@scope/name` → `%40scope%2Fname`).
  - Integrity strings (e.g. `sha512-abc sha256-xyz`) are split and mapped to CycloneDX
    `hashes[]` entries with correct algorithm names (`SHA-512`, `SHA-256`).
  - Metadata block includes timestamp, safedeps tool entry, and project application
    component.
  - Components are sorted alphabetically for deterministic output.
  - Options: `--output <file>` (default stdout), `--include-dev` (includes
    `devDependencies`), `--path <dir>` (project root).
  - `parseLockfileIntegrity()` added to `src/utils/lockfileParser.ts` to extract SRI
    hashes from both v1 and v2/v3 lockfile formats.

### Changed

- **`scan` command** (`src/commands/scan.ts`): `scanInstallScripts()` added to the
  `Promise.allSettled` detector array. `scanAbandoned()` is called synchronously after
  the maintainer result resolves (it is a pure function, no await needed).
  `installScriptResult` and `abandonedResult` added to the `ScanResult` object.
  Both are wired into `--fail-on` logic.
- **Terminal reporter** (`src/reporters/terminal.ts`): Added `_renderInstallScriptSection()`
  and `_renderAbandonedSection()`. Section render order: CVE → License → Maintainer →
  Install Scripts → Abandoned. Summary footer extended with install script and abandoned
  package counts.
- **`bin/safedeps.ts`**: Registered `diff`, `guard`, and `sbom` commands.

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
