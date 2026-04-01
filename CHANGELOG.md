# Changelog

All notable changes to SafeDeps are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

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
