# SafeDeps

**Open source npm security scanner — catch supply chain attacks before they catch you.**

[![npm version](https://img.shields.io/npm/v/safedeps?style=flat-square)](https://www.npmjs.com/package/safedeps)
[![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)](https://nodejs.org)
[![license](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](https://github.com/kumarsainideepak/safedeps/blob/main/LICENSE)

`npm audit` only checks known CVEs. SafeDeps goes further — it also detects
typosquatting, license violations, and compromised maintainer accounts.

```
$ npx safedeps scan

  SafeDeps v1.0.0 — scanning 47 dependencies…

  Typosquat Analysis — 47 packages

  CONFIDENCE  PACKAGE              FINDING
  ─────────────────────────────────────────────────────────────────────────
  HIGH        expres@0.0.1         Typosquatting — did you mean "express"?

  CVE Vulnerabilities — scanned 47 packages

  SEVERITY    PACKAGE              VULNERABILITIES
  ─────────────────────────────────────────────────────────────────────────
  HIGH        axios@0.21.1         GHSA-43fc-jf86-j433, GHSA-cph5-m8f7-6c5x
                                   Fix available: 1.8.4

  License Compliance — project: MIT

  SEVERITY    PACKAGE              FINDING
  ─────────────────────────────────────────────────────────────────────────
  HIGH        some-gpl-pkg@1.0.0   GPL-3.0 is incompatible with your MIT project

  Maintainer Health — 47 packages

  SEVERITY    PACKAGE              FINDING
  ─────────────────────────────────────────────────────────────────────────
  HIGH        left-pad@1.3.0       Score 18/100 — abandoned, single anonymous maintainer
```

---

## Installation

```bash
# Run without installing
npx safedeps scan

# Install globally
npm install -g safedeps

# Install as a dev dependency (CI/CD)
npm install --save-dev safedeps
```

Requires Node.js ≥ 18. No API keys needed.

---

## Commands

### `safedeps scan`

Scans all dependencies in the current project's `package.json`.

```bash
safedeps scan [options]
```

| Option | Default | Description |
|---|---|---|
| `-P, --path <dir>` | cwd | Path to project root |
| `-S, --severity <level>` | `low` | Minimum severity to report (`low` / `medium` / `high` / `critical`) |
| `-O, --output <format>` | `terminal` | Output format: `terminal` or `json` |
| `-L, --license <spdx>` | from `package.json` | Override project license for compatibility check |
| `--include-dev` | off | Include `devDependencies` in license scan |
| `--offline` | off | Skip CVE + maintainer checks (no network) |
| `--fail-on <level>` | — | Exit code 1 if any finding meets this level (CI gate) |
| `-v, --verbose` | off | Show advisory links, CVSS vectors, score breakdowns |

**Examples:**

```bash
# Scan current project
safedeps scan

# Only show high/critical issues
safedeps scan --severity high

# Fail the build on critical findings (CI)
safedeps scan --fail-on critical

# JSON output for pipeline consumption
safedeps scan --output json > report.json

# Offline — typosquat + license only, no network
safedeps scan --offline

# Verbose — show CVE links, CVSS scores, score breakdowns
safedeps scan --verbose

# Include devDependencies in license check
safedeps scan --include-dev
```

---

### `safedeps check <package>`

Full security audit on a single package — useful before `npm install`.

```bash
safedeps check <packageName[@version]> [options]
```

| Option | Default | Description |
|---|---|---|
| `-O, --output <format>` | `terminal` | `terminal` or `json` |
| `-v, --verbose` | off | Show advisory links, CVSS vectors, score breakdown |

**Examples:**

```bash
# Audit latest version
safedeps check axios

# Audit a specific version
safedeps check axios@0.21.1

# With verbose CVE detail (links, CVSS, affected range)
safedeps check lodash@4.17.4 --verbose

# Machine-readable output
safedeps check express --output json
```

---

### `safedeps update-packages`

Refreshes the local list of top npm packages used by the typosquat detector.
Run this occasionally to keep detection up to date with the current npm ecosystem.

```bash
safedeps update-packages [options]
```

| Option | Default | Description |
|---|---|---|
| `--count <n>` | `5000` | Number of packages to keep in the list |
| `--min-downloads <n>` | `1000` | Minimum weekly downloads threshold |
| `-O, --output <format>` | `terminal` | `terminal` or `json` |

```bash
# Default — fetch top 5,000 packages with ≥ 1,000 weekly downloads
safedeps update-packages

# Smaller, faster list
safedeps update-packages --count 1000

# Stricter quality filter (popular packages only)
safedeps update-packages --min-downloads 50000
```

---

## CI/CD Integration

Use `--fail-on` to gate your pipeline:

```bash
# Fail on any high or critical finding
safedeps scan --fail-on high

# Fail only on critical
safedeps scan --fail-on critical
```

**GitHub Actions:**

```yaml
- name: SafeDeps security scan
  run: npx safedeps scan --fail-on high
```

**package.json scripts:**

```json
{
  "scripts": {
    "security": "safedeps scan",
    "security:ci": "safedeps scan --fail-on critical --output json"
  }
}
```

---

## What it detects

| Detector | Method | Network |
|---|---|---|
| **Typosquatting** | Levenshtein distance, Soundex phonetics, homoglyphs, separator swaps, combosquats — against top npm packages | No |
| **CVE vulnerabilities** | OSV.dev batch API — scans **all installed packages** (direct + transitive) from `package-lock.json`, matching `npm audit` coverage | Yes |
| **License compliance** | SPDX normalisation, compatibility matrix for your project license | No |
| **Maintainer health** | npm packument + GitHub signals — recency, account age, maintainer count, activity | Yes |

Each typosquat finding is enriched with live npm data (download count, package age, published versions) to suppress false positives.

---

## Verbose output

Pass `-v` / `--verbose` to any command for extended detail:

- **CVE**: advisory permalink (OSV), NVD links per alias, CVSS score + vector, affected range, fixed-in version, published date, description
- **License**: SPDX reference URL, tldrlegal.com plain-English summary, compatibility explanation
- **Maintainer**: npm URL, GitHub URL, per-maintainer profile links, score breakdown (recency / maintainerCount / accountAge / githubActivity / issueHealth / popularity)

```bash
safedeps check axios@0.21.1 --verbose
safedeps scan --verbose
```

---

## How it works

```
package.json + package-lock.json
         │
         ▼
  ┌──────────────────────────────────────┐
  │  Typosquat   │  CVE (OSV.dev)        │
  │  (offline)   │  License (SPDX)       │
  │              │  Maintainer (npm/GH)  │
  └──────────────────────────────────────┘
         │
         ▼
  terminal (colour-coded) | JSON (CI/CD)
```

- **Full transitive coverage** — reads `package-lock.json` to scan every installed package (direct + transitive), not just what's in `package.json`
- **One batch request** to OSV.dev for all packages — no per-package API calls, no rate limit concerns
- **Lockfile-first versioning** — uses exact resolved versions from `package-lock.json`, never guesses
- **No API keys required** — all data sources are free and public
- **Offline mode** — typosquat + license detectors work with zero network calls

---

## License

[AGPL-3.0](https://github.com/kumarsainideepak/safedeps/blob/main/LICENSE) — free to use, modify, and distribute.
For commercial licensing without AGPL obligations: kumarsainideepak32@gmail.com

---

Built by [Deepak Kumar Saini](https://github.com/kumarsainideepak)
