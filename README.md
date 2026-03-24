<div align="center">

<img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge" alt="version"/>
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

**SafeDeps fills that gap — for free, forever.**

```bash
$ npx safedeps scan

  SafeDeps v1.0.0 — scanning 142 dependencies...

  ✗  CRITICAL  lodahs@1.0.2        Typosquatting — did you mean "lodash"?
  ✗  HIGH      axios@0.21.1        CVE-2023-45857 — CSRF vulnerability (fix: 1.6.0)
  ⚠  MEDIUM    left-pad@1.3.0      Maintainer score: 12/100 — abandoned since 2020
  ⚠  MEDIUM    some-util@2.1.0     License: GPL-3.0 conflicts with your MIT project
  ✓  OK        express@4.18.2      No issues found
  ✓  OK        react@18.2.0        No issues found

  Summary: 2 critical · 1 high · 2 medium · 139 clean
  Run `safedeps fix` to see recommended actions.
```

---

## ✨ Features

### 🔍 Typosquatting Detection
Compares every package name in your `package.json` against the top 5,000 most-downloaded npm packages using **Levenshtein distance** and **Soundex** algorithms. Catches attacks like:
- Character substitution: `recat` → `react`
- Missing characters: `expres` → `express`
- Extra characters: `lodashh` → `lodash`
- Dependency confusion: internal package names mirrored on public registry

### 🛡️ CVE Vulnerability Scanning
Cross-references all dependencies against **three free, public vulnerability databases** with no API key required:
- [OSV.dev](https://osv.dev) — Google's Open Source Vulnerabilities database
- [NVD NIST](https://nvd.nist.gov) — National Vulnerability Database
- [GitHub Advisory Database](https://github.com/advisories) — community-maintained advisories

Outputs severity level (Critical / High / Medium / Low), affected version range, and the exact fix version.

### ⚖️ License Compliance Checker
Maps every dependency's SPDX license and flags incompatibilities with your project's chosen license. Catches the most common gotcha in commercial development — GPL code embedded in a proprietary product.

Supported license compatibility checks:
- MIT, ISC, BSD-2-Clause, BSD-3-Clause (permissive)
- Apache-2.0 (permissive with patent clause)
- GPL-2.0, GPL-3.0, LGPL (copyleft)
- AGPL-3.0 (strong copyleft)
- Unlicense, CC0 (public domain)

### 👤 Maintainer Health Score
Pulls live data from the npm registry and GitHub API to generate a **0–100 trust score** for each package based on:

| Signal | Weight |
|--------|--------|
| Days since last publish | 25% |
| Number of maintainers | 20% |
| Maintainer account age | 20% |
| GitHub repository activity | 15% |
| 2FA status (where available) | 10% |
| Open issues / PR ratio | 10% |

A package with score < 30 is flagged as high risk regardless of other factors.

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
# Only show high and critical issues
safedeps scan --severity high
```

### Check a single package before installing
```bash
# Check before you npm install
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

### Export results to HTML report
```bash
safedeps scan --output html > safedeps-report.html
```

### Watch mode — monitor for changes (coming in v1.1)
```bash
safedeps watch
```

---

## ⚙️ Configuration

Create a `safedeps.config.json` in your project root to customise behaviour:

```json
{
  "license": "MIT",
  "severity": "medium",
  "ignore": [
    "CVE-2021-XXXXX",
    "some-package@1.0.0"
  ],
  "alerts": {
    "slack": "https://hooks.slack.com/your-webhook-url",
    "email": "security@yourcompany.com"
  },
  "maintainerScoreThreshold": 30,
  "failOnCritical": true
}
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `license` | `string` | auto-detected | Your project's SPDX license identifier |
| `severity` | `string` | `"low"` | Minimum severity to report (`low`, `medium`, `high`, `critical`) |
| `ignore` | `array` | `[]` | CVE IDs or package names to suppress |
| `alerts` | `object` | `null` | Slack webhook or email for watch mode alerts |
| `maintainerScoreThreshold` | `number` | `30` | Flag packages below this maintainer score |
| `failOnCritical` | `boolean` | `false` | Exit with code 1 if critical issues found (for CI/CD) |

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

      - name: Run SafeDeps scan
        run: npx safedeps scan --output json --severity high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Fail on critical issues
        run: npx safedeps scan --fail-on critical
```

### package.json scripts
```json
{
  "scripts": {
    "security": "safedeps scan",
    "security:ci": "safedeps scan --fail-on critical --output json"
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
    ┌─────────────────────────────────────────┐
    │           SafeDeps Engine               │
    │                                         │
    │  ┌─────────────┐  ┌──────────────────┐  │
    │  │ Typosquat   │  │  CVE Checker     │  │
    │  │ Engine      │  │  OSV + NVD +     │  │
    │  │ (Levenshtein│  │  GitHub Advisory │  │
    │  │  + Soundex) │  │                  │  │
    │  └─────────────┘  └──────────────────┘  │
    │                                         │
    │  ┌─────────────┐  ┌──────────────────┐  │
    │  │  License    │  │  Maintainer      │  │
    │  │  Checker    │  │  Health Score    │  │
    │  │  (SPDX)     │  │  (npm + GitHub)  │  │
    │  └─────────────┘  └──────────────────┘  │
    │                                         │
    │         Risk Aggregator                 │
    └────────────────┬────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │                     │
     Terminal output       JSON / HTML
     (colour-coded)        (for CI/CD)
```

All data sources used are **free and public** — no API keys required for core functionality:

| Data Source | What It Provides | Rate Limit |
|-------------|-----------------|------------|
| [OSV.dev API](https://osv.dev/docs/) | CVE + vulnerability data | 1,000 req/day |
| [NVD NIST API](https://nvd.nist.gov/developers) | CVE details + CVSS scores | 5 req/30 sec |
| [npm Registry API](https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md) | Package metadata + maintainer info | No key needed |
| [GitHub Advisory DB](https://github.com/advisories) | Community vulnerability reports | Token optional |
| [GitHub REST API](https://docs.github.com/en/rest) | Repository health signals | 60 req/hr |

---

## 🗺️ Roadmap

### v1.0 — CLI MVP
- [ ] Typosquatting detection (Levenshtein + Soundex)
- [ ] CVE scanning (OSV + NVD + GitHub Advisory)
- [ ] License compliance checker (SPDX)
- [ ] Maintainer health score
- [ ] JSON + HTML export
- [ ] `safedeps check <package>` single package lookup

### v1.1 — Monitoring & Alerts
- [ ] Watch mode — monitor lockfile for changes in real time
- [ ] Slack / email / Discord webhook alerts
- [ ] GitHub Action (official marketplace action)
- [ ] SARIF output for GitHub Security tab integration

### v1.2 — Visualisation
- [ ] Interactive dependency graph (web UI)
- [ ] Scan history dashboard (self-hostable)
- [ ] SBOM export — CycloneDX and SPDX formats

### v2.0 — Team & SaaS
- [ ] Multi-project dashboard
- [ ] Team management + role-based access
- [ ] Custom policy engine
- [ ] PDF compliance reports (SOC2, NIS2, FedRAMP-ready)
- [ ] API access for enterprise integrations

---

## 🤝 Contributing

Contributions are what make open source great. All contributions are welcome — bug fixes, new features, documentation, tests, or ideas.

### Getting started

```bash
# Fork the repo, then clone your fork
git clone https://github.com/YOUR_USERNAME/safedeps.git
cd safedeps

# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test

# Run linter
npm run lint
```

### Contribution areas

| Area | Difficulty | Description |
|------|-----------|-------------|
| 🐛 Bug fixes | Easy | Fix issues tagged `bug` on GitHub |
| 📖 Documentation | Easy | Improve README, add examples, fix typos |
| 🌐 New data source | Medium | Integrate additional vulnerability databases |
| 🔍 Detection rules | Medium | Improve typosquatting or scoring algorithms |
| 🎨 Output formatting | Medium | Improve terminal UI or HTML report design |
| ⚡ Performance | Hard | Optimise API batching, add caching layer |
| 🧪 Tests | Medium | Improve test coverage |

### Guidelines
- Open an issue before starting work on a large feature
- Follow the existing code style (ESLint config included)
- Write tests for new detection logic
- Update documentation for any changed behaviour
- Keep PRs focused — one feature or fix per PR

---

## 📁 Project Structure

```
safedeps/
├── packages/
│   ├── cli/                    ← Core CLI tool (this repo)
│   │   ├── src/
│   │   │   ├── commands/       ← CLI commands (scan, check, watch)
│   │   │   ├── detectors/      ← Typosquat, CVE, License, Maintainer engines
│   │   │   ├── reporters/      ← Terminal, JSON, HTML output formatters
│   │   │   ├── sources/        ← API clients (OSV, NVD, npm, GitHub)
│   │   │   └── utils/          ← Shared helpers, cache, config loader
│   │   └── tests/
│   ├── web-dashboard/          ← Self-hosted UI (coming v1.2)
│   └── github-action/          ← Official GitHub Action (coming v1.1)
├── docs/                       ← Extended documentation
├── .github/
│   ├── workflows/              ← CI/CD for SafeDeps itself
│   └── ISSUE_TEMPLATE/
├── safedeps.config.json        ← Example config
└── README.md
```

---

## 🔐 Security Policy

Found a vulnerability in SafeDeps itself? Please **do not** open a public GitHub issue.

Email us at: **kumarsainideepak32@gmail.com**

We follow responsible disclosure and will respond within 48 hours.

---

## 📊 Comparison with alternatives

| Feature | npm audit | Snyk | Socket.dev | **SafeDeps** |
|---------|-----------|------|------------|--------------|
| Known CVE detection | ✅ | ✅ | ✅ | ✅ |
| Typosquatting detection | ❌ | ❌ | ✅ | ✅ |
| License compliance | ❌ | 💰 Paid | 💰 Paid | ✅ Free |
| Maintainer health score | ❌ | ❌ | Partial | ✅ |
| Real-time alerts | ❌ | 💰 Paid | 💰 Paid | ✅ Free |
| Self-hostable | ❌ | ❌ | ❌ | ✅ |
| Open source | ❌ | ❌ | ❌ | ✅ AGPL-3.0 |
| Free for indie devs | ✅ | Limited | Limited | ✅ Always |
| CI/CD integration | ❌ | ✅ | ✅ | ✅ |

---

## 🌟 Show your support

If SafeDeps helps protect your project, please consider:
- ⭐ **Starring this repo** — it helps others discover the tool
- 🐦 **Sharing on Twitter/X** — tag `#SafeDeps` and `#npmSecurity`
- 💼 **Writing about it** — blog posts, Dev.to articles, LinkedIn posts
- 🐛 **Reporting bugs** — every issue report makes the tool better
- 💰 **GitHub Sponsors** — helps fund ongoing development *(link coming soon)*

---

## 📄 License

SafeDeps is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

This means:
- ✅ You can use, modify, and distribute this software freely
- ✅ You can use it in your own projects, including commercial ones
- ⚠️ If you modify SafeDeps and run it as a network service (e.g. a SaaS product), you **must** release your modifications under AGPL-3.0
- ⚠️ You must preserve the copyright notice and license in all copies

For commercial licensing (if you need to use SafeDeps without AGPL obligations), contact: **kumarsainideepak32@gmail.com**
See the [LICENSE](LICENSE) file for the full text.

---

<div align="center">

Built with ❤️ by [Deepak Kumar Saini](https://www.linkedin.com/in/deepak-kumar-saini-976ba6223/)

*Inspired by the 2025 npm supply chain attack wave — because `npm audit` wasn't enough.*

</div>
