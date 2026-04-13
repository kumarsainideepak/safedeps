/**
 * Install Script Auditing Detector
 *
 * Reads node_modules/<pkg>/package.json for every dependency and flags
 * packages with preinstall, install, or postinstall lifecycle scripts.
 * Script contents are analysed for high-risk patterns (network calls,
 * eval, child_process, obfuscation).
 *
 * Fully offline — no network calls required.
 */

import fs from 'fs';
import path from 'path';
import type { ParsedPackageJson } from '../utils/packageParser';

// ─── Public types ──────────────────────────────────────────────────────────

export type ScriptRisk = 'high' | 'medium' | 'informational';

export type ScriptType = 'preinstall' | 'install' | 'postinstall';

export interface InstallScriptFinding {
  name:        string;
  version:     string;
  scriptType:  ScriptType;
  scriptBody:  string;
  truncated:   string;
  risk:        ScriptRisk;
  riskReason:  string;
  npmUrl:      string;
}

export interface InstallScriptResult {
  findings:      InstallScriptFinding[];
  scanned:       number;
  highRisk:      number;
  mediumRisk:    number;
  informational: number;
  error?:        string;
}

export interface ScanInstallScriptOptions {
  projectPath?:  string;
  lockVersions?: Map<string, string>;
}

// ─── High-risk patterns ────────────────────────────────────────────────────

const HIGH_RISK_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\bcurl\s/i,            reason: 'Downloads content via curl' },
  { pattern: /\bwget\s/i,            reason: 'Downloads content via wget' },
  { pattern: /\bnode\s+-e\b/,        reason: 'Executes inline Node.js code' },
  { pattern: /\beval\s*\(/,          reason: 'Uses eval()' },
  { pattern: /\bFunction\s*\(/,      reason: 'Uses Function() constructor' },
  { pattern: /\bchild_process\b/,    reason: 'Imports child_process module' },
  { pattern: /\bexecSync\b/,         reason: 'Uses execSync' },
  { pattern: /\bexec\s*\(/,          reason: 'Uses exec()' },
  { pattern: /\.sh\b/,               reason: 'Executes shell script' },
  { pattern: /\bpowershell\b/i,      reason: 'Executes PowerShell' },
  { pattern: /\bcmd\s+\/c\b/i,       reason: 'Executes Windows cmd' },
  { pattern: /https?:\/\//,          reason: 'Contains URL (potential data exfiltration)' },
];

const LIFECYCLE_SCRIPTS: ScriptType[] = ['preinstall', 'install', 'postinstall'];

// ─── Risk classification ───────────────────────────────────────────────────

export function _classifyScriptRisk(
  scriptBody: string,
  scriptType: ScriptType,
): { risk: ScriptRisk; reason: string } {
  // Check high-risk patterns first
  for (const { pattern, reason } of HIGH_RISK_PATTERNS) {
    if (pattern.test(scriptBody)) {
      return { risk: 'high', reason };
    }
  }

  // Any preinstall script is medium risk — runs before package code is available
  if (scriptType === 'preinstall') {
    return { risk: 'medium', reason: 'preinstall hook runs before package code is available' };
  }

  // Long scripts may indicate obfuscation
  if (scriptBody.length > 200) {
    return { risk: 'medium', reason: `Unusually long script (${scriptBody.length} chars)` };
  }

  return { risk: 'informational', reason: 'Lifecycle script present' };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function _truncate(s: string, maxLen: number = 120): string {
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen) + '...';
}

function _readPackageScripts(
  nodeModulesPath: string,
  packageName: string,
): { version: string; scripts: Record<string, string> } | null {
  const pkgJsonPath = path.join(nodeModulesPath, packageName, 'package.json');
  try {
    const raw = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    return {
      version: raw.version ?? '(unknown)',
      scripts: raw.scripts ?? {},
    };
  } catch {
    return null;
  }
}

// ─── Main scanner ──────────────────────────────────────────────────────────

export async function scanInstallScripts(
  parsedPackageJson: ParsedPackageJson,
  options: ScanInstallScriptOptions = {},
): Promise<InstallScriptResult> {
  const { projectPath = process.cwd(), lockVersions } = options;
  const nodeModulesPath = path.resolve(projectPath, 'node_modules');

  const findings: InstallScriptFinding[] = [];
  let scanned = 0;

  for (const name of parsedPackageJson.allPackages) {
    const pkg = _readPackageScripts(nodeModulesPath, name);
    if (!pkg) continue;

    scanned++;
    const version = lockVersions?.get(name) ?? pkg.version;

    for (const scriptType of LIFECYCLE_SCRIPTS) {
      const scriptBody = pkg.scripts[scriptType];
      if (!scriptBody) continue;

      const { risk, reason } = _classifyScriptRisk(scriptBody, scriptType);

      findings.push({
        name,
        version,
        scriptType,
        scriptBody,
        truncated:  _truncate(scriptBody),
        risk,
        riskReason: reason,
        npmUrl:     `https://www.npmjs.com/package/${name}`,
      });
    }
  }

  // Sort: high risk first, then medium, then informational
  const RISK_ORDER: Record<ScriptRisk, number> = { high: 0, medium: 1, informational: 2 };
  findings.sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk]);

  return {
    findings,
    scanned,
    highRisk:      findings.filter(f => f.risk === 'high').length,
    mediumRisk:    findings.filter(f => f.risk === 'medium').length,
    informational: findings.filter(f => f.risk === 'informational').length,
  };
}
