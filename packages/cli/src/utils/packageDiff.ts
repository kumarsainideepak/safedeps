/**
 * Package Diff Utility
 *
 * Computes the semantic difference between two versions of an npm package:
 * dependencies added/removed/changed, install scripts added/removed/changed,
 * and publisher identity changes.
 */

export interface VersionManifest {
  name:            string;
  version:         string;
  dependencies:    Record<string, string>;
  devDependencies: Record<string, string>;
  scripts:         Record<string, string>;
  publisher:       string | null;     // _npmUser.name from registry manifest
}

export interface ScriptChange {
  key:  string;
  from: string;
  to:   string;
}

export interface DepChange {
  name: string;
  from: string;
  to:   string;
}

export interface PackageDiff {
  name:              string;
  fromVersion:       string;
  toVersion:         string;
  publisherChanged:  boolean;
  previousPublisher: string | null;
  currentPublisher:  string | null;
  // Install script changes
  scriptsAdded:      Array<{ key: string; value: string }>;
  scriptsRemoved:    string[];
  scriptsChanged:    ScriptChange[];
  // Dependency changes (prod only)
  depsAdded:         Array<{ name: string; version: string }>;
  depsRemoved:       string[];
  depsChanged:       DepChange[];
  riskFlags:         string[];       // human-readable risk summary
}

const INSTALL_HOOKS = new Set(['preinstall', 'install', 'postinstall']);

function _installScripts(scripts: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(scripts).filter(([k]) => INSTALL_HOOKS.has(k)),
  );
}

export function computeDiff(from: VersionManifest, to: VersionManifest): PackageDiff {
  const publisherChanged  = from.publisher !== to.publisher;

  // ── Install scripts ──────────────────────────────────────────────────────
  const fromScripts = _installScripts(from.scripts);
  const toScripts   = _installScripts(to.scripts);

  const scriptsAdded:   Array<{ key: string; value: string }> = [];
  const scriptsRemoved: string[]                               = [];
  const scriptsChanged: ScriptChange[]                        = [];

  const allScriptKeys = new Set([...Object.keys(fromScripts), ...Object.keys(toScripts)]);

  for (const key of allScriptKeys) {
    const inFrom = key in fromScripts;
    const inTo   = key in toScripts;

    if (!inFrom && inTo) {
      scriptsAdded.push({ key, value: toScripts[key] });
    } else if (inFrom && !inTo) {
      scriptsRemoved.push(key);
    } else if (inFrom && inTo && fromScripts[key] !== toScripts[key]) {
      scriptsChanged.push({ key, from: fromScripts[key], to: toScripts[key] });
    }
  }

  // ── Prod dependency changes ──────────────────────────────────────────────
  const depsAdded:   Array<{ name: string; version: string }> = [];
  const depsRemoved: string[]                                  = [];
  const depsChanged: DepChange[]                              = [];

  const allDeps = new Set([...Object.keys(from.dependencies), ...Object.keys(to.dependencies)]);

  for (const dep of allDeps) {
    const inFrom = dep in from.dependencies;
    const inTo   = dep in to.dependencies;

    if (!inFrom && inTo) {
      depsAdded.push({ name: dep, version: to.dependencies[dep] });
    } else if (inFrom && !inTo) {
      depsRemoved.push(dep);
    } else if (inFrom && inTo && from.dependencies[dep] !== to.dependencies[dep]) {
      depsChanged.push({ name: dep, from: from.dependencies[dep], to: to.dependencies[dep] });
    }
  }

  // ── Risk flags ───────────────────────────────────────────────────────────
  const riskFlags: string[] = [];

  if (publisherChanged) {
    riskFlags.push(
      `Publisher changed: ${from.publisher ?? '(unknown)'} → ${to.publisher ?? '(unknown)'}`,
    );
  }

  for (const s of scriptsAdded) {
    riskFlags.push(`New install hook added: ${s.key}`);
  }

  for (const s of scriptsChanged) {
    riskFlags.push(`Install hook modified: ${s.key}`);
  }

  if (depsAdded.length > 0) {
    riskFlags.push(`${depsAdded.length} new dependency(s) added`);
  }

  return {
    name:              from.name,
    fromVersion:       from.version,
    toVersion:         to.version,
    publisherChanged,
    previousPublisher: from.publisher,
    currentPublisher:  to.publisher,
    scriptsAdded,
    scriptsRemoved,
    scriptsChanged,
    depsAdded,
    depsRemoved,
    depsChanged,
    riskFlags,
  };
}
