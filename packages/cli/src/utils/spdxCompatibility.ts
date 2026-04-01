/**
 * SPDX License Compatibility Engine
 *
 * Provides three capabilities:
 *   1. normaliseLicense()  — maps raw license strings → canonical SPDX identifiers
 *   2. classifyLicense()   — buckets a SPDX ID into a category (permissive, copyleft, …)
 *   3. checkCompatibility() — decides whether a dependency's license is compatible with
 *                             the project's declared license, returning ok / warning / conflict
 *
 * Compatibility model (project license → dependency license):
 *
 *   permissive + permissive        → ok
 *   permissive + weak-copyleft     → warning   (safe if library used unmodified)
 *   permissive + strong-copyleft   → conflict  (GPL requires the whole work to be GPL)
 *   permissive + network-copyleft  → conflict  (AGPL/SSPL triggers on network use)
 *   weak-copyleft + strong/network → conflict
 *   strong-copyleft + permissive   → ok
 *   Apache-2.0  + GPL-2.0-only     → conflict  (FSF-recognised patent clause incompatibility)
 *   GPL-2.0-only + GPL-3.0-*       → conflict  (version mismatch — GPLv2-only cannot include GPLv3)
 */

// ─── License categories ────────────────────────────────────────────────────

export type LicenseCategory =
  | 'permissive'
  | 'weak-copyleft'
  | 'strong-copyleft'
  | 'network-copyleft'
  | 'unknown';

export type CompatibilityStatus = 'ok' | 'warning' | 'conflict' | 'unknown';

export interface CompatibilityResult {
  status: CompatibilityStatus;
  reason: string;
}

// ─── Canonical SPDX sets ───────────────────────────────────────────────────

const PERMISSIVE = new Set([
  'MIT', 'MIT-0', 'ISC', '0BSD', 'WTFPL',
  'BSD-2-Clause', 'BSD-3-Clause', 'BSD-4-Clause',
  'Apache-2.0',
  'Unlicense', 'CC0-1.0',
  'BlueOak-1.0.0', 'Zlib',
  'Python-2.0', 'PSF-2.0',
  'Artistic-2.0',
]);

const WEAK_COPYLEFT = new Set([
  'LGPL-2.0-only', 'LGPL-2.0-or-later',
  'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'MPL-2.0',
  'EPL-1.0', 'EPL-2.0',
  'CDDL-1.0',
  'EUPL-1.1',
]);

const STRONG_COPYLEFT = new Set([
  'GPL-2.0-only', 'GPL-2.0-or-later',
  'GPL-3.0-only', 'GPL-3.0-or-later',
]);

const NETWORK_COPYLEFT = new Set([
  'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'SSPL-1.0',
  'EUPL-1.2',
]);

// ─── Normalisation alias map ───────────────────────────────────────────────
// Maps common non-standard strings (lowercase) → canonical SPDX identifier.

const ALIAS_MAP: Record<string, string> = {
  // MIT
  'mit':                     'MIT',
  'mit license':             'MIT',
  'mit/x11':                 'MIT',
  'the mit license':         'MIT',
  // ISC
  'isc':                     'ISC',
  'isc license':             'ISC',
  // BSD
  'bsd':                     'BSD-2-Clause',
  'bsd-2':                   'BSD-2-Clause',
  'bsd2':                    'BSD-2-Clause',
  'simplified bsd':          'BSD-2-Clause',
  'bsd-3':                   'BSD-3-Clause',
  'bsd3':                    'BSD-3-Clause',
  'new bsd':                 'BSD-3-Clause',
  'modified bsd':            'BSD-3-Clause',
  // Apache
  'apache':                  'Apache-2.0',
  'apache 2':                'Apache-2.0',
  'apache 2.0':              'Apache-2.0',
  'apache-2':                'Apache-2.0',
  'apache license 2.0':      'Apache-2.0',
  'apache license, version 2.0': 'Apache-2.0',
  // GPL
  'gpl':                     'GPL-3.0-or-later',
  'gpl-2':                   'GPL-2.0-only',
  'gpl-2.0':                 'GPL-2.0-only',
  'gpl2':                    'GPL-2.0-only',
  'gpl v2':                  'GPL-2.0-only',
  'gnu gpl v2':              'GPL-2.0-only',
  'gpl-2.0+':                'GPL-2.0-or-later',
  'gpl-3':                   'GPL-3.0-only',
  'gpl-3.0':                 'GPL-3.0-only',
  'gpl3':                    'GPL-3.0-only',
  'gpl v3':                  'GPL-3.0-only',
  'gplv3':                   'GPL-3.0-only',
  'gnu gpl v3':              'GPL-3.0-only',
  'gpl-3.0+':                'GPL-3.0-or-later',
  // LGPL
  'lgpl':                    'LGPL-2.1-or-later',
  'lgpl-2.1':                'LGPL-2.1-only',
  'lgpl-2.1+':               'LGPL-2.1-or-later',
  'lgpl-3.0':                'LGPL-3.0-only',
  'lgpl-3.0+':               'LGPL-3.0-or-later',
  // AGPL
  'agpl':                    'AGPL-3.0-or-later',
  'agpl-3':                  'AGPL-3.0-only',
  'agpl-3.0':                'AGPL-3.0-only',
  'agpl-3.0+':               'AGPL-3.0-or-later',
  // MPL
  'mpl':                     'MPL-2.0',
  'mpl-2':                   'MPL-2.0',
  'mpl-2.0':                 'MPL-2.0',
  'mozilla public license 2.0': 'MPL-2.0',
  // Unlicense / public domain
  'unlicense':               'Unlicense',
  'public domain':           'Unlicense',
  'the unlicense':           'Unlicense',
  // CC0
  'cc0':                     'CC0-1.0',
  'cc0-1.0':                 'CC0-1.0',
  'creative commons zero v1.0 universal': 'CC0-1.0',
  // WTFPL
  'wtfpl':                   'WTFPL',
  'do what the fuck you want to public license': 'WTFPL',
};

// Pre-built lookup of all canonical SPDX IDs for fast case-insensitive matching
const ALL_CANONICAL = new Set([
  ...PERMISSIVE,
  ...WEAK_COPYLEFT,
  ...STRONG_COPYLEFT,
  ...NETWORK_COPYLEFT,
]);
const CANONICAL_LOWER = new Map<string, string>();
for (const id of ALL_CANONICAL) {
  CANONICAL_LOWER.set(id.toLowerCase(), id);
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Converts a raw license string from package.json into a canonical SPDX
 * identifier, or returns 'UNKNOWN' if it cannot be resolved.
 *
 * Handles:
 *   - Already-canonical SPDX IDs (returned as-is, modulo case correction)
 *   - Common aliases (e.g. "Apache 2.0" → "Apache-2.0")
 *   - SPDX expressions (e.g. "MIT OR Apache-2.0" → takes first term)
 *   - null / undefined → 'UNKNOWN'
 */
export function normaliseLicense(raw: string | null | undefined): string {
  if (!raw || raw.trim() === '') return 'UNKNOWN';

  const s = raw.trim();

  // SPDX OR expression — pick the most permissive term
  // e.g. "GPL-3.0-only OR MIT" → "MIT" (not GPL-3.0-only)
  if (/\s+OR\s+/i.test(s)) {
    const terms = s.split(/\s+OR\s+/i).map(t => normaliseLicense(t.replace(/[()]/g, '').trim()));
    const priority: Record<LicenseCategory, number> = {
      permissive: 0, 'weak-copyleft': 1, 'strong-copyleft': 2, 'network-copyleft': 3, unknown: 4,
    };
    return terms.reduce((best, t) =>
      priority[classifyLicense(t)] < priority[classifyLicense(best)] ? t : best
    );
  }

  // SPDX AND expression — all terms apply simultaneously; return the most restrictive
  if (/\s+AND\s+/i.test(s)) {
    const terms = s.split(/\s+AND\s+/i).map(t => normaliseLicense(t.replace(/[()]/g, '').trim()));
    const priority: Record<LicenseCategory, number> = {
      'network-copyleft': 0, 'strong-copyleft': 1, 'weak-copyleft': 2, permissive: 3, unknown: 4,
    };
    return terms.reduce((most, t) =>
      priority[classifyLicense(t)] < priority[classifyLicense(most)] ? t : most
    );
  }

  // Exact canonical SPDX match (case-insensitive)
  const canonical = CANONICAL_LOWER.get(s.toLowerCase());
  if (canonical) return canonical;

  // Alias map lookup
  const aliased = ALIAS_MAP[s.toLowerCase()];
  if (aliased) return aliased;

  // If it looks like a SPDX ID (no spaces, contains hyphens/dots) return as-is
  // so it can be shown to the user even if we can't classify it
  return s;
}

/**
 * Buckets a canonical SPDX identifier into a broad license category.
 */
export function classifyLicense(spdxId: string): LicenseCategory {
  if (PERMISSIVE.has(spdxId))       return 'permissive';
  if (WEAK_COPYLEFT.has(spdxId))    return 'weak-copyleft';
  if (STRONG_COPYLEFT.has(spdxId))  return 'strong-copyleft';
  if (NETWORK_COPYLEFT.has(spdxId)) return 'network-copyleft';
  return 'unknown';
}

/**
 * Determines whether a dependency's license is compatible with the project's
 * declared license and returns a status + human-readable reason.
 */
export function checkCompatibility(
  projectLicense: string,
  depLicense: string,
): CompatibilityResult {
  if (depLicense === 'UNKNOWN') {
    return { status: 'unknown', reason: 'License could not be determined — review manually' };
  }

  const projectCategory = classifyLicense(projectLicense);
  const depCategory     = classifyLicense(depLicense);

  if (projectCategory === 'unknown') {
    return {
      status:  'unknown',
      reason:  `Project license "${projectLicense}" is not a recognised SPDX identifier`,
    };
  }

  if (depCategory === 'unknown') {
    return {
      status:  'unknown',
      reason:  `Dependency license "${depLicense}" is not a recognised SPDX identifier — review manually`,
    };
  }

  // ── Special cases ────────────────────────────────────────────────────────

  // Apache-2.0 and GPL-2.0-only are mutually incompatible (FSF position:
  // the Apache patent grant imposes extra restrictions incompatible with GPLv2)
  if (projectLicense === 'Apache-2.0' && depLicense === 'GPL-2.0-only') {
    return {
      status: 'conflict',
      reason: 'GPL-2.0-only is incompatible with Apache-2.0 — patent clause creates additional restrictions (see FSF guidance)',
    };
  }

  // GPL-2.0-only project cannot use GPL-3.0 code — the "only" clause forbids it
  if (
    projectLicense === 'GPL-2.0-only' &&
    (depLicense === 'GPL-3.0-only' || depLicense === 'GPL-3.0-or-later')
  ) {
    return {
      status: 'conflict',
      reason: 'GPL-2.0-only projects cannot include GPL-3.0 code — "GPL-2.0-only" explicitly excludes later versions',
    };
  }

  // ── General matrix ───────────────────────────────────────────────────────

  if (projectCategory === 'permissive') {
    if (depCategory === 'strong-copyleft') {
      return {
        status: 'conflict',
        reason: `${depLicense} requires all combined works to be released under ${depLicense} — incompatible with ${projectLicense}`,
      };
    }
    if (depCategory === 'network-copyleft') {
      return {
        status: 'conflict',
        reason: `${depLicense} requires source disclosure when the software is used over a network — incompatible with ${projectLicense}`,
      };
    }
    if (depCategory === 'weak-copyleft') {
      return {
        status: 'warning',
        reason: `${depLicense} requires modifications to the library itself to be shared — safe if used unmodified as a dependency`,
      };
    }
  }

  if (projectCategory === 'weak-copyleft') {
    if (depCategory === 'strong-copyleft' || depCategory === 'network-copyleft') {
      return {
        status: 'conflict',
        reason: `${depLicense} requires all combined works to be ${depLicense} — incompatible with ${projectLicense}`,
      };
    }
  }

  if (projectCategory === 'strong-copyleft') {
    if (depCategory === 'network-copyleft') {
      return {
        status: 'warning',
        reason: `${depLicense} adds network-use disclosure obligations on top of GPL requirements`,
      };
    }
  }

  return { status: 'ok', reason: '' };
}

/** Returns a short human-readable label for a license category. */
export function categoryLabel(cat: LicenseCategory): string {
  switch (cat) {
    case 'permissive':       return 'Permissive';
    case 'weak-copyleft':    return 'Weak Copyleft';
    case 'strong-copyleft':  return 'Copyleft';
    case 'network-copyleft': return 'Network Copyleft';
    default:                 return 'Unknown';
  }
}
