/**
 * SignalRegistry — a shared store for per-package signals collected across
 * multiple detectors in a single scan pass.
 *
 * Detectors write signals as they fetch them; other detectors (or the reporter)
 * can read the enriched data without making duplicate network calls.
 */

export interface PackageSignals {
  weeklyDownloads?:    number | null;
  createdAt?:          Date | null;
  publishedVersions?:  number | null;
  maintainerCount?:    number;
  accountAgeDays?:     number | null;
  hasGitHubRepo?:      boolean;
  githubStars?:        number | null;
  existsOnNpm?:        boolean | null;
}

export class SignalRegistry {
  private readonly _signals = new Map<string, PackageSignals>();

  get(name: string): PackageSignals | undefined {
    return this._signals.get(name);
  }

  /** Merges partial signals into the existing entry. Never overwrites with undefined. */
  set(name: string, partial: Partial<PackageSignals>): void {
    const existing = this._signals.get(name) ?? {};
    const merged: PackageSignals = { ...existing };

    for (const key of Object.keys(partial) as Array<keyof PackageSignals>) {
      const value = partial[key];
      if (value !== undefined) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (merged as any)[key] = value;
      }
    }

    this._signals.set(name, merged);
  }

  getAll(): ReadonlyMap<string, PackageSignals> {
    return this._signals;
  }
}
