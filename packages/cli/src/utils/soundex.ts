/**
 * Generates the Soundex phonetic code for a string.
 *
 * Soundex encodes words by their English pronunciation, collapsing similar-
 * sounding consonants into a single digit. Two words with the same Soundex
 * code sound alike — useful for catching phonetic typosquatting attacks like
 * 'expres' vs 'express', or 'lodahs' vs 'lodash'.
 *
 * Algorithm (American Soundex):
 *   1. Keep the first letter as-is
 *   2. Replace consonants with digits (see map below)
 *   3. Remove adjacent duplicates
 *   4. Remove all vowels / H / W / Y
 *   5. Pad or truncate to 4 characters
 */
const CODES: Record<string, string> = {
  B: '1', F: '1', P: '1', V: '1',
  C: '2', G: '2', J: '2', K: '2', Q: '2', S: '2', X: '2', Z: '2',
  D: '3', T: '3',
  L: '4',
  M: '5', N: '5',
  R: '6',
};

export function soundex(str: string): string {
  if (!str || typeof str !== 'string') return '';

  // Normalise: uppercase, letters only
  const s = str.toUpperCase().replace(/[^A-Z]/g, '');
  if (!s.length) return '';

  const firstLetter = s[0];
  let result = firstLetter;
  let prevCode = CODES[firstLetter] ?? '0';

  for (let i = 1; i < s.length && result.length < 4; i++) {
    const code = CODES[s[i]];

    // Skip vowels, H, W, Y (no code) and adjacent duplicates
    if (code && code !== prevCode) {
      result += code;
    }

    // H and W do not separate same-coded letters; all others do
    if (s[i] !== 'H' && s[i] !== 'W') {
      prevCode = code ?? '0';
    }
  }

  // Pad to exactly 4 characters
  return result.padEnd(4, '0');
}

export function soundexMatch(a: string, b: string): boolean {
  return soundex(a) === soundex(b);
}
