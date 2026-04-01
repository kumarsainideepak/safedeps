/**
 * Computes the Levenshtein edit distance between two strings.
 *
 * Levenshtein distance = minimum number of single-character edits
 * (insertions, deletions, substitutions) to transform string A into string B.
 *
 * Example:
 *   levenshtein('lodash', 'lodahs') => 2  (swap last two chars)
 *   levenshtein('react',  'recat')  => 2  (swap 'a' and 'c')
 *   levenshtein('express','expres') => 1  (one deletion)
 *
 * Uses dynamic programming with O(m*n) time and O(min(m,n)) space.
 */
export function levenshtein(a: string, b: string): number {
  // Quick exits
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Always iterate over the shorter string to save memory
  if (a.length > b.length) [a, b] = [b, a];

  const aLen = a.length;
  const bLen = b.length;

  // Single row DP — we only ever need the previous row
  let prevRow: number[] = Array.from({ length: aLen + 1 }, (_, i) => i);

  for (let j = 1; j <= bLen; j++) {
    const currRow: number[] = [j];

    for (let i = 1; i <= aLen; i++) {
      const insertCost  = currRow[i - 1] + 1;
      const deleteCost  = prevRow[i] + 1;
      const replaceCost = prevRow[i - 1] + (a[i - 1] === b[j - 1] ? 0 : 1);

      currRow.push(Math.min(insertCost, deleteCost, replaceCost));
    }

    prevRow = currRow;
  }

  return prevRow[aLen];
}
