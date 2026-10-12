// The Node reference: a tiny word counter the port replaces.
export const CASE_FOLD = true;
export const MIN_LENGTH = 1;

export function tally(request) {
  const counts = {};
  for (const word of request.words) {
    const key = CASE_FOLD ? word.toLowerCase() : word;
    if (key.length < MIN_LENGTH) continue;
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return { counts, distinct: Object.keys(counts).length, total: request.words.length };
}
