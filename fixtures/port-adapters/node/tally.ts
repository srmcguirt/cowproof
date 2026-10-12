// The same reference in TypeScript (erasable syntax only: annotations, no enums).
export const CASE_FOLD: boolean = true;
export const MIN_LENGTH: number = 1;

interface Request {
  words: string[];
}

export function tally(request: Request): { counts: Record<string, number>; distinct: number; total: number } {
  const counts: Record<string, number> = {};
  for (const word of request.words) {
    const key: string = CASE_FOLD ? word.toLowerCase() : word;
    if (key.length < MIN_LENGTH) continue;
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return { counts, distinct: Object.keys(counts).length, total: request.words.length };
}
