/**
 * Shared tokenizer for the local knowledge base — used both when indexing a
 * report (to build a chunk's `keywords`) and when scoring a query. Previously
 * duplicated verbatim in `rag-chunks.ts` and `rag.server.ts`.
 */
const STOP_WORDS = new Set([
  "the", "and", "or", "to", "in", "a", "of", "for", "with", "on", "at", "by",
  "from", "is", "this", "that", "it",
]);

export function tokenize(text: string): string[] {
  const clean = text.toLowerCase().replace(/[^a-z0-9_#$]/g, " ");
  return clean.split(/\s+/).filter((w) => w.length > 2 && !STOP_WORDS.has(w));
}
