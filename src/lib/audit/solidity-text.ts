/**
 * Text utilities for Solidity source that the reply validators need.
 *
 * Why this exists: `parseTestCodeReply` rejects generated code containing string
 * concatenation with `+`, because Solidity has no such operator and the file then
 * never compiles (forge reports zero tests, which is indistinguishable from a file
 * with no test function). Measured 2026-11-04: the EntryPoint PoC carried a
 * four-line assertion message joined with `+` and every run of it was wasted.
 *
 * But the check ran against the raw file, comments included — and the generation
 * prompt itself says `never write "a" + "b"`. A model that echoes that instruction
 * in a comment, which is exactly the kind of explanatory comment the prompt
 * encourages, produced a file that was valid Solidity and was still rejected. The
 * retry then asked for the same thing again.
 *
 * Comments cannot break compilation, so the check must not see them.
 */

/**
 * Remove `//` line comments and `/* *\/` block comments from Solidity source,
 * leaving string literals untouched — a URL such as "https://example.com" contains
 * `//` and must survive, and a quote inside a comment must not open a string.
 *
 * Returns source of the same length semantics as needed for regex checks; it is not
 * intended for recompilation, only for pattern matching.
 */
export function stripSolidityComments(src: string): string {
  let out = "";
  let i = 0;
  const n = src.length;

  while (i < n) {
    const c = src[i]!;
    const next = src[i + 1];

    // Line comment: drop to end of line, keep the newline so line numbers survive.
    if (c === "/" && next === "/") {
      while (i < n && src[i] !== "\n") i += 1;
      continue;
    }

    // Block comment: drop through the closing marker.
    if (c === "/" && next === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }

    // String or char literal: copy verbatim, honouring backslash escapes.
    if (c === '"' || c === "'") {
      const quote = c;
      out += c;
      i += 1;
      while (i < n) {
        const d = src[i]!;
        out += d;
        if (d === "\\") {
          i += 1;
          if (i < n) {
            out += src[i]!;
            i += 1;
          }
          continue;
        }
        i += 1;
        if (d === quote) break;
      }
      continue;
    }

    out += c;
    i += 1;
  }

  return out;
}
