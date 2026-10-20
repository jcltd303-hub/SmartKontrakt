/**
 * Shared text helpers for the SmartPoC modules. Pure, dependency-free.
 */

/**
 * A comment/string-stripped, length-preserving copy of Solidity source, so
 * indices in the result line up with the original (used for brace/paren
 * matching and identifier scans).
 */
export function stripNonCode(src: string): string {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") {
        out += " ";
        i += 1;
      }
    } else if (c === "/" && n === "*") {
      out += "  ";
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) {
        out += src[i] === "\n" ? "\n" : " ";
        i += 1;
      }
      out += "  ";
      i += 2;
    } else if (c === '"' || c === "'") {
      const quote = c;
      out += " ";
      i += 1;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === "\\") {
          out += "  ";
          i += 2;
          continue;
        }
        out += src[i] === "\n" ? "\n" : " ";
        i += 1;
      }
      out += " ";
      i += 1;
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

/** Split on top-level commas (ignores commas nested in (), [], <>). */
export function splitTopLevel(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of text) {
    if (ch === "(" || ch === "[" || ch === "<") depth += 1;
    else if (ch === ")" || ch === "]" || ch === ">") depth = Math.max(0, depth - 1);
    if (ch === "," && depth === 0) {
      out.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out;
}

/** Index of the `}` matching the `{` at `open` (in a stripped copy), or -1. */
export function matchBrace(stripped: string, open: number): number {
  let depth = 0;
  for (let i = open; i < stripped.length; i += 1) {
    if (stripped[i] === "{") depth += 1;
    else if (stripped[i] === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Index of the `)` matching the `(` at `open` (in a stripped copy), or -1. */
export function matchParen(stripped: string, open: number): number {
  let depth = 0;
  for (let i = open; i < stripped.length; i += 1) {
    if (stripped[i] === "(") depth += 1;
    else if (stripped[i] === ")") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}
