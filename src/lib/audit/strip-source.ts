// src/lib/audit/strip-source.ts
//
// One implementation of "the source with comments and string bodies blanked", shared by
// the detector that needed it and the calibration gate that needed it second.
//
// Why it lives here: `detect.ts` already imports from `severity-calibration.ts`, so the
// gate importing back would be a cycle. Duplicating the function would be worse — this
// session has spent enough time on two copies of one rule drifting apart.
//
// OFFSETS ARE PRESERVED. Every consumed character becomes a space (newlines stay
// newlines), so a match index computed on the stripped view can be used to slice the
// REAL source. The selfdestruct rule depends on that: it recovers the beneficiary
// argument by paren-scanning the original text at an offset found here.

/** Blank out `//`, `/* *\/` and string/char literals, preserving length and line breaks. */
export function stripCommentsAndStringsKeepLines(src: string): string {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") { out += " "; i += 1; }
    } else if (c === "/" && n === "*") {
      out += "  "; i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) {
        out += src[i] === "\n" ? "\n" : " "; i += 1;
      }
      out += "  "; i += 2;
    } else if (c === '"' || c === "'") {
      const q = c;
      out += " "; i += 1;
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") { out += "  "; i += 2; continue; }
        out += src[i] === "\n" ? "\n" : " "; i += 1;
      }
      out += " "; i += 1;
    } else {
      out += c; i += 1;
    }
  }
  return out;
}
