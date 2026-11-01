import { countExecutableTestFunctions } from "@/lib/audit/poc-outcome";

/**
 * Pure rendering helpers for the PoC chat tab, kept out of the .tsx
 * so the component file exports only the component (the repo's
 * react-refresh lint rule) and so the segmentation + gate logic is
 * readable in one place.
 */

export type PocChatSegment =
  | { kind: "text"; text: string }
  | { kind: "code"; code: string; language: string };

/** Split an assistant reply into prose and fenced code blocks. */
export function splitChatSegments(content: string): PocChatSegment[] {
  const segments: PocChatSegment[] = [];
  const fence = /```([A-Za-z0-9_+-]*)\n?([\s\S]*?)```/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = fence.exec(content)) !== null) {
    if (m.index > last) segments.push({ kind: "text", text: content.slice(last, m.index) });
    segments.push({ kind: "code", code: m[2] ?? "", language: m[1] ?? "" });
    last = m.index + m[0].length;
  }
  if (last < content.length) segments.push({ kind: "text", text: content.slice(last) });
  return segments.filter((s) => (s.kind === "text" ? s.text.trim().length > 0 : true));
}

/**
 * The repo's executable-test gate, mirrored for the Run button: a
 * Test contract AND at least one executable test function (the same
 * two predicates the per-finding run path checks). A block failing
 * the gate can still be Applied — it just cannot be Run, because the
 * harness would execute zero tests and report no_tests.
 */
export function chatCodeIsRunnable(code: string): boolean {
  return /\bcontract\s+\w+\s+is\s+[^{]*\bTest\b/.test(code) && countExecutableTestFunctions(code) > 0;
}
