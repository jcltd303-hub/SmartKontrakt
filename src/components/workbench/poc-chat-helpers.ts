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

export type PocChatContextEstimate = {
  /** Approximate tokens the next send will carry (system + history). */
  tokens: number;
  /** Conversation turns the next send will include (after the cap). */
  turns: number;
};

/**
 * Estimate the context window the next chat send will occupy: the
 * system prompt (the template prose is roughly constant; the context
 * fields enter at their prompt caps, mirroring poc-chat.server.ts)
 * plus the last 40 conversation turns at their wire caps, attachments
 * included. Chars/4 is the standard rough token ratio — this is a
 * gauge for the panel, not a billing number, and the UI labels it ≈.
 */
export function estimatePocChatContext(args: {
  messages: Array<{
    role: string;
    content: string;
    attachments?: Array<{ content: string }>;
  }>;
  sourceChars: number;
  findingsChars: number;
  draftChars: number;
  lastRunChars: number;
}): PocChatContextEstimate {
  const SYSTEM_TEMPLATE_CHARS = 2600;
  const systemChars =
    SYSTEM_TEMPLATE_CHARS +
    Math.min(args.sourceChars, 12000) +
    Math.min(args.findingsChars, 6000) +
    Math.min(args.draftChars, 30000) +
    Math.min(args.lastRunChars, 6000);
  const turns = args.messages
    .filter((m) => m.role === "user" || m.role === "assistant")
    .slice(-40);
  let historyChars = 0;
  for (const m of turns) {
    historyChars += Math.min(m.content.length, 8000);
    for (const att of (m.attachments ?? []).slice(0, 4)) {
      historyChars += Math.min(att.content.length, 12000);
    }
  }
  return {
    tokens: Math.ceil((systemChars + historyChars) / 4),
    turns: turns.length,
  };
}

/**
 * Render a conversation as a Markdown document for the panel's
 * Export button — the whole visible record: turns, run results,
 * attachment contents and the replying model per assistant turn.
 */
export function buildPocChatExport(args: {
  title: string;
  address: string;
  chainId: string;
  contractName: string;
  exportedAt: string;
  messages: Array<{
    role: string;
    content: string;
    model?: string;
    attachments?: Array<{ name: string; content: string }>;
  }>;
}): string {
  const lines: string[] = [
    `# ${args.title || "PoC chat"}`,
    "",
    `Target: ${args.address || "(none)"} (${args.chainId}) · Contract: ${args.contractName || "(unknown)"}`,
    `Exported: ${args.exportedAt}`,
    "",
  ];
  for (const m of args.messages) {
    if (m.role === "run") {
      lines.push("## Run result", "", "```", m.content, "```", "");
      continue;
    }
    const who = m.role === "user" ? "You" : "PoC assistant";
    lines.push(`## ${who}${m.role === "assistant" && m.model ? ` (via ${m.model})` : ""}`, "", m.content, "");
    for (const att of m.attachments ?? []) {
      lines.push(`### Attached file: ${att.name}`, "", "```", att.content, "```", "");
    }
  }
  return lines.join("\n");
}
