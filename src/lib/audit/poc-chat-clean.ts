/**
 * Input cleaning for the PoC chat server fn (requestPocChat in
 * ai.functions.ts). Lives in its own module — not .server.ts, not the
 * functions file — so the caps are unit-testable under plain node:
 * ai.functions.ts pulls in @tanstack/react-start, which the repo's
 * node --test harness never imports.
 *
 * The caps mirror requestPocRepair's: bulk text fields at 30,000
 * chars, log-shaped fields at 8,000, short identity fields at a few
 * hundred. The server module (poc-chat.server.ts) re-caps everything
 * again when it assembles the prompt — the validator is the wire
 * boundary, the prompt caps are the budget boundary, and neither
 * trusts the other.
 */

export type PocChatWireMessage = {
  role: "user" | "assistant";
  content: string;
};

export type PocChatWireContext = {
  address: string;
  chainId: string;
  contractName: string;
  source: string;
  findingsSummary: string;
  pocDraft: string;
  lastRunSummary: string;
};

export const POC_CHAT_MAX_TURNS = 40;
export const POC_CHAT_MAX_MESSAGE_CHARS = 8000;

const cap = (v: unknown, max: number): string =>
  typeof v === "string" ? v.slice(0, max) : "";

/**
 * Clean the chat payload: at most the LAST 40 turns (the freshest end
 * of the conversation is the one that matters), each message a
 * user/assistant turn of at most 8,000 chars. Entries with any other
 * role or a non-string body are dropped, not coerced — a "system" or
 * "run" entry smuggled into the history must not reach the model as a
 * privileged turn. Throws when nothing usable remains.
 */
export function cleanPocChatInput(input: unknown): {
  messages: PocChatWireMessage[];
  context: PocChatWireContext;
} {
  if (!input || typeof input !== "object") {
    throw new Error("Invalid request payload");
  }
  const { messages, context } = input as {
    messages?: unknown;
    context?: Partial<Record<keyof PocChatWireContext, unknown>>;
  };
  if (!Array.isArray(messages)) {
    throw new Error("PoC chat requires a messages array");
  }
  const cleanMessages: PocChatWireMessage[] = [];
  for (const m of messages.slice(-POC_CHAT_MAX_TURNS)) {
    if (!m || typeof m !== "object") continue;
    const { role, content } = m as { role?: unknown; content?: unknown };
    if (role !== "user" && role !== "assistant") continue;
    if (typeof content !== "string" || content.trim().length === 0) continue;
    cleanMessages.push({ role, content: content.slice(0, POC_CHAT_MAX_MESSAGE_CHARS) });
  }
  if (cleanMessages.length === 0) {
    throw new Error("PoC chat requires at least one user or assistant message");
  }
  const ctx = context && typeof context === "object" ? context : {};
  return {
    messages: cleanMessages,
    context: {
      address: cap(ctx.address, 100),
      chainId: cap(ctx.chainId, 100),
      contractName: cap(ctx.contractName, 300) || "TargetContract",
      source: cap(ctx.source, 30000),
      findingsSummary: cap(ctx.findingsSummary, 8000),
      pocDraft: cap(ctx.pocDraft, 30000),
      lastRunSummary: cap(ctx.lastRunSummary, 8000),
    },
  };
}
