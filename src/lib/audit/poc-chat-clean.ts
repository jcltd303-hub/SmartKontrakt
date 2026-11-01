/**
 * Input cleaning for the PoC chat server fns (ai.functions.ts).
 * Lives in its own module — not .server.ts, not the functions
 * file — so the caps are unit-testable under plain node:
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

/** A file the user attached to a chat message (upload in the chat
 *  panel). Text only — the client reads the file as text and the
 *  content rides inside the user turn, delimited as data. */
export type PocChatAttachment = {
  name: string;
  content: string;
};

export type PocChatWireMessage = {
  role: "user" | "assistant";
  content: string;
  attachments?: PocChatAttachment[];
};

/**
 * Which OpenRouter lane answers a chat send. "chat" is the
 * conversation lane (the reasoning default — explanations, audits,
 * strategy); "code" is the exploit-generation lane (the code-purpose
 * default) and is what the Suggest-a-PoC / Fix-the-last-run quick
 * actions send, so a generated exploit comes from the code model,
 * not the conversation model.
 */
export type PocChatPurpose = "chat" | "code";

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
export const POC_CHAT_MAX_ATTACHMENTS = 4;
export const POC_CHAT_MAX_ATTACHMENT_CHARS = 20000;
export const POC_CHAT_MAX_ATTACHMENT_NAME_CHARS = 120;

/** Saved conversations keep more than a send does: model replies
 *  (a full PoC file can run past the 8k send cap) and the run
 *  summaries are part of the record the user saved. */
export const POC_CHAT_MAX_STORED_MESSAGES = 200;
export const POC_CHAT_MAX_STORED_MESSAGE_CHARS = 64000;

const cap = (v: unknown, max: number): string =>
  typeof v === "string" ? v.slice(0, max) : "";

function cleanAttachments(raw: unknown): PocChatAttachment[] {
  if (!Array.isArray(raw)) return [];
  const out: PocChatAttachment[] = [];
  for (const a of raw) {
    if (out.length >= POC_CHAT_MAX_ATTACHMENTS) break;
    if (!a || typeof a !== "object") continue;
    const { name, content } = a as { name?: unknown; content?: unknown };
    if (typeof content !== "string" || content.length === 0) continue;
    out.push({
      name: cap(name, POC_CHAT_MAX_ATTACHMENT_NAME_CHARS) || "attachment",
      content: content.slice(0, POC_CHAT_MAX_ATTACHMENT_CHARS),
    });
  }
  return out;
}

/**
 * Clean the chat payload: at most the LAST 40 turns (the freshest end
 * of the conversation is the one that matters), each message a
 * user/assistant turn of at most 8,000 chars with at most 4 capped
 * attachments. Entries with any other role or a non-string body are
 * dropped, not coerced — a "system" or "run" entry smuggled into the
 * history must not reach the model as a privileged turn. The purpose
 * is coerced to the conversation lane unless it is exactly "code".
 * Throws when nothing usable remains.
 */
export function cleanPocChatInput(input: unknown): {
  messages: PocChatWireMessage[];
  context: PocChatWireContext;
  purpose: PocChatPurpose;
} {
  if (!input || typeof input !== "object") {
    throw new Error("Invalid request payload");
  }
  const { messages, context, purpose } = input as {
    messages?: unknown;
    context?: Partial<Record<keyof PocChatWireContext, unknown>>;
    purpose?: unknown;
  };
  if (!Array.isArray(messages)) {
    throw new Error("PoC chat requires a messages array");
  }
  const cleanMessages: PocChatWireMessage[] = [];
  for (const m of messages.slice(-POC_CHAT_MAX_TURNS)) {
    if (!m || typeof m !== "object") continue;
    const { role, content, attachments } = m as {
      role?: unknown;
      content?: unknown;
      attachments?: unknown;
    };
    if (role !== "user" && role !== "assistant") continue;
    if (typeof content !== "string" || content.trim().length === 0) continue;
    const cleaned: PocChatWireMessage = {
      role,
      content: content.slice(0, POC_CHAT_MAX_MESSAGE_CHARS),
    };
    const atts = cleanAttachments(attachments);
    if (atts.length > 0) cleaned.attachments = atts;
    cleanMessages.push(cleaned);
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
    purpose: purpose === "code" ? "code" : "chat",
  };
}

// ------------------------------------------------------------ saved chats

/** A message as persisted in poc_chats.messages_json — the display
 *  record, so the display-only "run" role and the replying model id
 *  are kept (the SEND cleaner above is the one that strips them). */
export type PocChatStoredMessage = {
  role: "user" | "assistant" | "run";
  content: string;
  attachments?: PocChatAttachment[];
  model?: string;
};

export type PocChatSaveInput = {
  id: string;
  title: string;
  address: string;
  chainId: string;
  contractName: string;
  messages: PocChatStoredMessage[];
};

const POC_CHAT_ID_RE = /^[A-Za-z0-9-]{8,64}$/;

/** Validate a saved-chat id (client-generated uuid shape). */
export function cleanPocChatId(input: unknown): { id: string } {
  if (!input || typeof input !== "object") throw new Error("Invalid request payload");
  const { id } = input as { id?: unknown };
  if (typeof id !== "string" || !POC_CHAT_ID_RE.test(id)) {
    throw new Error("PoC chat id is missing or malformed");
  }
  return { id };
}

/**
 * Clean a save payload. Messages keep the last 200 entries with the
 * stored caps; a message with an unknown role or empty body is
 * dropped. The title falls back to the first user turn, then to a
 * dated placeholder, so a saved chat is never untitled.
 */
export function cleanPocChatSaveInput(input: unknown): PocChatSaveInput {
  if (!input || typeof input !== "object") {
    throw new Error("Invalid request payload");
  }
  const raw = input as {
    id?: unknown;
    title?: unknown;
    address?: unknown;
    chainId?: unknown;
    contractName?: unknown;
    messages?: unknown;
  };
  const { id } = cleanPocChatId(raw);
  if (!Array.isArray(raw.messages)) {
    throw new Error("Saving a PoC chat requires a messages array");
  }
  const messages: PocChatStoredMessage[] = [];
  for (const m of raw.messages.slice(-POC_CHAT_MAX_STORED_MESSAGES)) {
    if (!m || typeof m !== "object") continue;
    const { role, content, attachments, model } = m as {
      role?: unknown;
      content?: unknown;
      attachments?: unknown;
      model?: unknown;
    };
    if (role !== "user" && role !== "assistant" && role !== "run") continue;
    if (typeof content !== "string" || content.trim().length === 0) continue;
    const cleaned: PocChatStoredMessage = {
      role,
      content: content.slice(0, POC_CHAT_MAX_STORED_MESSAGE_CHARS),
    };
    const atts = cleanAttachments(attachments);
    if (atts.length > 0) cleaned.attachments = atts;
    if (typeof model === "string" && model.trim().length > 0) {
      cleaned.model = model.slice(0, 200);
    }
    messages.push(cleaned);
  }
  if (messages.length === 0) {
    throw new Error("Nothing to save — the conversation is empty");
  }
  const firstUser = messages.find((m) => m.role === "user");
  const title =
    cap(raw.title, 120).trim() ||
    (firstUser ? firstUser.content.trim().slice(0, 80) : "") ||
    "PoC chat";
  return {
    id,
    title,
    address: cap(raw.address, 100),
    chainId: cap(raw.chainId, 100),
    contractName: cap(raw.contractName, 300),
    messages,
  };
}

/** Clean a saved-chat list request: just a clamped limit. */
export function cleanPocChatListInput(input: unknown): { limit: number } {
  const raw = (input && typeof input === "object" ? input : {}) as { limit?: unknown };
  const n = typeof raw.limit === "number" && Number.isFinite(raw.limit) ? Math.floor(raw.limit) : 30;
  return { limit: Math.min(50, Math.max(1, n)) };
}
