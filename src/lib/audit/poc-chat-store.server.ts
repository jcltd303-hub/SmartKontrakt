import { getSql } from "@/lib/db";
import type { PocChatSaveInput, PocChatStoredMessage } from "./poc-chat-clean.ts";

/**
 * Persistence for saved PoC chat conversations (migration 0019,
 * table poc_chats). The chat panel saves a conversation on the
 * user's click and lists/loads/deletes from the same panel; rows are
 * unowned like every table in this app. All inputs arrive already
 * cleaned by poc-chat-clean.ts — this module is SQL + row shaping
 * only. getSql throws when no database is configured (the no-fallback
 * rule), and that error is the honest answer here: a save that
 * silently went nowhere would be worse than a failed one.
 */

export type SavedPocChatSummary = {
  id: string;
  title: string;
  address: string;
  chainId: string;
  contractName: string;
  messageCount: number;
  createdAt: string;
  updatedAt: string;
};

export type SavedPocChat = SavedPocChatSummary & {
  messages: PocChatStoredMessage[];
};

type PocChatRow = {
  id: string;
  title: string;
  address: string;
  chain_id: string;
  contract_name: string;
  message_count: number;
  messages_json?: string;
  created_at: Date | string;
  updated_at: Date | string;
};

const iso = (v: Date | string): string =>
  v instanceof Date ? v.toISOString() : String(v);

const toSummary = (row: PocChatRow): SavedPocChatSummary => ({
  id: row.id,
  title: row.title,
  address: row.address,
  chainId: row.chain_id,
  contractName: row.contract_name,
  messageCount: row.message_count,
  createdAt: iso(row.created_at),
  updatedAt: iso(row.updated_at),
});

/** Insert or overwrite one conversation (save is an explicit click;
 *  re-saving the same id updates it in place). */
export async function savePocChat(input: PocChatSaveInput): Promise<SavedPocChatSummary> {
  const sql = await getSql();
  const rows = await sql<PocChatRow>`
    insert into poc_chats (id, title, address, chain_id, contract_name, message_count, messages_json)
    values (${input.id}, ${input.title}, ${input.address}, ${input.chainId}, ${input.contractName},
            ${input.messages.length}, ${JSON.stringify(input.messages)})
    on conflict (id) do update set
      title = excluded.title,
      address = excluded.address,
      chain_id = excluded.chain_id,
      contract_name = excluded.contract_name,
      message_count = excluded.message_count,
      messages_json = excluded.messages_json,
      updated_at = now()
    returning id, title, address, chain_id, contract_name, message_count, created_at, updated_at`;
  return toSummary(rows[0]!);
}

/** The saved list, freshest first — summaries only (no message
 *  bodies), so the panel can render it without hauling every
 *  conversation's full text over the wire. */
export async function listPocChats(limit: number): Promise<SavedPocChatSummary[]> {
  const sql = await getSql();
  const rows = await sql<PocChatRow>`
    select id, title, address, chain_id, contract_name, message_count, created_at, updated_at
    from poc_chats
    order by updated_at desc
    limit ${limit}`;
  return rows.map(toSummary);
}

/** One full conversation for loading into the panel. */
export async function getPocChat(id: string): Promise<SavedPocChat> {
  const sql = await getSql();
  const rows = await sql<PocChatRow>`
    select id, title, address, chain_id, contract_name, message_count, messages_json, created_at, updated_at
    from poc_chats
    where id = ${id}`;
  const row = rows[0];
  if (!row) throw new Error(`Saved PoC chat ${id} not found`);
  let messages: PocChatStoredMessage[];
  try {
    const parsed: unknown = JSON.parse(row.messages_json ?? "[]");
    messages = Array.isArray(parsed) ? (parsed as PocChatStoredMessage[]) : [];
  } catch {
    throw new Error(`Saved PoC chat ${id} has a corrupt messages document`);
  }
  return { ...toSummary(row), messages };
}

/** Delete one saved conversation by id (the panel's per-chat
 *  delete). Returns whether a row was actually removed. */
export async function deletePocChat(id: string): Promise<{ deleted: boolean }> {
  const sql = await getSql();
  const rows = await sql<{ id: string }>`
    delete from poc_chats where id = ${id} returning id`;
  return { deleted: rows.length > 0 };
}
