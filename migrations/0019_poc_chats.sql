-- Migration 0019: saved PoC chat conversations.
--
-- The workbench PoC chat started session-only; the auditor needs the
-- conversation to survive the session (a PoC iteration can run across
-- days and across the phone/laptop pair). One row per saved
-- conversation: the display messages (user / assistant / run entries,
-- with any file attachments and the replying model id) as one JSON
-- document, plus the target snapshot the chat was about. Rows are
-- unowned, like every table in this app (no accounts). Deleting is
-- per-row by id from the chat panel — the user's own record, removed
-- on their click; there is no bulk delete.

create table if not exists poc_chats (
  id text primary key,
  title text not null,
  address text not null default '',
  chain_id text not null default '',
  contract_name text not null default '',
  message_count integer not null default 0,
  messages_json text not null default '[]',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists poc_chats_updated_idx
  on poc_chats (updated_at desc);
