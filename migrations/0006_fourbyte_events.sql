-- Migration 0006: 4byte.directory event-signature database (32-byte topics).
-- Same shape as 0005's function-selector table. One row per
-- (topic, signature) pair; a topic can map to several event signatures.
-- Source: ethereum-lists/4bytes `event-signatures/` dir, imported by
-- scripts/import-4byte.mjs.

create table if not exists fourbyte_event_signatures (
  topic text not null, -- '0xddf252ad...'
  signature text not null, -- 'Transfer(address,address,uint256)'
  created_at timestamptz not null default now(),
  primary key (topic, signature)
);
