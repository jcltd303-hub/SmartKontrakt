-- Migration 0005: 4byte.directory function-selector database.
-- One row per (selector, signature) pair. A selector can map to several
-- text signatures (collisions), so the pair is the primary key — and the
-- PK's B-tree also serves lookups by selector (leftmost column).
-- Source: ethereum-lists/4bytes, the bulk dataset behind 4byte.directory,
-- imported by scripts/import-4byte.mjs. ~1.18M rows (API count 2026-10-17).

create table if not exists fourbyte_signatures (
  selector text not null, -- '0xa9059cbb'
  signature text not null, -- 'transfer(address,uint256)'
  created_at timestamptz not null default now(),
  primary key (selector, signature)
);
