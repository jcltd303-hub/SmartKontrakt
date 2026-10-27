-- Migration 0019: drop the RAG knowledge base.
--
-- RAG was eliminated on 2026-10-21 (storage): chunks stopped being built or
-- written on save, `bulk-persist` records were made the source of truth, and the
-- `indexToRag` flag became a no-op kept only for caller compatibility. What was
-- left is a table nothing writes, a column nothing reads, and a full-text index
-- over an empty table — plus 1,000 lines of module and UI that query it.
--
-- This drops the storage. The code removal lands with it for the column, because
-- `contract_scans` inserts still listed `is_rag_indexed`: dropping the column
-- without removing it from those inserts would break every save.
--
-- Idempotent: safe on a database where the table was already dropped by hand (the
-- case that made `sql/ops/wipe-keep-caches.sql` abort on a missing relation).

drop table if exists rag_knowledge_chunks cascade;

alter table contract_scans drop column if exists is_rag_indexed;
