-- Migration 0009: real full-text search for the local knowledge base.
--
-- The previous query loaded the 150 most-recent chunks and scored them with a
-- JS tokenizer, so every chunk older than the newest 150 was silently
-- unreachable, and a semantic query only matched if the literal tokens
-- appeared. A stored tsvector column plus a GIN index moves filtering and
-- ranking into Postgres and removes the row cap. `replaceRagChunks` (the only
-- writer) populates `search_vector` on every insert; this migration backfills
-- rows written before the column existed.

alter table rag_knowledge_chunks add column if not exists search_vector tsvector;

create index if not exists rag_chunks_search_idx
  on rag_knowledge_chunks using gin (search_vector);

-- `to_tsvector(regconfig, text)` (the two-arg, explicitly-typed form) is
-- immutable, unlike the one-arg text form, so it is safe in a plain update.
update rag_knowledge_chunks
set search_vector = to_tsvector('english'::regconfig,
      coalesce(title, '') || ' ' || coalesce(content, '') || ' ' ||
      coalesce(keywords, '') || ' ' || coalesce(detector, '') || ' ' ||
      coalesce(swc, '') || ' ' || coalesce(contract_name, ''))
where search_vector is null;
