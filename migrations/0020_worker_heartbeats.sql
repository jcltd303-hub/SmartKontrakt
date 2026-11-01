-- Migration 0020: pipeline worker heartbeats.
--
-- The two pipeline workers (phone + laptop) write one row each: their
-- identity, the analyzer version their code carries, their run state,
-- and when they were last seen. The Records view reads these rows to
-- show which workers exist and whether one is running an analyzer the
-- archive has already moved past — the stale-worker failure mode that
-- refilled the archive with already-fixed finding classes went
-- unnoticed for days because nothing anywhere displayed a worker's
-- version. Rows are unowned, like every table in this app. A worker
-- that never comes back simply ages in place; nothing deletes rows.

create table if not exists worker_heartbeats (
  worker_id text primary key,
  analyzer_version text not null,
  state text not null default 'idle',
  note text,
  started_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create index if not exists worker_heartbeats_seen_idx
  on worker_heartbeats (last_seen_at desc);
