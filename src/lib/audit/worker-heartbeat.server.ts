// src/lib/audit/worker-heartbeat.server.ts
//
// Pipeline worker heartbeats (migration 0020), with the Sql handle
// injected — the same shape as dispositions.server.ts, so the semantics
// are testable against PGlite (worker-heartbeat.test.ts).
//
// One row per worker (the pipeline runs on two machines: phone +
// laptop). The worker upserts its row at boot, at run start, and at run
// end; the Records view reads the rows back and judges each worker's
// analyzer baseline against the current one. A worker that falls
// behind is then VISIBLE in the app instead of silently refilling the
// archive with findings in classes the newer analyzer already fixed.
import type { Sql } from "../sql-client.ts";
import { baselineOf, isBaselineOlder } from "./analyzer-version.ts";

export type WorkerHeartbeat = {
  workerId: string;
  analyzerVersion: string;
  state: string;
  note: string | null;
  startedAt: string;
  lastSeenAt: string;
};

type HeartbeatRow = {
  worker_id: string;
  analyzer_version: string;
  state: string;
  note: string | null;
  started_at: string;
  last_seen_at: string;
};

function rowToHeartbeat(row: HeartbeatRow): WorkerHeartbeat {
  return {
    workerId: row.worker_id,
    analyzerVersion: row.analyzer_version,
    state: row.state,
    note: row.note ?? null,
    startedAt: row.started_at,
    lastSeenAt: row.last_seen_at,
  };
}

/**
 * Upsert this worker's heartbeat. `startedAt` is set on first insert and
 * preserved afterwards (it marks when this worker process generation
 * first appeared); every call refreshes version, state, note and
 * last_seen_at.
 */
export async function recordWorkerHeartbeat(
  sql: Sql,
  input: { workerId: string; analyzerVersion: string; state: string; note?: string | null },
): Promise<void> {
  const workerId = input.workerId?.trim();
  if (!workerId) throw new Error("A worker id is required to record a heartbeat.");
  await sql`
    insert into worker_heartbeats (worker_id, analyzer_version, state, note)
    values (${workerId}, ${input.analyzerVersion}, ${input.state}, ${input.note ?? null})
    on conflict (worker_id) do update set
      analyzer_version = excluded.analyzer_version,
      state = excluded.state,
      note = excluded.note,
      last_seen_at = now()`;
}

/** All known workers, most recently seen first. */
export async function listWorkerHeartbeats(sql: Sql): Promise<WorkerHeartbeat[]> {
  const rows = await sql<HeartbeatRow>`
    select worker_id, analyzer_version, state, note, started_at, last_seen_at
    from worker_heartbeats
    order by last_seen_at desc`;
  return rows.map(rowToHeartbeat);
}

/** A heartbeat judged against the current analyzer baseline. */
export type WorkerStaleness = WorkerHeartbeat & {
  baseline: string | null;
  /** True when the worker's baseline is older than the current one. */
  stale: boolean;
};

export function judgeWorkerStaleness(
  heartbeats: WorkerHeartbeat[],
  currentStamp: string,
): WorkerStaleness[] {
  const currentBaseline = baselineOf(currentStamp);
  return heartbeats.map((h) => ({
    ...h,
    baseline: baselineOf(h.analyzerVersion),
    stale: isBaselineOlder(h.analyzerVersion, currentBaseline),
  }));
}
