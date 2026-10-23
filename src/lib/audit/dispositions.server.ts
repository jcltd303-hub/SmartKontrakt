// src/lib/audit/dispositions.server.ts
//
// Persistence for auditor dispositions (migration 0015), with the Sql
// handle injected — the same shape as scan-archive.server.ts, so the
// semantics are testable against PGlite without a live database
// (dispositions.test.ts). persist.server.ts holds the getSql()-resolving
// wrappers the server functions call.
//
// Write semantics are the idempotency contract of the feature:
// - one row per finding (finding_id is the PK);
// - setting a disposition UPSERTS that row;
// - setting the SAME disposition + note again is a true no-op: no write
//   happens, so `updated_at` does not move and the returned row is the
//   stored one.
import type { Sql } from "../sql-client.ts";
import {
  isAuditorDisposition,
  type AuditorDisposition,
  type FindingDisposition,
} from "./adjudication.ts";

export type { AuditorDisposition, FindingDisposition };

const MAX_NOTE_CHARS = 2000;

type DispositionRow = {
  finding_id: string;
  disposition: string;
  note: string | null;
  updated_at: string;
};

function rowToDisposition(row: DispositionRow): FindingDisposition | null {
  if (!isAuditorDisposition(row.disposition)) return null;
  return {
    findingId: row.finding_id,
    disposition: row.disposition,
    note: row.note ?? null,
    updatedAt: row.updated_at,
  };
}

function cleanNote(note: string | null | undefined): string | null {
  if (typeof note !== "string") return null;
  const trimmed = note.trim();
  return trimmed ? trimmed.slice(0, MAX_NOTE_CHARS) : null;
}

/**
 * Set (or change) the auditor disposition for one finding. Returns the
 * row of record after the write — or the pre-existing row, untouched,
 * when the requested disposition + note already match it.
 */
export async function setDispositionRow(
  sql: Sql,
  input: { findingId: string; disposition: AuditorDisposition; note?: string | null },
): Promise<FindingDisposition> {
  if (!input.findingId?.trim()) throw new Error("A finding id is required to set a disposition.");
  if (!isAuditorDisposition(input.disposition)) {
    throw new Error(`Unknown auditor disposition: ${String(input.disposition)}`);
  }
  const note = cleanNote(input.note);

  const existing = await sql<DispositionRow>`
    select finding_id, disposition, note, updated_at::text as updated_at
    from auditor_dispositions
    where finding_id = ${input.findingId}
  `;
  const current = existing[0] ? rowToDisposition(existing[0]) : null;
  if (current && current.disposition === input.disposition && current.note === note) {
    return current; // same value re-set: a no-op by contract
  }

  const rows = await sql<DispositionRow>`
    insert into auditor_dispositions (finding_id, disposition, note, updated_at)
    values (${input.findingId}, ${input.disposition}, ${note}, now())
    on conflict (finding_id) do update
      set disposition = excluded.disposition,
          note = excluded.note,
          updated_at = now()
    returning finding_id, disposition, note, updated_at::text as updated_at
  `;
  const written = rows[0] ? rowToDisposition(rows[0]) : null;
  if (!written) throw new Error("The disposition write did not return a row.");
  return written;
}

/** All dispositions for the findings of one scan. */
export async function getDispositionRowsForScan(sql: Sql, scanId: string): Promise<FindingDisposition[]> {
  const rows = await sql<DispositionRow>`
    select d.finding_id, d.disposition, d.note, d.updated_at::text as updated_at
    from auditor_dispositions d
    join findings f on f.id = d.finding_id
    where f.scan_id = ${scanId}
    order by d.updated_at desc
  `;
  return rows.map(rowToDisposition).filter((d): d is FindingDisposition => d !== null);
}

/** Dispositions for an explicit set of finding ids (the PoC Audits feed
 *  spans many scans, so it asks by id). Empty input → empty result, no
 *  query issued. */
export async function getDispositionRowsForFindings(
  sql: Sql,
  findingIds: readonly string[],
): Promise<FindingDisposition[]> {
  if (findingIds.length === 0) return [];
  const rows = await sql.query<DispositionRow>(
    `select finding_id, disposition, note, updated_at::text as updated_at
     from auditor_dispositions
     where finding_id = any($1::text[])
     order by updated_at desc`,
    [[...findingIds]],
  );
  return rows.map(rowToDisposition).filter((d): d is FindingDisposition => d !== null);
}

/** findingId → disposition map, the shape both UIs consume. */
export function dispositionsByFindingId(
  rows: readonly FindingDisposition[],
): Record<string, FindingDisposition> {
  const out: Record<string, FindingDisposition> = {};
  for (const row of rows) out[row.findingId] = row;
  return out;
}
