// src/lib/audit/fp-signatures.server.ts
//
// Persistence for the FP signature layer (migration 0017), with the
// Sql handle injected — the same shape as dispositions.server.ts, so
// the semantics are testable against PGlite without a live database
// (fp-signatures.server.test.ts). persist.server.ts holds the
// getSql()-resolving wrappers the server functions call.
//
// Ownership split, by design:
// - auditor_dispositions is the source of truth for EVIDENCE: the only
//   rows derivation reads are findings a human disposed as
//   'false_positive'.
// - fp_signatures stores the human's DECISION about a derived pattern
//   (candidate / confirmed / dismissed) plus the evidence snapshot.
// Refresh semantics:
// - a derived key with no row is inserted as 'candidate';
// - an existing row's evidence snapshot is refreshed in place — its
//   status and decided_at are NEVER touched by refresh, so a
//   dismissed signature is never re-proposed and a confirmed one is
//   never silently un-confirmed by new data;
// - a CANDIDATE whose evidence evaporates (its dispositions were
//   changed away from false_positive, dropping it below the two-scan
//   threshold) is deleted — it was never decided, and keeping it would
//   propose a pattern the evidence no longer supports. Confirmed and
//   dismissed rows are decisions of record and are kept regardless.
import type { Sql } from "../sql-client.ts";
import {
  deriveFpSignatureCandidates,
  isFpSignatureDecision,
  type FpEvidenceRow,
  type FpSignature,
  type FpSignatureStatus,
} from "./fp-signatures.ts";

type FpSignatureRow = {
  signature_key: string;
  detector: string;
  title_pattern: string;
  location_fn: string | null;
  snippet_class: string | null;
  status: string;
  evidence_count: number;
  scan_count: number;
  sample_finding_ids: string;
  sample_titles: string;
  created_at: string;
  updated_at: string;
  decided_at: string | null;
};

const FP_SIGNATURE_STATUS_SET: ReadonlySet<string> = new Set(["candidate", "confirmed", "dismissed"]);

function parseJsonArray(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function rowToSignature(row: FpSignatureRow): FpSignature | null {
  if (!FP_SIGNATURE_STATUS_SET.has(row.status)) return null;
  return {
    key: row.signature_key,
    detector: row.detector,
    titlePattern: row.title_pattern,
    locationFn: row.location_fn ?? null,
    snippetClass:
      row.snippet_class === "disassembly" || row.snippet_class === "source" || row.snippet_class === "empty"
        ? row.snippet_class
        : null,
    status: row.status as FpSignatureStatus,
    evidenceCount: row.evidence_count,
    scanCount: row.scan_count,
    sampleFindingIds: parseJsonArray(row.sample_finding_ids),
    sampleTitles: parseJsonArray(row.sample_titles),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    decidedAt: row.decided_at ?? null,
  };
}

const SIGNATURE_COLUMNS = `
  signature_key, detector, title_pattern, location_fn, snippet_class, status,
  evidence_count, scan_count, sample_finding_ids, sample_titles,
  created_at::text as created_at, updated_at::text as updated_at, decided_at::text as decided_at
`;

/** The derivation input: every finding a human disposed as
 *  false_positive, with the shape columns. Dispositions of any other
 *  value contribute nothing — confirmed findings are the layer's
 *  negative space, not its evidence. */
export async function readFpEvidenceRows(sql: Sql): Promise<FpEvidenceRow[]> {
  const rows = await sql<{
    finding_id: string;
    scan_id: string;
    detector: string;
    title: string;
    location_fn: string | null;
    snippet: string;
  }>`
    select f.id as finding_id, f.scan_id as scan_id, f.detector, f.title,
           f.location_fn, f.snippet
    from auditor_dispositions d
    join findings f on f.id = d.finding_id
    where d.disposition = 'false_positive'
    order by f.id asc
  `;
  return rows.map((r) => ({
    findingId: r.finding_id,
    scanId: r.scan_id,
    detector: r.detector,
    title: r.title,
    locationFn: r.location_fn ?? null,
    snippet: r.snippet ?? "",
  }));
}

/** All stored signature rows: candidates first (they are the work
 *  queue), then confirmed, then dismissed; strongest evidence first
 *  within a status. */
export async function listFpSignatureRows(sql: Sql): Promise<FpSignature[]> {
  const rows = await sql.query<FpSignatureRow>(
    `select ${SIGNATURE_COLUMNS}
     from fp_signatures
     order by case status when 'candidate' then 0 when 'confirmed' then 1 else 2 end,
              evidence_count desc, signature_key asc`,
  );
  return rows.map(rowToSignature).filter((s): s is FpSignature => s !== null);
}

/** Confirmed signatures only — the annotation source for read paths. */
export async function getConfirmedFpSignatureRows(sql: Sql): Promise<FpSignature[]> {
  const rows = await sql.query<FpSignatureRow>(
    `select ${SIGNATURE_COLUMNS}
     from fp_signatures
     where status = 'confirmed'
     order by evidence_count desc, signature_key asc`,
  );
  return rows.map(rowToSignature).filter((s): s is FpSignature => s !== null);
}

/**
 * Re-derive candidates from the current false_positive dispositions
 * and reconcile them with the stored decisions (see the header for the
 * exact semantics). Returns every stored row after the refresh.
 */
export async function refreshFpSignatures(sql: Sql): Promise<FpSignature[]> {
  const candidates = deriveFpSignatureCandidates(await readFpEvidenceRows(sql));
  const derivedKeys = new Set(candidates.map((c) => c.key));

  for (const candidate of candidates) {
    // Insert as candidate, or refresh ONLY the evidence snapshot of
    // the existing row — status/decided_at are the human's and are
    // deliberately absent from the update set.
    await sql`
      insert into fp_signatures (
        signature_key, detector, title_pattern, location_fn, snippet_class, status,
        evidence_count, scan_count, sample_finding_ids, sample_titles
      ) values (
        ${candidate.key}, ${candidate.payload.detector}, ${candidate.payload.titlePattern},
        ${candidate.payload.locationFn}, ${candidate.payload.snippetClass}, 'candidate',
        ${candidate.evidenceCount}, ${candidate.scanCount},
        ${JSON.stringify(candidate.sampleFindingIds)}, ${JSON.stringify(candidate.sampleTitles)}
      )
      on conflict (signature_key) do update
        set evidence_count = excluded.evidence_count,
            scan_count = excluded.scan_count,
            sample_finding_ids = excluded.sample_finding_ids,
            sample_titles = excluded.sample_titles,
            updated_at = now()
    `;
  }

  // Evaporated candidates (never decided, evidence gone) are removed;
  // decided rows stay whatever the evidence does now.
  const existing = await listFpSignatureRows(sql);
  for (const row of existing) {
    if (row.status === "candidate" && !derivedKeys.has(row.key)) {
      await sql`delete from fp_signatures where signature_key = ${row.key}`;
    }
  }
  return listFpSignatureRows(sql);
}

/**
 * Record the human's decision on one signature. Confirm and dismiss
 * are the only decisions; re-deciding (confirm → dismiss and back) is
 * allowed and moves decided_at — the row is the decision of record,
 * and the latest human word wins.
 */
export async function setFpSignatureStatus(
  sql: Sql,
  input: { signatureKey: string; status: "confirmed" | "dismissed" },
): Promise<FpSignature> {
  if (!input.signatureKey?.trim()) throw new Error("A signature key is required to record a decision.");
  if (!isFpSignatureDecision(input.status)) {
    throw new Error(`Unknown FP signature decision: ${String(input.status)}`);
  }
  const rows = await sql.query<FpSignatureRow>(
    `update fp_signatures
     set status = $1, decided_at = now(), updated_at = now()
     where signature_key = $2
     returning ${SIGNATURE_COLUMNS}`,
    [input.status, input.signatureKey],
  );
  const updated = rows[0] ? rowToSignature(rows[0]) : null;
  if (!updated) throw new Error(`No FP signature exists for key ${input.signatureKey}.`);
  return updated;
}
