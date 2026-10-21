/**
 * Deterministic identity of a PoC run: the finding plus the sha3-256 of the
 * executed source.
 *
 * Persistence keys the run row on this, so re-saving the same proof updates the
 * existing row instead of appending a duplicate (migration 0013), and so the
 * question "have we already executed exactly this proof?" is answerable.
 *
 * Its own module — no database or server imports — so both the client and the
 * test harness can use it.
 */
import { sha3_256 } from "js-sha3";

export function pocRunKey(findingId: string, source: string): { id: string; digest: string } {
  const digest = sha3_256(source);
  return { id: `poc:${findingId}:${digest.slice(0, 40)}`, digest };
}
