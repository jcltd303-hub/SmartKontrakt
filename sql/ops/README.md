# Archive operations

Postgres scripts, run against the project database. The BigQuery queries in the
parent directory are unrelated — those read public chain data.

Run from the repo root:

```bash
set -a; . pipeline-worker/.env; set +a      # DATABASE_URL lives there
```

## Order of operations before a wipe

```bash
# 1. A real backup, to a local file. Not the in-database snapshot below:
#    that dies with the project.
bash scripts/backup-supabase.sh
#    Check the tail: elapsed time, file size, restorable object count.

# 2. Clear the archive, keeping what was learned.
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/ops/wipe-keep-caches.sql
```

## The scripts

| File | What it does | Reversible |
| --- | --- | --- |
| `wipe-keep-caches.sql` | Truncates the five scan-output tables. **Keeps** `fp_signatures` (accumulated false-positive knowledge) and the fourbyte selector caches, and copies `auditor_dispositions` into `dispositions_archive` first, because `finding_id ... ON DELETE CASCADE` would otherwise destroy every human triage decision as a side effect. | No, but the caches and triage notes survive |
| `wipe-all.sql` | Truncates all nine tables. Nothing learned survives. | No |
| `backup-snapshot.sql` | Copies every table into a `backup_<date>` schema in the same database, and refuses to re-run over an existing snapshot. | Yes, via `restore-snapshot.sql` — but only against the same database |
| `restore-snapshot.sql` | Restores from a `backup_<date>` schema in one transaction, in foreign-key order. | — |

`wipe-all.sql` and `backup-snapshot.sql` print row counts before they act, so the
transcript says what moved.

## What a wipe means for the next run

Nothing in the archive is worth keeping on analysis grounds: it was produced under
older detector rules, and the PoC verdicts in it are mostly infrastructure failures
that the classifier was mislabelling as `no_tests`. After a wipe every address is
new, so `refresh` is irrelevant — pass `refresh: "none"`.
