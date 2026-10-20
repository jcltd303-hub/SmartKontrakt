# SmartPoC execution and evidence

SmartPoC is the shared Foundry execution flow in `src/lib/audit/foundry-backend.ts`.
It is not a separate Go engine. Existing retry and direct-run APIs delegate to it.

| Entry point | Behavior |
| --- | --- |
| Saved audit loaded into Workbench | Sequentially runs missing Critical/High finding PoCs when a target address exists; stops scheduling after a new load or backend outage. |
| Finding Run, AI review and Deep Agent | Uses Foundry execution, chain RPC retries, and compile repair. |
| Interactive editor and manual Foundry panel | Executes through the shared runner and reports standalone Supabase persistence status. |
| Recent PoC Audits | Runs recommended finding tests and persists findings/history. |
| Pipeline worker | Uses the same runner; confirmed findings retain their execution evidence. |

Each result carries the target, requested chain, executed-source SHA-256, start/finish
timestamps, attempted RPCs, test count, and Foundry output. These also appear in logs
so existing database records and UI output retain the evidence. A completed repaired
finding includes an original-input digest to avoid rerunning it unless its input changes.

Zero-test responses are errors even if the backend reports success. Skipped and
unreachable runs are not successful tests. A passing Foundry test proves its assertions
passed; exploit validity still depends on the test asserting the claimed behavior.

Execution requires the user's reachable Foundry backend. Database saves require the
configured PostgreSQL connection or browser publishable/anon Supabase configuration.
Persistence failures are shown separately from execution verdicts; Retry Save does
not execute the test again. Existing migrations through `0008_finding_poc_runs.sql`
must be applied. This refactor introduces no new schema migration.

Verification: `npm test`, `npm run typecheck`, `npm run build`. The tests cover
zero-test rejection, source evidence, chain-scoped execution, one compile repair,
saved-audit queue filtering/outage behavior, standalone saves, repaired-proof reuse,
and PostgreSQL evidence/history retention. These tests do not constitute a live
fork execution against a user's connected backend.
