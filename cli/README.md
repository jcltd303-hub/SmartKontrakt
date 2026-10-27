# audit-tui — the terminal interface

The web UI is not needed on the box that runs the pipeline. This is the replacement:
one screen, driven by keys, showing the run, the LLM, the archive and the read
queue, over SSH, with no dependencies and no toolchain.

```bash
node cli/audit-tui.mjs                      # worker on :8788
WORKER_URL=http://127.0.0.1:8789 node cli/audit-tui.mjs
node cli/audit-tui.mjs --once               # one frame and exit (CI, cron, ssh one-liner)
DATABASE_URL=... node cli/audit-tui.mjs     # adds archive counts from the DB
```

Keys: `tab`/`↑↓` move, `enter` opens the selected item, `p` pauses, `u` resumes,
`x` (or `ctrl-c`) quits. `NO_COLOR=1` or `TERM=dumb` renders plain text.

## What it shows

| Panel | Source | Why it is there |
| --- | --- | --- |
| Header | `/status` | state, chain, and which shard this process owns |
| Progress | `/status` | bar, address rate, **ETA from the run's own clock** — not a sample window, so a run hours in estimates honestly |
| LLM | `/health/llm` | verdict plus `ok/total` usable, so `degraded` is visible before the narratives are empty |
| Archive | DB | scans, findings, critical, high |
| Read queue | DB + `triage.ts` | the banded queue — `now`, `next`, `live`, `bg` |
| Menu | — | run control, queue, stats, settings, database |

## Why not Rust

Considered, and it is the wrong trade today:

- The analyzer is 27k lines of **calibrated** TypeScript — 60 detectors,
  reachability classes, 131/143 SmartBugs, a 25-case incident corpus, the PoC
  chain. A rewrite forks that calibration and takes weeks to return to parity.
- The measured bottlenecks were bugs (4-byte timeouts, the retired Sourcify v1),
  not the runtime.
- A terminal client in the same runtime **imports** the queue, stats and freshness
  functions. A Rust one would have to re-implement them or shell out.
- There is no `cargo` on the pipeline box, so a Rust TUI could not be built there
  without adding a toolchain — the thing this is meant to avoid.

If profiling ever shows the Solidity parser dominating, port *that* behind a
boundary (napi or a subprocess). Not the pipeline.

## Testing

`src/lib/audit/cli-render.test.ts` covers every formatter as a pure function, and
one test spawns this binary against a fake worker to prove the polling path.
Rendering is separated from I/O in `render.mjs` for exactly that reason.
