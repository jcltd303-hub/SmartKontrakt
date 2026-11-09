# HELLBENT feeder — queue → pipeline worker, no manual file step

HELLBENT (the profit-hunting ranker in `profit-agent/`) outputs scan
queues as plain txt files: 1,000 checksummed addresses, one per line
(`scan-queue-v2.txt`, `scan-queue-fullchain-v2.txt`, `scan-queue.txt`).

`hellbent-feed.py` is the wire between that output and this worker:

```
HELLBENT queue txt
  → filter skip-list (known analyzer killers) + dedupe (case-insensitive)
  → ~/hellbent-queue.csv   (stable path, one address per line)
  → GET  127.0.0.1:8788/status   (must be idle)
  → POST 127.0.0.1:8788/start    { addressesFile, chainId: "ethereum",
                                   aiSecondPass: true, delayMs: 600 }
  → worker's own Supabase skip-check drops already-saved addresses
```

## Files

| File | What it is |
|---|---|
| `hellbent-feed.py` | The feeder. Python 3 stdlib only — no installs. |
| `hellbent-feed.sh` | Thin bash wrapper (`bash pipeline-worker/hellbent-feed.sh …`). |
| `hellbent-skip.txt` | **Skip-list. Seeded with the ConfidentialPool OOM-killer.** Add any new killer here — the feeder also carries that one address built-in, in case the file is ever lost. |

## Phone commands (Termux proot, from the repo root)

> ⚠️ These files are built and tested locally but **not pushed yet** —
> they land in the repo on Jer's push word. After the push:

```bash
cd ~/SmartKontrakt
git stash; git pull; git stash pop   # if you have local changes; plain `git pull` if not
chmod +x pipeline-worker/hellbent-feed.sh
```

1. **Get the queue txt onto the phone** (download the file sent in chat,
   then move it somewhere stable):

   ```bash
   mv ~/storage/downloads/scan-queue-v2.txt ~/hellbent-scan-queue-v2.txt
   ```

   (Any path works — pass it as the first argument. A bare filename is
   also searched for in `~`, `~/Downloads`, and `~/storage/downloads`.)

2. **Make sure the worker is running** (skip if it already is):

   ```bash
   termux-wake-lock                      # in Termux, before proot
   bash scripts/termux-start-all.sh      # or: bash pipeline-worker/start.sh
   curl -s http://127.0.0.1:8788/status | head -c 300
   ```

3. **Feed it:**

   ```bash
   bash pipeline-worker/hellbent-feed.sh ~/hellbent-scan-queue-v2.txt
   ```

   Expected output on success:

   ```
   Read:    1000 line(s) — 0 blank/comment, 0 invalid, 0 duplicate(s) removed, 1 skip-listed removed
     SKIPPED (killer list): 0x000000000Ed1eabD231Be41d93b719056F7febFC
   Wrote:   /root/hellbent-queue.csv — 999 address(es), one per line
   STARTED: 999 addresses (N already saved, skipped by the worker), chain=ethereum, aiSecondPass=true, delayMs=600
   ```

4. **Monitor** as usual: `curl -s http://127.0.0.1:8788/status`, or the
   app's Address Pipeline tab.

## Behaviour worth knowing

- **Worker busy** → feeder writes `~/hellbent-queue.csv`, says so
  plainly, exit code 2, starts nothing. Re-run it when the run ends.
- **Worker down / unreachable** → same: file ready, message tells you to
  start the worker first. Nothing is half-started.
- **No argument** → auto-finds the newest queue
  (`scan-queue-fullchain-v2.txt` > `scan-queue-v2.txt` > `scan-queue.txt`)
  in cwd, `~`, the script folder, or `../profit-agent` (VM layout).
- **`--prep-only`** → file prep only, prints the exact manual `curl`
  `/start` line. Used for the local tests.
- **`--no-ai`** → `aiSecondPass: false` (default is on, the standing
  start config; the worker refuses AI mode without
  `OPENROUTER_API_KEY` in `pipeline-worker/.env` and the feeder relays
  that error verbatim).
- **Re-feeding is safe.** The feeder dedupes within the file; the worker
  dedupes against Supabase on every `/start`.
- **Skip-list maintenance:** one address per line in
  `hellbent-skip.txt`, `#` comments and reasons allowed, matching is
  case-insensitive. Every run prints what it removed and why it matters:
  ConfidentialPool's 265 KB source OOM-kills the analyzer (>4 GB heap),
  which would kill the worker mid-run.

## Local test evidence (2026-11-09, this VM — not the phone)

- `hellbent-feed.py --prep-only` on `scan-queue-v2.txt`:
  1,000 read → **999 written**, exactly the ConfidentialPool line
  removed, 0 invalid, 0 dupes.
- The produced file was parsed with the repo's **actual**
  `parseAddressList` (`src/lib/audit/address-fetcher.ts`, via tsx):
  **999 items**, all chain `ethereum`, killer absent.
- Mock-worker tests (local stub on 127.0.0.1): idle → `/start` POSTed
  with the exact standing payload and reported started; busy → file
  ready, exit 2, no POST; unreachable → file ready, exit 2.
