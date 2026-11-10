#!/usr/bin/env python3
"""
HELLBENT -> SmartKontrakt pipeline worker feeder.

Takes a HELLBENT scan-queue txt (one checksummed address per line),
filters the skip-list (known analyzer killers), dedupes
case-insensitively, writes the result to a stable path the worker can
read, then — if the worker is up and idle — starts the run via
POST http://127.0.0.1:8788/start.

Stdlib only, so it runs anywhere python3 does: this VM, Termux, and
Termux proot Ubuntu on Jer's phone (where the worker lives).

Usage:
  python3 hellbent-feed.py [queue.txt] [options]
  bash hellbent-feed.sh scan-queue-v2.txt          # same, via wrapper

Config source of truth: src/lib/config.mjs (WORKER_URL_DEFAULT,
WORKER_START_DEFAULTS). This file is Python-stdlib-only and cannot import
the JS module, so the worker URL / chain / delay defaults below are
re-stated here and PINNED by the drift test in src/lib/audit/config-drift.test.ts
— if that test fails, update these defaults to match config.mjs, not the
other way around.

Options:
  --skip PATH      skip-list file (default: hellbent-skip.txt next to
                   this script, else ~/hellbent-skip.txt)
  --out PATH       output file (default: ~/hellbent-queue.csv)
  --worker URL     worker base URL (default: http://127.0.0.1:8788,
                   or $HELLBENT_WORKER_URL)
  --chain ID       chainId for /start (default: ethereum)
  --delay-ms N     delayMs for /start (default: 600)
  --no-ai          start with aiSecondPass off (default: on, matching
                   the standing worker start config)
  --prep-only      only write the output file; never contact the worker

Exit codes:
  0  run started, or --prep-only file written
  2  file written and ready, but the run was NOT started (worker busy,
     unreachable, or it rejected the start) — message says which
  1  bad input (queue missing/empty, no valid addresses, write failed)

The worker itself re-checks Supabase on /start and skips every
already-saved address, so feeding a queue twice never double-scans.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Defense in depth: this address is filtered even if the skip-list file
# is missing. ConfidentialPool — confirmed analyzer OOM-killer
# (2026-11-08, >4GB heap in detectSource). Keep hellbent-skip.txt as the
# editable list; this constant is the floor that cannot be lost.
BUILTIN_SKIP = {
    "0x000000000ed1eabd231be41d93b719056f7febfc": "OOM-killer ConfidentialPool (built-in)",
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def first_address_token(line):
    """First comma/semicolon/tab/space-delimited token of a line, unquoted."""
    line = line.strip().lstrip("\ufeff")
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    token = re.split(r"[,;\t ]", line, maxsplit=1)[0].strip().strip("\"'")
    return token or None


def load_skip_list(path):
    """Returns (lowercased address -> reason/note, path_used or None)."""
    skip = dict(BUILTIN_SKIP)
    used = None
    if path and os.path.isfile(path):
        used = path
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                token = first_address_token(raw)
                if token and ADDRESS_RE.match(token):
                    note = raw.strip()
                    skip[token.lower()] = note
    return skip, used


def default_skip_path(explicit):
    if explicit:
        return explicit
    env = os.environ.get("HELLBENT_SKIP", "").strip()
    if env:
        return os.path.expanduser(env)
    for cand in (
        os.path.join(SCRIPT_DIR, "hellbent-skip.txt"),
        os.path.expanduser("~/hellbent-skip.txt"),
        os.path.join(os.getcwd(), "hellbent-skip.txt"),
    ):
        if os.path.isfile(cand):
            return cand
    return None


def find_queue(explicit):
    """Resolve the queue argument, with phone/VM-friendly fallbacks."""
    if explicit:
        p = os.path.expanduser(explicit)
        if os.path.isfile(p):
            return p
        # Bare filename: search the places a downloaded queue lands.
        for base in (os.getcwd(), os.path.expanduser("~"),
                     os.path.expanduser("~/Downloads"),
                     os.path.expanduser("~/storage/downloads"),
                     SCRIPT_DIR, os.path.join(SCRIPT_DIR, "..", "profit-agent")):
            cand = os.path.join(base, explicit)
            if os.path.isfile(cand):
                return cand
        return None
    # No argument: newest HELLBENT queue wins (full-chain v2 > v2 > v1).
    for name in ("scan-queue-fullchain-v2.txt", "scan-queue-v2.txt", "scan-queue.txt"):
        for base in (os.getcwd(), os.path.expanduser("~"),
                     os.path.expanduser("~/Downloads"),
                     os.path.expanduser("~/storage/downloads"),
                     os.path.expanduser("~/storage/shared/Download"),
                     os.path.expanduser("/storage/emulated/0/Download"),
                     SCRIPT_DIR,
                     os.path.join(SCRIPT_DIR, "..", "profit-agent")):
            cand = os.path.join(base, name)
            if os.path.isfile(cand):
                return cand
    return None


def prep_queue(queue_path, skip):
    """Filter + dedupe. Returns (kept, stats) — kept preserves the first
    occurrence's checksummed spelling and queue order."""
    kept = []
    seen = set()
    stats = {"lines": 0, "blank_or_comment": 0, "invalid": [], "dupes": 0,
             "skipped": []}
    with open(queue_path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            stats["lines"] += 1
            token = first_address_token(raw)
            if token is None:
                stats["blank_or_comment"] += 1
                continue
            if not ADDRESS_RE.match(token):
                stats["invalid"].append(raw.strip()[:80])
                continue
            low = token.lower()
            if low in skip:
                stats["skipped"].append(token)
                continue
            if low in seen:
                stats["dupes"] += 1
                continue
            seen.add(low)
            kept.append(token)
    return kept, stats


def write_output(kept, out_path):
    """Atomic write: tmp file in the same directory, then rename, so the
    worker never reads a half-written queue."""
    out_path = os.path.abspath(os.path.expanduser(out_path))
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for addr in kept:
            fh.write(addr + "\n")
    os.replace(tmp, out_path)
    return out_path


def http_json(method, url, payload=None, timeout=15):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body or "{}")
        except json.JSONDecodeError:
            parsed = {"error": body.strip()[:300]}
        return err.code, parsed


def main(argv=None):
    ap = argparse.ArgumentParser(description="Feed a HELLBENT queue to the pipeline worker.")
    ap.add_argument("queue", nargs="?", help="HELLBENT queue txt (default: auto-find latest)")
    ap.add_argument("--skip", help="skip-list file")
    ap.add_argument("--out", default="~/hellbent-queue.csv",
                    help="output file (default: ~/hellbent-queue.csv)")
    ap.add_argument("--worker", default=os.environ.get("HELLBENT_WORKER_URL", "http://127.0.0.1:8788"),
                    help="worker base URL (default: WORKER_URL_DEFAULT in src/lib/config.mjs)")
    ap.add_argument("--chain", default="ethereum",
                    help="chainId (default: WORKER_START_DEFAULTS.chainId in src/lib/config.mjs)")
    ap.add_argument("--delay-ms", type=int, default=600,
                    help="delayMs (default: WORKER_START_DEFAULTS.delayMs in src/lib/config.mjs)")
    ap.add_argument("--no-ai", action="store_true", help="aiSecondPass off (default: on)")
    ap.add_argument("--prep-only", action="store_true",
                    help="write the file only; do not contact the worker")
    args = ap.parse_args(argv)

    queue_path = find_queue(args.queue)
    if not queue_path:
        print(f"ERROR: queue file not found: {args.queue or '(no default queue found)'}",
              file=sys.stderr)
        print("Searched: the given path, cwd, ~, ~/Downloads, "
              "~/storage/downloads, ~/storage/shared/Download, "
              "/storage/emulated/0/Download, this script's folder, and "
              "../profit-agent.", file=sys.stderr)
        return 1
    queue_path = os.path.abspath(queue_path)

    skip_path = default_skip_path(args.skip)
    skip, skip_used = load_skip_list(skip_path)
    if args.skip and not skip_used:
        print(f"WARNING: --skip file not found ({args.skip}); built-in skip-list only.",
              file=sys.stderr)
    elif not skip_used:
        print("WARNING: no hellbent-skip.txt found; built-in skip-list only "
              f"({len(BUILTIN_SKIP)} address).", file=sys.stderr)

    kept, stats = prep_queue(queue_path, skip)
    print(f"Queue:   {queue_path}")
    print(f"Skip:    {skip_used or '(built-in only)'} ({len(skip)} address(es) listed)")
    print(f"Read:    {stats['lines']} line(s)"
          f" — {stats['blank_or_comment']} blank/comment,"
          f" {len(stats['invalid'])} invalid,"
          f" {stats['dupes']} duplicate(s) removed,"
          f" {len(stats['skipped'])} skip-listed removed")
    for addr in stats["skipped"]:
        print(f"  SKIPPED (killer list): {addr}")
    for bad in stats["invalid"][:5]:
        print(f"  INVALID line ignored: {bad}")
    if len(stats["invalid"]) > 5:
        print(f"  ... and {len(stats['invalid']) - 5} more invalid line(s)")

    if not kept:
        print("ERROR: no addresses left after filtering — nothing written.", file=sys.stderr)
        return 1

    try:
        out_path = write_output(kept, args.out)
    except OSError as err:
        print(f"ERROR: could not write output file: {err}", file=sys.stderr)
        return 1
    print(f"Wrote:   {out_path} — {len(kept)} address(es), one per line")

    if args.prep_only:
        print("Prep only — worker not contacted. Start it manually with:")
        print(f'  curl -s -X POST {args.worker}/start -H \'Content-Type: application/json\' \\')
        print(f'    -d \'{{"addressesFile": "{out_path}", "chainId": "{args.chain}", '
              f'"aiSecondPass": {str(not args.no_ai).lower()}, "delayMs": {args.delay_ms}}}\'')
        return 0

    # --- talk to the worker -------------------------------------------------
    worker = args.worker.rstrip("/")
    try:
        code, status_body = http_json("GET", f"{worker}/status")
    except (urllib.error.URLError, OSError, ValueError) as err:
        print(f"\nWorker NOT reachable at {worker} ({err}).")
        print(f"The queue file is ready: {out_path} ({len(kept)} addresses).")
        print("Start the worker first (in proot, from the repo root):")
        print("  bash pipeline-worker/start.sh")
        print("then re-run this feeder, or start the run manually with the "
              "curl line shown by --prep-only.")
        return 2
    if code != 200 or not isinstance(status_body, dict):
        print(f"\nWorker /status answered HTTP {code} — not starting anything.")
        print(f"The queue file is ready: {out_path} ({len(kept)} addresses).")
        return 2

    state = status_body.get("state", "unknown")
    if state != "idle":
        print(f"\nWorker is BUSY (state: {state}"
              + (f", {status_body.get('completed', 0)}/{status_body.get('total', 0)} done"
                 f", current: {status_body.get('current')}" if state in ("running", "paused", "stopping") else "")
              + "). Run NOT started.")
        print(f"The queue file is ready: {out_path} ({len(kept)} addresses).")
        print("Wait for the current run to finish (or POST /stop), then re-run this feeder.")
        return 2

    payload = {
        "addressesFile": out_path,
        "chainId": args.chain,
        "aiSecondPass": not args.no_ai,
        "delayMs": args.delay_ms,
    }
    try:
        code, body = http_json("POST", f"{worker}/start", payload)
    except (urllib.error.URLError, OSError, ValueError) as err:
        print(f"\nWorker /start failed to send ({err}).")
        print(f"The queue file is ready: {out_path} ({len(kept)} addresses).")
        return 2
    if code == 200 and isinstance(body, dict) and body.get("ok"):
        print(f"\nSTARTED: {body.get('total', len(kept))} addresses"
              f" ({body.get('skipped', 0)} already saved, skipped by the worker),"
              f" chain={args.chain}, aiSecondPass={str(payload['aiSecondPass']).lower()},"
              f" delayMs={args.delay_ms}")
        print(f"Monitor: curl -s {worker}/status")
        return 0

    err_msg = body.get("error") if isinstance(body, dict) else str(body)
    print(f"\nWorker REJECTED the start (HTTP {code}): {err_msg}")
    print(f"The queue file is ready: {out_path} ({len(kept)} addresses).")
    if payload["aiSecondPass"] and err_msg and "OPENROUTER_API_KEY" in str(err_msg):
        print("Hint: set OPENROUTER_API_KEY in pipeline-worker/.env, or re-run with --no-ai.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
