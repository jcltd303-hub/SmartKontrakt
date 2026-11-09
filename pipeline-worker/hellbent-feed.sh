#!/usr/bin/env bash
# HELLBENT -> pipeline worker feeder (thin wrapper over hellbent-feed.py).
#   bash pipeline-worker/hellbent-feed.sh [queue.txt] [options]
# Run `python3 pipeline-worker/hellbent-feed.py --help` for all options.
# Stdlib-only python3 — works in Termux proot on the phone.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found — install it first:"
  echo "  Ubuntu (proot): apt install -y python3"
  echo "  Termux:         pkg install python"
  exit 1
fi

exec python3 "$SCRIPT_DIR/hellbent-feed.py" "$@"
