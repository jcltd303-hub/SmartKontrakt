#!/usr/bin/env bash
# SmartKontrakt pipeline worker — start the headless address-pipeline runner.
#   bash pipeline-worker/start.sh
# The worker stays alive serving its control API on http://127.0.0.1:8788
# (loopback only) until you Ctrl+C it. Browser close does not stop a run.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v npx >/dev/null 2>&1; then
  echo "npx not found — install npm first:"
  echo "  Ubuntu (proot): apt install -y npm"
  echo "  Termux:         pkg install -y nodejs"
  exit 1
fi

# First run only: the worker imports `pg` (node-postgres) from the repo's
# node_modules, so the repo dependencies must be installed.
if [ ! -d node_modules ]; then
  echo "Installing repo dependencies (first run only, a few minutes)..."
  npm install
fi

exec npx -y tsx pipeline-worker/worker.ts
