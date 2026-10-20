#!/usr/bin/env bash
# Linux CI runner. Each npm server gets a dedicated process group for cleanup.
set -euo pipefail
cd "$(dirname "$0")/.."
artifacts=/workspace/screenshots/ci
mkdir -p "$artifacts"
server_pid=''
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill -TERM -- "-$server_pid" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=''
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_server() {
  local mode="$1" port="$2"
  # A pre-existing listener must never provide a false positive readiness check.
  if curl --silent --max-time 2 "http://127.0.0.1:$port/" >/dev/null; then
    echo "Refusing occupied port $port" >&2
    return 1
  fi
  setsid npm run "$mode" >"$artifacts/$mode-server.log" 2>&1 &
  server_pid=$!
  local ready=0
  for ((attempt = 0; attempt < 120; attempt++)); do
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "$mode server exited before becoming ready; see $mode-server.log" >&2
      return 1
    fi
    if curl --silent --fail --max-time 2 "http://127.0.0.1:$port/" >/dev/null; then
      ready=1
      break
    fi
    sleep 0.5
  done
  if [[ "$ready" != 1 ]]; then
    echo "$mode server did not become healthy within the bounded readiness window" >&2
    return 1
  fi
}

start_server dev 8080
timeout --signal=TERM --kill-after=5s 120s node scripts/browser-smoke.mjs \
  http://127.0.0.1:8080/ "$artifacts/dev.png" >"$artifacts/dev-smoke.log" 2>&1
node scripts/ci-smoke-verdict.mjs "$artifacts/dev.json"
cleanup
start_server preview 8081
timeout --signal=TERM --kill-after=5s 120s node scripts/browser-smoke.mjs \
  http://127.0.0.1:8081/ "$artifacts/built.png" --baseline "$artifacts/dev.json" \
  >"$artifacts/built-smoke.log" 2>&1
node scripts/ci-smoke-verdict.mjs "$artifacts/built.json" --require-baseline
