#!/usr/bin/env bash
# SmartKontrakt Termux backend setup — run once, then start the server.
#   bash scripts/termux-setup.sh
# The script installs Node + Foundry if missing, fetches forge-std, and
# starts the local backend (foreground — keep this Termux session open).
set -euo pipefail

# --- Node (the backend is zero-dependency stdlib only) ---
if ! command -v node >/dev/null 2>&1; then
  echo "Installing nodejs via pkg..."
  pkg update -y && pkg install -y nodejs
fi

# --- Foundry ---
export PATH="$HOME/.foundry/bin:$PATH"
if ! command -v forge >/dev/null 2>&1; then
  echo "Installing Foundry via foundryup..."
  curl -L https://foundry.paradigm.xyz | bash
  # foundryup is a glibc binary; on Termux it may fail to exec ("required file
  # not found" = missing loader, not missing file). Don't let set -e kill the
  # script here — fall through to the forge check below, which prints the
  # proot fallback.
  "$HOME/.foundry/bin/foundryup" || true
fi

# The prebuilt Foundry binary sometimes refuses to run under Termux
# (exec format / missing loader). Fallback: run it under proot Ubuntu.
if ! forge --version >/dev/null 2>&1; then
  cat <<'EOF'
forge does not run under Termux on this device. Fallback: proot Ubuntu.
proot shares the phone's network, so the browser still reaches 127.0.0.1:8787.
  pkg install -y proot-distro
  proot-distro install ubuntu
  proot-distro login ubuntu -- bash -c "apt update && apt install -y git nodejs curl && git clone https://github.com/jcltd303-hub/SmartKontrakt.git && cd SmartKontrakt && bash scripts/termux-setup.sh"
Inside Ubuntu the same script finishes (glibc present) and starts the server.
EOF
  exit 1
fi

# --- Repo + deps ---
cd "$(dirname "$0")/.."
if [ ! -d "foundry/lib/forge-std" ]; then
  (cd foundry && forge install foundry-rs/forge-std)
fi

# --- Start the backend ---
echo "Starting SmartKontrakt Foundry backend on http://127.0.0.1:8787 ..."
echo "Tip: run 'termux-wake-lock' in another session so Android doesn't kill the server mid-run."
echo "RPC: set ETH_RPC_URL to your own node, or the public default is used."
# PublicNode first — eth.llamarpc.com is dead (HTTP 525). The backend
# rotates providers on failure anyway, but start on a working one.
ETH_RPC_URL="${ETH_RPC_URL:-https://ethereum.publicnode.com}" node termux-backend/server.mjs
