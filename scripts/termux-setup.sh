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
  "$HOME/.foundry/bin/foundryup"
fi

# The prebuilt Foundry binary sometimes refuses to run under Termux
# (exec format / missing loader). Fallback: run it under proot Ubuntu.
if ! forge --version >/dev/null 2>&1; then
  cat <<'EOF'
forge does not run under Termux on this device. Fallback: proot Ubuntu.
  pkg install -y proot-distro
  proot-distro install ubuntu
  proot-distro login ubuntu
Inside Ubuntu, re-run this script (curl + foundryup work there), then start
the server the same way: node termux-backend/server.mjs
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
ETH_RPC_URL="${ETH_RPC_URL:-https://eth.llamarpc.com}" node termux-backend/server.mjs
