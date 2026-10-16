# Foundry Fork PoC — SmartKontrakt

Runnable exploit harness. The web app's AI tab **generates** a Foundry test
suite; this project is where that test actually **runs** — against a fork of
live chain state, on your own machine. Nothing here runs on Vercel.

## Layout

- `foundry.toml` — Foundry config. Optimizer off (PoC clarity), `ffi` off
  (tests must never shell out), `[rpc_endpoints] mainnet` from `ETH_RPC_URL`.
- `test/PoC.t.sol` — reference exploit harness (TEMPLATE). Forks from
  `POC_RPC_URL` (default `mainnet` alias) at `POC_FORK_BLOCK` (0 = latest),
  targets `POC_TARGET`. Contains:
  - `test_forkSanity` — harness self-check (target has code at this fork).
  - `test_exploitTemplate` — reentrancy-drain example. Replace with the
    real exploit flow from the AI-generated PoC for the finding under audit.
- `src/` — empty. Add helper contracts here if an exploit needs them.

## Quick start

```bash
# 1. Install Foundry (once)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# 2. Fetch the only dependency (forge-std)
cd foundry
forge install foundry-rs/forge-std

# 3. Run the PoC against a local anvil fork (recommended)
export ETH_RPC_URL="https://eth.llamarpc.com"   # or your own node
cd ..
./scripts/run-fork-poc.sh 0x<target-address> [test/PoC.t.sol] [block-number]
```

Direct Foundry run (no anvil — forge forks the RPC itself):

```bash
cd foundry
POC_TARGET=0x... POC_FORK_BLOCK=0 forge test --fork-url "$ETH_RPC_URL" -vvv
```

## Env vars

| Var | Purpose | Default |
| --- | --- | --- |
| `ETH_RPC_URL` | Upstream RPC that anvil / forge forks from | `https://eth.llamarpc.com` (same public mainnet endpoint the app uses) |
| `POC_TARGET` | Contract under audit (`0x...`) | _(required)_ |
| `POC_FORK_BLOCK` | Pin the fork block for reproducibility | `0` = latest |
| `POC_RPC_URL` | RPC the test itself forks from | `mainnet` (the `foundry.toml` alias) |
| `POC_ANVIL_PORT` | Port for the script's anvil sandbox | `8545` |

## Reading results

- `test_forkSanity` passes → harness + fork + target are wired correctly.
- Exploit test passes → the exploit reproduced on fork state.
- Exploit test fails → exploit did **not** reproduce (guarded target, wrong
  interface, or fork block moved state). That failure is the signal, not a
  harness bug.

## Safety

Fork-only. `anvil --fork-url` and `forge test --fork-url` execute against a
local copy of chain state — nothing is broadcast, nothing is spent, no
private key is ever needed or accepted. Never point this at a live `--broadcast`
run; the harness has no broadcast path.
