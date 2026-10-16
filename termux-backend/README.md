# Termux Local Backend — SmartKontrakt Foundry PoC

Small zero-dependency Node server that lets the Vercel app run a Foundry
exploit PoC against a fork of live chain state — on Jer's own phone.

## Why this exists

The Vercel app can never shell out to `forge` (serverless). This backend
runs under Termux on the S24, shells out to **your** forge binary, and the
app (same device, browser) fetches it at `http://127.0.0.1:8787`. Browsers
exempt loopback from mixed-content blocking, so the HTTPS app talking to
the `http://localhost` backend works. No Tailscale, no public exposure —
the server binds `127.0.0.1` **only**.

## Run it

```bash
# One-time setup (installs Node + Foundry if missing, fetches forge-std,
# then starts the server in the foreground):
bash scripts/termux-setup.sh

# Afterwards, just:
cd ~/SmartKontrakt && node termux-backend/server.mjs
```

Keep the Termux session alive while running PoCs:
`termux-wake-lock` in another session. `PORT=8787` (default) and
`ETH_RPC_URL` (default `https://eth.llamarpc.com`) are the only env knobs;
`FOUNDRY_DIR` overrides the scaffold location if you run from elsewhere.

If the prebuilt `forge` binary refuses to run under Termux, the setup
script prints the proot-distro Ubuntu fallback — run Foundry there instead.

## Endpoints

| Method | Path | Body / Response |
| --- | --- | --- |
| GET | `/health` | `{ ok, forge: bool, anvil: bool }` — best-effort `forge --version` / `anvil --version` |
| POST | `/run-poc` | `{ address, testCode, blockNumber?, rpcUrl? }` → `{ ok, passed, logs, durationMs, error? }` |
| OPTIONS | any | CORS preflight → 204 |

- `address` must be `0x` + 40 hex chars. `testCode` capped at 200KB.
- `blockNumber` (optional, non-negative int) pins the fork; omitted = latest.
- `rpcUrl` (optional) overrides `ETH_RPC_URL` / the public default for this run.
- `ok` = forge ran to completion; `passed` = exit code 0 (the PoC reproduced).
  A PoC that runs and fails is `ok: true, passed: false` — that failure is
  the signal, not a bug.
- `logs` = combined forge stdout+stderr, tail-capped at ~50KB (the summary
  is at the end).
- One run at a time: a second request while one is in flight gets
  `409 { error: "busy" }`.
- Validation failures → `400 { error }`. Forge missing / timeout → `500`.

## How a run works

1. `mkdtemp` under the OS temp dir; copy `foundry/foundry.toml` (+ `src/`,
   `lib/` when present) in; write `testCode` to `test/PoC.t.sol`.
   If `lib/forge-std` is missing, the server tries
   `forge install foundry-rs/forge-std` once in the temp project.
2. Run `forge test --fork-url <RPC> [--fork-block-number <n>]
   --match-contract PoC -vvv` with a 120s timeout (SIGKILL on expiry).
   Forge's built-in `--fork-url` **is** the live-net sandbox (in-memory
   fork) — no anvil process is managed.
3. Env for the test: `POC_TARGET=<address>`,
   `POC_FORK_BLOCK=<block or 0>`, `POC_RPC_URL=<rpc>`, plus `ETH_RPC_URL`
   (resolves the `mainnet` alias in `foundry.toml`). Generated tests must
   declare `contract PoC` (see `foundry/test/PoC.t.sol` template).
4. Temp dir is always removed afterwards.

## Safety properties

- **Fork-only.** `forge test --fork-url` executes against a local copy of
  chain state. Nothing is broadcast, nothing is spent, no private key is
  ever needed, accepted, or used. There is no `--broadcast` path.
- **No `--ffi`, ever.** The server never passes it, and the scaffold's
  `foundry.toml` sets `ffi = false`, so test code cannot shell out from
  inside the EVM.
- **Scrubbed child env.** The forge child gets only PATH/HOME/TMPDIR +
  the POC_* vars + the RPC URL. A test's `vm.envOr` can never read the
  parent process's secrets.
- **Filesystem.** `foundry.toml` grants tests read-only access to the temp
  project dir only — nothing sensitive lives there.
- **Loopback-only bind.** `127.0.0.1:8787`. Nothing on the LAN or internet
  can reach it. CORS `*` is fine for a localhost-only backend.
- **Bounds.** 200KB test code, 1MB request body, 120s run timeout,
  one-run-at-a-time, 50KB log cap.

## Troubleshooting

- **"Backend not reachable"** in the app → the server isn't running.
  Start it (above), keep the Termux session open, and confirm
  `curl http://127.0.0.1:8787/health` answers.
- **`409 busy`** → a PoC is already running. Wait for it (max 120s) and retry.
- **`forge failed to start`** → Foundry isn't installed or not on PATH.
  Re-run `bash scripts/termux-setup.sh`.
- **`forge-std is missing`** → run `forge install foundry-rs/forge-std`
  once inside `foundry/`, then retry.
- **Runs die midway** → Android killed Termux. Run `termux-wake-lock`,
  and keep Termux in the foreground (or at least not swiped away).
- **RPC rate limits** → set `ETH_RPC_URL` to your own node (Alchemy /
  Infura / local) before starting the server, or pass `rpcUrl` per run.
