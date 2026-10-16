# Foundry Fork PoC — SmartKontrakt

The app's AI tab **generates** a Foundry exploit test suite. This is the
missing second half: actually **running** that test against a fork of live
chain state.

## What it is

- `foundry/` — runnable Foundry project. `test/PoC.t.sol` is the reference
  exploit harness (template): forks from `POC_RPC_URL`, targets `POC_TARGET`,
  includes a fork sanity check + a reentrancy-drain example to adapt per
  finding.
- `scripts/run-fork-poc.sh` — one-command runner: starts a local `anvil`
  fork sandbox, runs `forge test` against it, kills anvil on exit.
- `src/components/foundry-export.tsx` — in-app export (AI tab). Downloads
  the generated test + a README with the exact fork-run commands. Client-side
  only, no server call.
- `foundry/README.md` — full harness docs (env vars, reading results).

## How to run it

```bash
# Install Foundry (once)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Fetch the only dependency
cd foundry && forge install foundry-rs/forge-std && cd ..

# Run the PoC (local anvil fork — recommended)
export ETH_RPC_URL="https://eth.llamarpc.com"   # or your own node
./scripts/run-fork-poc.sh 0x<target-address> [test/PoC.t.sol] [fork-block-number]
```

Or export from the app: Workbench → AI tab → **Download Exploit.t.sol** +
**Download PoC README**, then run the README's commands.

## What runs where

| Piece | Where it runs |
| --- | --- |
| AI test generation (OpenRouter) | Vercel server route (existing) |
| PoC export (download test + README) | Browser, client-side only |
| `forge test` / `anvil` | **Your machine only — never Vercel** |

Vercel serverless cannot run `forge`/`anvil` binaries, and shelling out
to them from a server route is not viable there. That is a platform
constraint, not a gap in this deliverable: the harness is local by design,
and the export is the bridge between the deployed app and the local run.

## Safety properties

- **Fork-only.** `anvil --fork-url` and `forge test --fork-url` execute
  against a local copy of chain state. Nothing is broadcast, nothing is
  spent.
- **No private keys.** The harness never asks for, accepts, or uses one.
  There is no `--broadcast` path anywhere in the project or script.
- **No secrets.** The only env var is `ETH_RPC_URL` (a public read-only
  endpoint by default). No API keys in the repo.
- **Sandbox hygiene.** The runner refuses to start if something already
  listens on the sandbox port, waits for anvil to answer before testing,
  and kills anvil on exit (trap on EXIT/INT/TERM).
- **No new dependencies, no behavior changes.** `forge-std` is the only
  Foundry dep (fetched by `forge install`, gitignored). No app routes, no
  server changes, no edits to existing files — `foundry-export.tsx` is
  additive with a wiring note.

## Verification status

- Shell script passes `bash -n`; TSX passes esbuild syntax check.
- `PoC.t.sol` was hand-reviewed for compile-plausibility (Solidity
  ^0.8.24, forge-std imports, all identifiers defined). One real bug was
  caught in review: profit must be measured on the attacker *contract*
  (it makes the calls), not the funding EOA — fixed.
- **Not verified:** an actual `forge test` run (`forge`/`anvil` are not
  installed in this environment). First run on a machine with Foundry
  installed is the proof: `test_forkSanity` should pass against any
  live target; `test_exploitTemplate` passes only on a genuinely
  reentrancy-vulnerable vault.
