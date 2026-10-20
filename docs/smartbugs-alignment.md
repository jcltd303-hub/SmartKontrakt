# SmartBugs-Curated alignment

The fallback PoC library is organised by the same taxonomy as
[**SmartBugs Curated**](https://github.com/smartbugs/smartbugs-curated) — the
reference dataset of annotated vulnerable Solidity contracts — so a finding's
detector maps to a dataset category and to a **working Foundry template**.

Three pieces keep them in sync:

| Piece | File | Role |
| --- | --- | --- |
| Taxonomy | `src/lib/audit/smartbugs.ts` | the ten DASP categories + `detector → category` |
| Library | `foundry/poc-fallbacks/*.t.sol` + `index.json` | one harness per scenario, each tagged with its category |
| Generated map | `src/lib/audit/poc-fallbacks.ts` | `POC_FALLBACK_BY_SMARTBUGS` (category → harness), emitted by `scripts/generate-poc-fallbacks-ts.mjs` |

`selectPocFallbacks` returns the detector-specific harness when one exists and
otherwise **falls back to the harness for the finding's category**, so a finding
always starts the model from a working template for the right vulnerability
class rather than an empty prompt.

## Coverage

Every one of the ten categories has at least one harness (enforced by
`scripts/verify-poc-fallbacks.test.mjs`).

| SmartBugs category | Harnesses | Detectors mapped |
|---|---|---|
| `reentrancy` | 5 | 3 — reentrancy, read-only-reentrancy, bytecode-reentrancy-shape |
| `access_control` | 10 | 15 — tx-origin, bytecode-origin, unprotected-admin, unprotected-ether, unprotected-initializer, default-visibility, delegatecall, bytecode-delegatecall, bytecode-proxy, assembly-sstore, assembly-param-sstore, extcodesize, centralization, shadowing, rtl-override |
| `arithmetic` | 2 | 2 — unchecked-block, div-before-mul |
| `unchecked_low_level_calls` | 3 | 6 — unchecked-call, bytecode-unchecked-call, erc20-unchecked, selfdestruct, bytecode-selfdestruct, token-drain |
| `denial_of_service` | 3 | 7 — strict-balance, eth-gas-stipend, hardcoded-gas, gas-estimator-dos, locked-ether, zero-address, msg-value-loop |
| `bad_randomness` | 1 | 1 — weak-randomness |
| `front_running` | 2 | 3 — slippage, zero-slippage-swap, front-running |
| `time_manipulation` | 1 | 2 — timestamp, bytecode-timestamp |
| `short_addresses` | 1 | 1 — short-address |
| `other` | 18 | 14 — balance-as-price, oracle-spot, encode-packed, signature-replay, signature-malleability, private-secret, fee-on-transfer, storage-gap, external-contract-referencing, bytecode-create2, bytecode-metadata, missing-event, floating-pragma, old-compiler |

54 detector ids in total map to a category.

## Adding a harness

1. Drop `NN-scenario.t.sol` in `foundry/poc-fallbacks/` following the existing
   shape: SPDX header, `pragma solidity ^0.8.24`, `import {Test, console} from
   "forge-std/Test.sol"`, `contract PoC is Test`, a `test_exploit()` that asserts
   the observable state change, and a `setUp()` that forks from
   `POC_TARGET` / `POC_RPC_URL` / `POC_FORK_BLOCK` (never a hardcoded target).
2. Add it to `index.json` with its `detectors`, `scenario`, and `smartbugs`
   category.
3. `npm run generate:fallbacks` to regenerate `poc-fallbacks.ts`.
4. `npm test` — the fallback test asserts structure, index↔disk agreement, and
   that every category stays covered.

## Verifying they actually compile

`npm test` does the fast structural + taxonomy checks. To compile every harness
against Foundry (one project per file, since each declares `contract PoC is
Test`):

```sh
npm run check:fallbacks   # requires `forge` on PATH
```

Each harness is fork-only: no `--broadcast`, no private keys, no real
transactions.
