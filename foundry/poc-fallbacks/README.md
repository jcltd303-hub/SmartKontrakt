# Fallback PoCs — `foundry/poc-fallbacks/`

One drop-in Foundry test per exploit scenario, for when the AI-generated PoC
is missing, fails to generate, or needs a second shape. Pick by finding:
`index.json` maps every Kiln detector id to its fallback file(s).

## Use

```bash
# 1. Pick the file for the finding (see index.json)
cp foundry/poc-fallbacks/01-reentrancy-classic.t.sol foundry/test/Exploit.t.sol

# 2. Adapt the TODO-marked constants / interfaces to the target's real ABI
#    (function names, token addresses, whale, proof, slot, ...)

# 3. Run against a fork — never mainnet, never --broadcast
export ETH_RPC_URL="https://ethereum.publicnode.com"
POC_TARGET=0x... ./scripts/run-fork-poc.sh 0x...
```

## Verification — what is actually proven

- **Compile + structure:** every template compiles (`npm run check:fallbacks`)
  and the generated module's selection invariants are unit-tested.
- **Vulnerability classes:** `npm run check:fixtures` proves each class
  reproduces on a known SmartBugs port and does not fire on its fixed variant —
  via bespoke per-port harnesses, **not** by executing these templates (it runs
  0 of the 47). See `foundry/poc-fixtures/README.md` for the precise claims and
  the open gap (templates executed unmodified against the ports is not wired).
- **Template execution:** the ai-poc-proof suite (`scripts/ai-poc-proof/`)
  dry-runs every template end-to-end against a purpose-built fixture per type,
  with TODO constants adapted per its manifest; individual templates also carry
  fork proofs where a header notes one (06, 46).

## Reading results

| Result | Meaning |
| --- | --- |
| `test_forkSanity` fails | Setup problem (RPC, address, fork block) — not the exploit. |
| Exploit test passes | Exploit **reproduced** on fork state. Real signal. |
| Exploit test fails | Exploit did **not** reproduce — guarded, wrong interface, or fork block moved state. Also a real signal. Do not "fix" the test to pass. |

## Shape (every file)

- `contract PoC is Test` — the name `run-fork-poc.sh` matches (`--match-contract PoC`).
- `setUp()` forks from `POC_RPC_URL` (`mainnet` alias), targets `POC_TARGET`,
  pins `POC_FORK_BLOCK` (0 = latest). Fails fast if `POC_TARGET` is unset.
- `test_forkSanity()` — fork live, target has code.
- `test_exploit()` (sometimes two tests) — the exploit flow. Every assertion
  measures OBSERVABLE state (balances, owner, shares, code) — a silent
  low-level call success never counts as proof on its own.

## Safety

- **Fork-only.** `anvil --fork-url` / `forge test --fork-url` run against a
  local copy of chain state. Nothing is broadcast, nothing is spent.
- **No private keys.** Tests never ask for, accept, or use one.
- **No secrets.** Only env vars are `POC_TARGET`, `POC_RPC_URL`,
  `POC_FORK_BLOCK`, `ETH_RPC_URL` (public read-only endpoint), and —
  for 46-token-rescue only — `POC_TOKEN` (the external token to judge;
  unset = the target as its own token). The app supplies `POC_TOKEN`
  from the scan's stored valuation when it knows the target's token
  holdings (see `externalTokenCandidate`), and `run-fork-poc.sh`
  passes it through when set.
- Tests that prank an owner / whale prove a CAPABILITY (centralization,
  approval abuse) — they do not spend anyone's funds.

## Notes that matter

- **Cancun / EIP-6780:** `selfdestruct` in a LATER transaction only moves
  the balance — it no longer deletes code. PoCs assert balance movement,
  not code deletion. The CREATE2 metamorphic PoC uses the same-tx factory
  path, the live post-Cancun variant; the classic multi-tx metamorphic is
  dead.
- **TODOs are real:** a fallback is a SHAPE, not a target-specific exploit.
  Function names, token addresses, proofs, slots, and whales must be adapted
  to the target's ABI. An unadapted fallback fails loudly (require with a
  message), never silently.
- **Not PoC-able (enforced by selection):** `missing-event`,
  `floating-pragma`, `old-compiler`, `rtl-override` have no on-chain
  exploit; the bytecode-shape signals `bytecode-metadata` and
  `bytecode-reentrancy-shape` are not standalone exploits; and the
  analyzer meta-findings `parse` and `report-cap` are not
  vulnerabilities at all. `selectPocFallbacks` returns NO template for
  these detectors (generated as `POC_NOT_POCABLE_DETECTORS` from
  `index.json`) — no SmartBugs-category fallback is borrowed for them,
  because a borrowed harness manufactures a verdict the finding never
  earned. (`default-visibility` and `bytecode-proxy` were previously
  listed here but DO have mechanism-correct harnesses — 07b and 11 —
  and are mapped to them instead.)
- **Fork dust:** a contract CREATE'd on a fork lands at a deterministic
  address that may already hold a mainnet balance (dust), which the new
  contract inherits. Assert `>=` the forced amount, never `==`, when a
  PoC creates contracts that forward value (see `12-selfdestruct`).
- Files live OUTSIDE `foundry/test/` so `forge test` never auto-runs them.
  Copy one into `test/Exploit.t.sol` to run it.
