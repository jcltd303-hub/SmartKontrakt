# PoC fixtures — ground truth for the fallback library

`foundry/poc-fallbacks/` ships **tailored pattern harnesses** that run against
arbitrary deployed targets. This directory is the other half: **verbatim,
modernized ports of specific SmartBugs Curated contracts**, each paired with the
harness that must reproduce the known bug.

Why both. A verbatim port alone cannot run against a stranger's target — wrong
ABI, wrong storage layout — so it proves nothing about the target. A pattern
alone cannot be *shown* to work: you cannot tell a harness that reproduces a bug
from one that silently passes. Together they give a measurable claim: the fixture
proves the pattern reproduces a **known** vulnerability, and the pattern is what
scales to real targets. This is also how the literature measures itself —
SmartPoC reports confirmation precision/recall on the SmartBugs-Vul and
FORGE-Vul benchmarks, and PoPoC keeps manually verified, containerized
reproductions for the same reason.

## The precision half

Every fixture is **differential**. The same attack is run twice: against the
vulnerable port (it must reproduce) and against a fixed variant with the
standard remediation applied (it must **not** reproduce). A harness that fires on
patched code is a false positive — worse than a miss, because it burns trust and
time. `test_fixtureDoesNotReproduceOnFixedContract` is that check.

## Provenance

Each vulnerable contract carries a header recording the dataset path, the
upstream source, the original pragma, and the original vulnerable line — and
states exactly which edits were made. For a 0.4/0.5 contract those edits are the
0.8 migration only (`call.value(x)()` → `call{value: x}("")`, explicit
visibility); **the vulnerable ordering is preserved verbatim**, because that
ordering *is* the bug.

## Running

```sh
npm run check:fixtures     # requires forge on PATH
```

## Adding a fixture

1. Copy the dataset contract from `smartbugs/smartbugs-curated` into `src/`,
   rename it, and migrate it to `^0.8.24` — nothing else.
2. Add a fixed variant with the standard remediation.
3. Add `test/<Name>.t.sol` with both halves: reproduce on the port, and prove it
   does **not** reproduce on the fixed variant.
4. Record it in the template's `provenance` in `foundry/poc-fallbacks/index.json`.
