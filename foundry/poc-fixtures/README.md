# PoC fixtures — ground truth for the fallback library

`foundry/poc-fallbacks/` ships **tailored pattern harnesses** that run against
arbitrary deployed targets. This directory is the other half: **verbatim,
modernized ports of specific SmartBugs Curated contracts**, each paired with the
harness that must reproduce the known bug.

Why both. A verbatim port alone cannot run against a stranger's target — wrong
ABI, wrong storage layout — so it proves nothing about the target. A pattern
alone cannot be *shown* to work: you cannot tell a harness that reproduces a bug
from one that silently passes. Together they give a measurable claim about the
vulnerability **class**: the fixture proves the class reproduces on a **known**
vulnerable contract (and does not fire on its fixed variant), and the pattern is
what scales to real targets. This is also how the literature measures itself —
SmartPoC reports confirmation precision/recall on the SmartBugs-Vul and
FORGE-Vul benchmarks, and PoPoC keeps manually verified, containerized
reproductions for the same reason.

**Precision about what is proven here.** The harness paired with each port is a
bespoke test written for that port — it is **not** the shipped fallback template
from `foundry/poc-fallbacks/`, and `check:fixtures` executes **0 of the 47
shipped templates**. What the shipped templates carry instead:

- compile + structural verification (`npm run check:fallbacks`, plus the
  generated-module unit tests);
- end-to-end execution against purpose-built per-type fixtures by the
  ai-poc-proof suite's dry run (`scripts/ai-poc-proof/`) — with the templates'
  TODO constants adapted per its manifest, exactly as a human would adapt them
  for a real target;
- individual fork proofs where noted in a template's header (e.g. 06 and 46
  against the FUUU field case).

**The gap.** Executing the shipped templates *unmodified* against these ports
is not wired. The ports' deployment setup (constructor args, funding, token and
whale provisioning) lives inside each bespoke harness's test code, not in a
machine-readable manifest the templates could be run from, and several
templates judge state a port does not provide (DEX pairs, whale balances,
external token holdings). Closing it takes: a per-template manifest mapping
each dataset-backed template to its port + setup steps + env (`POC_TARGET`,
`POC_TOKEN`, fork block), an anvil runner reusing the ai-poc-proof deployment
machinery, and a per-template pass over the results — the TODO-gated templates
would additionally need their manifest adaptations declared, and would be
reported as adapted runs, not unmodified ones.

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

## What's covered

Every SmartBugs-Curated contract that a fallback template claims to derive from
has a port here — enforced by `scripts/verify-poc-fixtures.test.mjs`, which fails
if a template's `provenance.sources` names a dataset contract with no port. As of
this writing that is 29 ports across all nine DASP classes: reentrancy (6),
access control (9), arithmetic (3), unchecked low-level calls (2), denial of
service (3), bad randomness (2), front running (2), time manipulation (1), short
addresses (1).

One further port is NOT a dataset port: `TokenRescue` (with
`TokenRescueFixed`), a modelled port of fallback template
`46-token-rescue.t.sol`, whose index.json provenance is "modelled" — no
SmartBugs contract exists for the unauthenticated-rescue pattern, so the
port declares itself modelled in its header (naming the template it
ports) rather than claiming a dataset path. The verifier accepts
exactly these two provenance kinds and rejects a port that claims
neither.

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
