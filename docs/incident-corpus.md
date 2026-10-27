# The 2026-era incident corpus

The SmartBugs Curated benchmark is 2018-era. It cannot fire a Uniswap-v4 hook
rule, an EIP-7702 guard rule or a shared-unlock netting rule, because those
shapes did not exist when the dataset was built — so every class added after the
2026 work was asserted by fixtures and never *measured*.

This corpus is the instrument for them: **12 detectors, 24 cases** (one positive
and one control each), in `test/fixtures/incident-corpus/`, scored by
`scripts/benchmark-incidents.ts` and gated by `incident-benchmark.test.ts`.

| Number | Value | What it means |
| --- | --- | --- |
| Recall on positives | **100%** (12/12) | every rule fires on its own mechanism |
| Cross-talk | **0** | no rule fires on a fixture it was not expected or justified on |
| Controls with any finding | 9/12 | hygiene notes and allowlist-gated payouts, each justified below |

Cross-talk is the number worth trusting. Recall here only says "the rule fires
on the shape I encoded" — the positives were written by the same hand as the
rules, so a rule and its fixture can share a blind spot. Cross-talk is a
relation **between** rules on shapes written for other rules, which is a real
measurement.

## Tolerances are justified, not silent

24 co-firings are declared in the manifest's `tolerate` list, each with a
`tolerateWhy`. They fall into four kinds:

- **the fixture really does have that defect too** — the `lockAcquired` fixtures
  are simultaneously an unauthenticated hook callback and a delta-netting shape,
  and both statements are true;
- **an allowlist-gated payout** — `unprotected-ether` fires because `isAuthed`
  does not credit a mapping guard, while the reachability class marks the site
  `GATED_PRECONDITION`, so the nuance survives on the finding itself;
- **raw `ecrecover`** — `ecrecover-zero` and `signature-malleability` are
  separate true defects in the signature fixtures;
- **a real deadline or slippage bound** — `timestamp` and `zero-slippage-swap`
  are correct reports on fixtures that use them.

Hygiene and presence notes (`floating-pragma`, `old-compiler`, `missing-event`,
`eth-gas-stipend`, `locked-ether`, …) are excluded from cross-talk for the same
reason the SmartBugs benchmark excludes them from the category vote: they fire
on nearly every contract and say nothing about which mechanism a fixture shows.

## What building it caught

Two real bugs, both in rules I had written and both invisible to the fixture
tests that already existed:

1. **The pre-0.8 arithmetic gate never worked.** `versionFloor` is encoded
   `8024` for `0.8.24`, not `8_024_000`, so `versionFloor < 8_000_000` was
   always true and `unchecked-block` fired on modern code — where the compiler
   emits the overflow check and there is nothing to find. Every fixture in this
   corpus is `0.8.24` and was reported as unchecked arithmetic. The gate is now
   `< 8000`.
2. **`self-attested-auth` matched a payout.** Its span ran from `if (` past the
   condition into the block body, where `payable(msg.sender).transfer(...)`
   matched — a payout read as "the caller attested itself". The rule now requires
   the cast to be inside the condition and excludes `payable`/`address` casts.

Neither was caught by the SmartBugs benchmark, because it has no modern
contracts, and neither was caught by the per-rule fixtures, because a fixture
only tests the rule it was written for. That is the argument for this corpus
existing at all.

## Limits

- **Positives are reconstructions.** Recall means "the rule fires on the shape I
  encoded", not "the rule catches the incident". Fetching the deployed, patched
  source of the twelve contracts would be the next step up in fidelity.
- **Controls are reconstructions of the fix.** A control that fires is either a
  rule that does not implement its invariant, or a fixture whose fix is
  incomplete — this corpus cannot tell you which.
- **Twelve detectors, not sixty-four.** The rest are measured by SmartBugs or by
  the fixture-debt ratchet in `detection-quality.test.ts`; several have neither.
