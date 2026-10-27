# The four deferred classes, implemented

`docs/recent-exploits-2026.md` listed four mechanisms as deliberately not
implemented, on the grounds that a pattern match on each fires on correct code.
That was right about the pattern match. Each of the four has an **invariant** a
correct implementation must satisfy, and the rule checks the invariant instead:

| Class | Incident | Invariant the rule checks |
| --- | --- | --- |
| `share-accounting-double-debit` | UNCX Vesting V2 (~$88k), Hedgey ($45M) | a share field that debits a global total is cleared when it is debited |
| `shared-unlock-delta-netting` | GoldPesa ($115k) | a callback that takes **and** settles first verifies the outstanding delta is settled |
| `idle-gap-interest-accrual` | BiFi (~165,574 USDT) | an accrual measuring elapsed blocks advances its checkpoint on the same path |
| `signature-field-omission` | GiddyDeFi ($1.3M) | every parameter that steers value is inside the signed digest |

Each has a positive fixture, a **control fixture that must stay quiet**, and a
Foundry harness (59–62). The control is the important half: the earlier decision
to defer these was about false positives, so the test that proves the fix
implements the invariant is the one that shows a *correct* contract does not
fire.

## What each rule actually keys on

**share-accounting-double-debit** collects `total -= <expr>` sites where `total`
looks global and `<expr>` reads a per-position field, groups them by field, and
fires only when two different functions debit the same field and no function
assigns that field to zero. Clearing the position is the fix, so clearing it is
the exemption.

**shared-unlock-delta-netting** requires the callback to both take
(`take`/`burn`/`mint`) and settle (`settle`/`settleFor`/`sync`) with no
`require`/revert mentioning a delta, settled amount, or outstanding debt.

**idle-gap-interest-accrual** finds `elapsed = block.number - checkpoint`,
followed by a multiplication by `elapsed` (or by the checkpoint itself), and
fires when the checkpoint is not assigned at statement level — a conditional
assignment, or none at all, is the bug.

**signature-field-omission** reads the digest span with the same paren-depth
helper the randomness rules use (so nested `abi.encode` calls are measured
correctly), then fires when a non-signature parameter that steers value is
absent from that span and is used to move value.

## Also fixed here

`bridge-message-auth` reported an ECDSA `claim(to, amount, v, r, s)` as an
*unverified* bridge handler, because its verification vocabulary looked for the
word "signature" and the parameters were `v`/`r`/`s`. A recovered signer is
verification of the message; the real defect in that shape is the omitted field,
which `signature-field-omission` now covers. The vocabulary includes
`ecrecover`/`recover(`.

## Measured

The SmartBugs benchmark is **unchanged** — 1014 findings, 7.091 per contract, no
per-category movement. That is expected and worth stating: the corpus is
2018-era, and these are 2026 classes. It also means the four rules cost nothing
in measured noise, but it does **not** mean they are well calibrated — the only
evidence they work is the fixture pairs and the harnesses. A corpus with 2026-era
contracts is the missing instrument.

Baseline `2026-10-27.8`. Suite: `deferred-classes.test.ts` (9 cases, positive +
control per class), whole suite green apart from the pre-existing sandbox-only
failures (ONNX out-of-memory, missing optional dependencies).
