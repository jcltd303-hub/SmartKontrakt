# LLM output contract

Four places where a model's reply used to become a **lie** instead of an
error. All four are fixed, and `llm-output-contract.test.ts` (17 cases) pins
them.

## 1. `as string` was not a check

```ts
threatModelReport: record.threatModelReport as string,   // ← the old line
```

The gate before it was truthiness, and an object is truthy. A reply of
`{"threatModelReport": {"executive": "…"}}` therefore passed validation, stayed
an **object**, and became `[object Object]` in three places: the stored
`ai_narrative`, the UI, and — worst — the *next* call's prompt, because
`buildAiReviewPrompt` interpolates the narrative as context for the code call.

Now `coerceModelText()` decides:

| Reply shape | Result |
| --- | --- |
| string | trimmed as-is |
| array of strings/numbers | joined with newlines, in order |
| object | its JSON text, so the content survives a wrong shape |
| number / boolean / null | `null` → `ReviewReplyError` |

The error now names the **type** as well as the keys
(`types: threatModelReport=number`), so a schema miss reads as a schema miss
rather than as an empty answer.

## 2. Unbounded prose was unbounded prompt growth

Nothing bounded the narrative. It is stored, rendered, and interpolated into
the code call's prompt — which is exactly the failure the two-call split was
built to fix on 2026-10-25 (the combined reply truncated at `max_tokens` with
the test code unborn).

- `NARRATIVE_MAX_CHARS = 24_000`, `ECONOMIC_MAX_CHARS = 4_000`: prose is
  truncated **with a visible marker** naming the original length, so a cut
  narrative says so instead of ending mid-sentence.
- `TEST_CODE_MAX_CHARS = 40_000`: code is **rejected**, never truncated — half
  a Solidity file is not a smaller Solidity file, it is a file that will not
  compile.

## 3. The analyzer claimed a review the model did not write

A missing `economicRiskSummary` was defaulted to *"Completed OpenRouter threat
review."* — a completion claim on an empty field. It is now
`ECONOMIC_SUMMARY_ABSENT`: *"The model did not provide an economic risk summary
for this contract."*

## 4. The code gate let uncompilable files through

`parseTestCodeReply` checked for a `Test` contract and an executable test, but
not for a pragma — so a fragment could reach the Foundry backend and spend a run
to discover it would not compile. A missing `pragma solidity` is now a named
problem, which routes the reply into the existing corrective retry.

## 5. The Deep Agent crashed on a schema miss

```ts
(parsed.hypotheses ?? []).filter(…)   // ← a string has no .filter
```

A reply of `{"hypotheses": "none"}` threw a `TypeError` and killed the search
round. The parsing is now a pure exported function, `parseProposalReply()`,
which returns "no hypotheses this round" for any non-array shape, drops
over-long generated code before it reaches the compiler, and is testable
without a network round.

## What this does not fix

The `ai-review-openrouter` and `deep-agent-round` suites still report one
file-level failure **in this sandbox**: `WebAssembly.instantiate(): Out of
memory` from the ONNX runtime's lazy ResNet load, fired after the tests finish.
That is the pod's 2 GB limit, not the LLM path — the same two files report the
same count before and after this change, and every individual test passes (39
and 6). It is worth watching in CI, where the limit is higher.
