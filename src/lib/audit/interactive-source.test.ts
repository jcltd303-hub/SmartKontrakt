import assert from "node:assert/strict";
import { test } from "node:test";
import {
  applyInteractiveEdit,
  applyInteractiveLoadError,
  applyWorkbenchPrefill,
  beginInteractiveLoad,
  initialInteractiveSource,
  interactiveBoxMismatch,
  settleInteractiveLoad,
  INTERACTIVE_SAMPLE_CODE,
  type InteractiveSourceState,
} from "./interactive-source.ts";

const ADDR_A = "0x1111111111111111111111111111111111111111";
const ADDR_B = "0x2222222222222222222222222222222222222222";
const SOURCE_A = "// SPDX-License-Identifier: MIT\ncontract A {}\n";
const SOURCE_B = "// SPDX-License-Identifier: MIT\ncontract B {}\n";

/** Run the load sequence exactly as the workbench controller does. */
async function runLoad(
  state: InteractiveSourceState,
  address: string,
  fetcher: (address: string) => Promise<{ rawBody: string; inputKind: "source" | "bytecode" }>,
): Promise<InteractiveSourceState> {
  let next = beginInteractiveLoad(state);
  try {
    const res = await fetcher(address);
    next = settleInteractiveLoad(next, address, res);
  } catch (err) {
    next = applyInteractiveLoadError(next, err instanceof Error ? err.message : String(err));
  }
  return next;
}

test("initial state is the pristine starter sample", () => {
  const s = initialInteractiveSource();
  assert.equal(s.code, INTERACTIVE_SAMPLE_CODE);
  assert.equal(s.codeForAddress, null);
  assert.equal(s.edited, false);
  assert.equal(s.status, "idle");
});

test("prefill on switch fills a pristine box from the workbench's held source — no fetch involved", () => {
  const s = applyWorkbenchPrefill(initialInteractiveSource(), {
    address: ADDR_A,
    heldBody: SOURCE_A,
    heldBodyIsBytecode: false,
  });
  assert.equal(s.code, SOURCE_A);
  assert.equal(s.codeForAddress, ADDR_A);
  assert.equal(s.edited, false);
  assert.equal(s.status, "loaded");
  assert.equal(s.notice, null);
});

test("prefill does nothing without a valid selected address or without a held body", () => {
  const init = initialInteractiveSource();
  assert.equal(
    applyWorkbenchPrefill(init, { address: "", heldBody: SOURCE_A, heldBodyIsBytecode: false }),
    init,
  );
  assert.equal(
    applyWorkbenchPrefill(init, { address: "not-an-address", heldBody: SOURCE_A, heldBodyIsBytecode: false }),
    init,
  );
  // The workbench holds nothing FOR this address (typed but never fetched):
  // the sample must not be dressed up as the contract's source.
  assert.equal(
    applyWorkbenchPrefill(init, { address: ADDR_A, heldBody: null, heldBodyIsBytecode: false }),
    init,
  );
});

test("prefill never overwrites an edited box", () => {
  const edited = applyInteractiveEdit(initialInteractiveSource(), "// my own experiment\n");
  const after = applyWorkbenchPrefill(edited, {
    address: ADDR_A,
    heldBody: SOURCE_A,
    heldBodyIsBytecode: false,
  });
  assert.equal(after, edited);
  assert.equal(after.code, "// my own experiment\n");
});

test("prefill does not silently retarget a box holding another address's untouched load", () => {
  const loaded = settleInteractiveLoad(initialInteractiveSource(), ADDR_A, {
    rawBody: SOURCE_A,
    inputKind: "source",
  });
  const after = applyWorkbenchPrefill(loaded, {
    address: ADDR_B,
    heldBody: SOURCE_B,
    heldBodyIsBytecode: false,
  });
  assert.equal(after, loaded);
  // …but re-entering with the SAME address refreshes from the held body.
  const refreshed = applyWorkbenchPrefill(loaded, {
    address: ADDR_A,
    heldBody: `${SOURCE_A}// newer fetch\n`,
    heldBodyIsBytecode: false,
  });
  assert.equal(refreshed.code, `${SOURCE_A}// newer fetch\n`);
  assert.equal(refreshed.codeForAddress, ADDR_A);
});

test("prefill with a bytecode body leaves the box paste-ready and explains why", () => {
  const s = applyWorkbenchPrefill(initialInteractiveSource(), {
    address: ADDR_A,
    heldBody: "0x6080604052",
    heldBodyIsBytecode: true,
  });
  assert.equal(s.code, INTERACTIVE_SAMPLE_CODE);
  assert.equal(s.codeForAddress, null);
  assert.match(s.notice ?? "", /runtime bytecode/);
  assert.match(s.notice ?? "", new RegExp(ADDR_A));
});

test("load by address fills the box with the fetched source (fetcher mocked)", async () => {
  const seen: string[] = [];
  const s = await runLoad(initialInteractiveSource(), ADDR_A, async (address) => {
    seen.push(address);
    return { rawBody: SOURCE_A, inputKind: "source" };
  });
  assert.deepEqual(seen, [ADDR_A]);
  assert.equal(s.code, SOURCE_A);
  assert.equal(s.codeForAddress, ADDR_A);
  assert.equal(s.status, "loaded");
  assert.equal(s.edited, false);
});

test("an explicit load replaces even an edited box — protection is only against the automatic prefill", async () => {
  const edited = applyInteractiveEdit(initialInteractiveSource(), "// work in progress\n");
  const s = await runLoad(edited, ADDR_B, async () => ({ rawBody: SOURCE_B, inputKind: "source" }));
  assert.equal(s.code, SOURCE_B);
  assert.equal(s.codeForAddress, ADDR_B);
  assert.equal(s.edited, false);
});

test("bytecode-only load shows the honest notice and leaves the box usable for paste", async () => {
  const before = initialInteractiveSource();
  const s = await runLoad(before, ADDR_A, async () => ({ rawBody: "0x6080604052", inputKind: "bytecode" }));
  assert.equal(s.status, "bytecode-only");
  assert.equal(s.code, before.code);
  assert.equal(s.codeForAddress, null);
  assert.match(s.notice ?? "", /No verified source/);
  // Paste flow is untouched by the notice: typing still just edits.
  const pasted = applyInteractiveEdit(s, "// pasted source\n");
  assert.equal(pasted.code, "// pasted source\n");
  assert.equal(pasted.edited, true);
});

test("a failed load surfaces the error and keeps the box content", async () => {
  const s = await runLoad(initialInteractiveSource(), ADDR_A, async () => {
    throw new Error("Sourcify unreachable");
  });
  assert.equal(s.status, "error");
  assert.equal(s.error, "Sourcify unreachable");
  assert.equal(s.code, INTERACTIVE_SAMPLE_CODE);
});

test("begin load marks loading and clears stale error/notice", () => {
  const errored = applyInteractiveLoadError(initialInteractiveSource(), "boom");
  const loading = beginInteractiveLoad(errored);
  assert.equal(loading.status, "loading");
  assert.equal(loading.error, null);
  assert.equal(loading.notice, null);
});

test("editing marks the box edited only on a real change, and keeps load provenance", () => {
  const loaded = settleInteractiveLoad(initialInteractiveSource(), ADDR_A, {
    rawBody: SOURCE_A,
    inputKind: "source",
  });
  assert.equal(applyInteractiveEdit(loaded, SOURCE_A), loaded);
  const edited = applyInteractiveEdit(loaded, `${SOURCE_A}// tweak\n`);
  assert.equal(edited.edited, true);
  assert.equal(edited.codeForAddress, ADDR_A);
});

test("mismatch notice names both addresses only when the box disagrees with the selection", () => {
  const loaded = settleInteractiveLoad(initialInteractiveSource(), ADDR_A, {
    rawBody: SOURCE_A,
    inputKind: "source",
  });
  assert.equal(interactiveBoxMismatch(loaded, ADDR_A), null);
  assert.equal(interactiveBoxMismatch(loaded, ADDR_A.toUpperCase().replace("0X", "0x")), null);
  assert.equal(interactiveBoxMismatch(initialInteractiveSource(), ADDR_B), null);
  const msg = interactiveBoxMismatch(loaded, ADDR_B);
  assert.match(msg ?? "", new RegExp(ADDR_A));
  assert.match(msg ?? "", new RegExp(ADDR_B));
});
