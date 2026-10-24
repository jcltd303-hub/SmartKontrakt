import test from "node:test";
import assert from "node:assert/strict";
import { sha3_256 } from "js-sha3";
import { selectImageBytecode } from "./input.ts";

test("pasted runtime hex takes precedence over an old fetched association", () => {
  assert.equal(
    selectImageBytecode("0x6001600055", { code: "0x00", sourceHash: "old" }),
    "0x6001600055",
  );
});
test("fetched runtime is used only for the exact source it accompanied", () => {
  const body = "contract Test {}";
  const runtime = { code: "0x6001600055", sourceHash: sha3_256(body) };
  assert.equal(selectImageBytecode(body, runtime), runtime.code);
  assert.equal(selectImageBytecode(body + " // edited", runtime), body + " // edited");
  assert.equal(selectImageBytecode(body), body);
});
