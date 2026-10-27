import test from "node:test";
import assert from "node:assert/strict";

import {
  BLOCKSCOUT_HOSTS,
  blockscoutAddressUrl,
  blockscoutContractUrl,
  blockscoutHost,
  bytecodeAnalysedLabel,
  bytecodeAnalysedNote,
} from "./address-fetcher.ts";

/**
 * C1/C2 (2026-10-27 detection upgrade): the second registry and the
 * bytecode-analysed label. These are the pure parts of the fallback — the
 * network calls themselves are covered by the integration suite, which
 * needs live providers. What is pinned here is the contract that mattered:
 * one registry is not a verdict, and "no source" is never "no analysis".
 */

const ADDR = "0xAbC0000000000000000000000000000000000001";

test("C1: known chains have a Blockscout instance, unknown chains do not", () => {
  assert.equal(blockscoutHost(1), "https://eth.blockscout.com");
  assert.equal(blockscoutHost(8453), "https://base.blockscout.com");
  assert.equal(blockscoutHost(999999), null);
  assert.ok(Object.keys(BLOCKSCOUT_HOSTS).length >= 5);
});

test("C1: URLs are built against the v2 API, lowercased, and trailing slashes are safe", () => {
  assert.equal(
    blockscoutContractUrl("https://eth.blockscout.com/", ADDR),
    `https://eth.blockscout.com/api/v2/smart-contracts/${ADDR.toLowerCase()}`,
  );
  assert.equal(
    blockscoutAddressUrl("https://eth.blockscout.com", ADDR),
    `https://eth.blockscout.com/api/v2/addresses/${ADDR.toLowerCase()}`,
  );
});

test("C2: a bytecode-only audit is labelled analysed, never unreadable", () => {
  const label = bytecodeAnalysedLabel(ADDR, null);
  assert.match(label, /^Bytecode-analysed \(0xAbC0\.\.\.0001\)$/);
  assert.doesNotMatch(label.toLowerCase(), /unreadable|unknown|failed/);
});

test("C3: a registry name is shown as metadata, not as a verified label", () => {
  const identity = {
    name: "AdminUpgradeabilityProxy",
    isContract: true,
    isVerified: false,
    hasCreationBytecode: true,
    implementations: ["0x1111111111111111111111111111111111111111"],
    proxyType: "eip1967",
  };
  const label = bytecodeAnalysedLabel(ADDR, identity);
  assert.match(label, /AdminUpgradeabilityProxy/);

  const note = bytecodeAnalysedNote(identity);
  assert.match(note, /Sourcify, then Blockscout/);
  assert.match(note, /creation bytecode/);
  assert.match(note, /eip1967/);
  assert.match(note, /registry metadata, not a compiler-verified label/);
});

test("C2: the note always says what a bytecode audit covers", () => {
  const note = bytecodeAnalysedNote(null);
  assert.match(note, /runtime bytecode/);
  assert.match(note, /opcodes, selectors and proxy shape are ground truth/);
});
