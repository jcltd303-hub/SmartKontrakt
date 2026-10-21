import test from "node:test";
import assert from "node:assert/strict";
import {
  formatNative,
  weiFromHex,
  nativeSymbol,
  normalizeChainId,
  isZeroBalance,
  balanceLabel,
} from "./balance.ts";

test("formatNative renders wei as a short decimal string", () => {
  assert.equal(formatNative(0n), "0");
  assert.equal(formatNative(1n), "<0.000001"); // dust is never shown as zero
  assert.equal(formatNative(10n ** 18n), "1");
  assert.equal(formatNative(15n * 10n ** 17n), "1.5");
  assert.equal(formatNative(1234567890123456789n), "1.234567");
});

test("weiFromHex parses JSON-RPC quantities and rejects junk", () => {
  assert.equal(weiFromHex("0x0"), 0n);
  assert.equal(weiFromHex("0xde0b6b3a7640000"), 10n ** 18n);
  assert.equal(weiFromHex("0x"), null);
  assert.equal(weiFromHex("1"), null);
  assert.equal(weiFromHex(undefined), null);
  assert.equal(weiFromHex(42), null);
});

test("chain helpers map ids and names to the native symbol", () => {
  assert.equal(normalizeChainId("base"), 8453);
  assert.equal(normalizeChainId("bsc"), 56);
  assert.equal(normalizeChainId("137"), 137);
  assert.equal(normalizeChainId(undefined), 1);
  assert.equal(nativeSymbol(1), "ETH");
  assert.equal(nativeSymbol(137), "POL");
  assert.equal(nativeSymbol("bsc"), "BNB");
  assert.equal(nativeSymbol(999999), "ETH"); // unknown chain falls back
});

test("isZeroBalance is true only for a confirmed zero (null is unknown, not zero)", () => {
  assert.equal(isZeroBalance(null), false);
  assert.equal(isZeroBalance({ wei: 0n, formatted: "0", symbol: "ETH", rpcUrl: "x" }), true);
  assert.equal(isZeroBalance({ wei: 1n, formatted: "0.000000", symbol: "ETH", rpcUrl: "x" }), false);
});

test("balanceLabel formats a stored balance and tolerates null / malformed", () => {
  assert.equal(balanceLabel("0"), "0 ETH");
  assert.equal(balanceLabel("1000000000000000000"), "1 ETH");
  assert.equal(balanceLabel("1000000000000000000", "POL"), "1 POL");
  assert.equal(balanceLabel(null), null);
  assert.equal(balanceLabel(undefined), null);
  assert.equal(balanceLabel(""), null);
  assert.equal(balanceLabel("not-a-number"), null);
});
