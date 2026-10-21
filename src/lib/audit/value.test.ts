import test from "node:test";
import assert from "node:assert/strict";
import {
  tokenAmount,
  usdValue,
  formatUsd,
  totalUsdOf,
  isZeroValue,
  type AddressValue,
  type TokenHolding,
} from "./value.ts";

function holding(over: Partial<TokenHolding> = {}): TokenHolding {
  return {
    kind: "erc20", address: "0xabc", symbol: "TKN", name: null, decimals: 18,
    raw: "1000000000000000000", amount: 1, priceUsd: 1, valueUsd: 1, priceSource: "blockscout",
    ...over,
  };
}

function value(over: Partial<AddressValue> = {}): AddressValue {
  return {
    address: "0x1", chainId: 1, symbol: "ETH", nativeWei: "0", nativeUsd: 0, totalUsd: 0,
    holdings: [], priced: 0, unpriced: 0, sources: [], complete: true, notes: [], valuedAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}

test("tokenAmount scales raw units by decimals without losing the integer path", () => {
  assert.equal(tokenAmount("1000000000000000000", 18), 1);
  assert.equal(tokenAmount("1500000", 6), 1.5);
  assert.equal(tokenAmount("0", 18), 0);
  assert.equal(tokenAmount("not-a-number", 18), 0);
});

test("usdValue is null when the price is unknown, never 0", () => {
  assert.equal(usdValue(2, 1.5), 3);
  assert.equal(usdValue(2, null), null);
  assert.equal(usdValue(Number.NaN, 1), null);
  assert.equal(usdValue(2, Number.NaN), null);
});

test("formatUsd renders compact magnitudes", () => {
  assert.equal(formatUsd(0), "$0.00");
  assert.equal(formatUsd(1.5), "$1.50");
  assert.equal(formatUsd(1234), "$1.23k");
  assert.equal(formatUsd(2_500_000), "$2.50M");
  assert.equal(formatUsd(3_000_000_000), "$3.00B");
  assert.equal(formatUsd(null), null);
});

test("totalUsdOf sums priced holdings and ignores unpriced ones", () => {
  const total = totalUsdOf([holding({ valueUsd: 2 }), holding({ valueUsd: null }), holding({ valueUsd: 3 })]);
  assert.equal(total, 5);
});

test("isZeroValue only fires on a CONFIRMED, fully priced zero", () => {
  assert.equal(isZeroValue(value()), true);
  assert.equal(isZeroValue(value({ totalUsd: 0.01 })), false);
  // Incomplete valuation is unknown, not zero — the whole point of the flag.
  assert.equal(isZeroValue(value({ complete: false })), false);
  // An unpriced holding means the total is a floor, so never "zero".
  assert.equal(isZeroValue(value({ unpriced: 1 })), false);
  assert.equal(isZeroValue(null), false);
});
