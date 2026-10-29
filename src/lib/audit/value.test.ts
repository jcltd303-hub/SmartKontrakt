import test from "node:test";
import assert from "node:assert/strict";
import { BoundedCache, tokenAmount, usdValue, formatUsd, totalUsdOf, isZeroValue, type AddressValue, type TokenHolding, isImplausibleHolding } from "./value.ts";

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


test("BoundedCache stays bounded by entry count (the leak that OOM'd the worker)", () => {
  const c = new BoundedCache<number>(3, 1_000_000, () => 10);
  for (let i = 0; i < 10; i++) c.set(`k${i}`, i);
  assert.equal(c.size, 3, "cache must not grow with the run");
  assert.equal(c.get("k0"), undefined, "oldest entry evicted");
  assert.equal(c.get("k9"), 9, "newest entry kept");
});

test("BoundedCache stays bounded by retained bytes", () => {
  const c = new BoundedCache<string>(100, 100, (v) => v.length);
  c.set("a", "x".repeat(60));
  c.set("b", "y".repeat(60));
  assert.ok(c.bytes <= 100, `retained bytes ${c.bytes} exceeded the budget`);
  assert.equal(c.size, 1);
});

test("BoundedCache refuses a value larger than the whole budget", () => {
  const c = new BoundedCache<string>(10, 100, (v) => v.length);
  c.set("big", "z".repeat(500));
  assert.equal(c.size, 0);
  assert.equal(c.get("big"), undefined);
});

test("BoundedCache.get refreshes recency, so hot entries survive", () => {
  const c = new BoundedCache<number>(2, 1_000_000, () => 1);
  c.set("a", 1);
  c.set("b", 2);
  assert.equal(c.get("a"), 1); // touch a so it is no longer the oldest
  c.set("c", 3);
  assert.equal(c.get("a"), 1, "recently used entry must survive");
  assert.equal(c.get("b"), undefined, "least recently used entry is evicted");
});

/**
 * Implausible holdings (2026-10-28).
 *
 * TheDAO 0xbf4ed7b2…a754 came back with `decimals: 1` where the token has 16, so the
 * amount was inflated by 10^15 and a 2.3e-14 price produced $26.7B — 99% of that
 * contract's totalUsd. With correct decimals it is worth $0.00003.
 */
test("the exact TheDAO row is rejected", () => {
  // raw 11456878859115020498998415, decimals read as 1, price 2.332824525832443e-14
  const amount = tokenAmount("11456878859115020498998415", 1);
  const value = usdValue(amount, 2.332824525832443e-14);
  assert.ok(amount > 1e24, `amount inflated to ${amount}`);
  assert.ok((value ?? 0) > 2.6e10, `value inflated to ${value}`);
  assert.equal(isImplausibleHolding(amount, value), true, "must be rejected");
});

test("with the correct 16 decimals the same holding is worth nothing", () => {
  const amount = tokenAmount("11456878859115020498998415", 16);
  const value = usdValue(amount, 2.332824525832443e-14);
  assert.ok(amount < 1e10, `amount ${amount}`);
  assert.ok((value ?? 1) < 0.01, `value ${value}`);
  assert.equal(isImplausibleHolding(amount, value), false, "a real token is kept");
});

test("ordinary holdings and real whales are not rejected", () => {
  assert.equal(isImplausibleHolding(1_145_687_885, 26.7), false, "a normal balance");
  assert.equal(isImplausibleHolding(2_234_886, 5.2e9), false, "WETH at 2.2M tokens, $5.2B");
  assert.equal(isImplausibleHolding(589_000_000_000_000, 5.8e6), false, "SHIB-scale supply");
  assert.equal(isImplausibleHolding(7112095738234, 1.04e5), false, "Pikaboss at 7.1e12 tokens");
});

test("beyond the whole-token bound, and beyond the value bound, is rejected", () => {
  assert.equal(isImplausibleHolding(1e19, 1), true, "more whole tokens than any token has");
  assert.equal(isImplausibleHolding(1e6, 2e10), true, "a $20B single holding");
  assert.equal(isImplausibleHolding(Number.NaN, 1), true, "NaN is not a holding");
  assert.equal(isImplausibleHolding(1e6, null), false, "unpriced stays unpriced, not rejected");
});
