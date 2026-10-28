import test from "node:test";
import assert from "node:assert/strict";

import { codeDuplication, codeHashOf, findSiblingScan } from "./code-reuse.server.ts";

/**
 * Identical runtime code is analysed once (2026-10-28).
 *
 * 543 findings across 393 contract-instances in one census: `execTransaction` on 27
 * contracts (27 Safe proxies, one implementation), `fallback ignores the delegatecall
 * result` on 59. Deployments, not distinct code.
 */

test("the hash is stable, case-insensitive and 0x-prefixed", () => {
  const code = "0x6080604052";
  const a = codeHashOf(code);
  assert.match(a!, /^0x[0-9a-f]{64}$/);
  assert.equal(codeHashOf("0x6080604052"), a);
  assert.equal(codeHashOf("0x6080604052".toUpperCase().replace("0X", "0x")), a);
  assert.equal(codeHashOf("6080604052"), a, "a bare hex body hashes the same");
});

test("no code means no hash — an EOA must never look dedupeable", () => {
  assert.equal(codeHashOf(null), null);
  assert.equal(codeHashOf(undefined), null);
  assert.equal(codeHashOf(""), null);
  assert.equal(codeHashOf("0x"), null);
  assert.equal(codeHashOf("0x0000000000"), null, "a zero-code read is not code");
});

test("different code hashes differently", () => {
  assert.notEqual(codeHashOf("0x6080604052"), codeHashOf("0x6080604053"));
});

test("a sibling lookup returns the stored body, excluding the address being scanned", async () => {
  const seen: unknown[] = [];
  const sql = (async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.join("?").replace(/\s+/g, " ").trim();
    seen.push({ text, values });
    return [
      { id: "scan-1", target_address: "0xaaa", contract_name: "Safe", body: "0x6080" },
    ];
  }) as unknown as Parameters<typeof findSiblingScan>[0];

  const sib = await findSiblingScan(sql, "ethereum", "0xdeadbeef", "0xbbb");
  assert.equal(sib?.scanId, "scan-1");
  assert.equal(sib?.body, "0x6080", "the body comes back so no fetch is needed");
  assert.equal(sib?.address, "0xaaa");

  const q = seen[0] as { text: string; values: unknown[] };
  assert.match(q.text, /from contract_scans/);
  assert.match(q.text, /code_hash = \?/);
  assert.match(q.text, /is distinct from \?/, "the address being scanned is excluded");
  assert.deepEqual(q.values, ["ethereum", "0xdeadbeef", "0xbbb"]);
});

test("no sibling means null, not an empty object", async () => {
  const sql = (async () => []) as unknown as Parameters<typeof findSiblingScan>[0];
  assert.equal(await findSiblingScan(sql, "ethereum", "0xdeadbeef", "0xbbb"), null);
});

test("the duplication ratio divides hashed rows by distinct code", async () => {
  const sql = (async () => [{ scans: "543", hashed: "393", distinct_code: "51" }]) as unknown as Parameters<
    typeof codeDuplication
  >[0];
  const d = await codeDuplication(sql);
  assert.deepEqual(d, { scans: 543, hashed: 393, distinctCode: 51, copiesPerCode: 7.71 });
});

test("an empty archive reports zero rather than dividing by zero", async () => {
  const sql = (async () => [{ scans: "0", hashed: "0", distinct_code: "0" }]) as unknown as Parameters<
    typeof codeDuplication
  >[0];
  assert.deepEqual(await codeDuplication(sql), { scans: 0, hashed: 0, distinctCode: 0, copiesPerCode: 0 });
});
