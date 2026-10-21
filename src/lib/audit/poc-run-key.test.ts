import test from "node:test";
import assert from "node:assert/strict";
import { pocRunKey } from "./poc-run-key.ts";

test("the same proof for the same finding yields the same run key", () => {
  const a = pocRunKey("scan:0", "contract PoC { function test_exploit() public {} }");
  const b = pocRunKey("scan:0", "contract PoC { function test_exploit() public {} }");
  assert.equal(a.id, b.id);
  assert.equal(a.digest, b.digest);
});

test("a different proof, or a different finding, is a different run", () => {
  const base = pocRunKey("scan:0", "code A");
  assert.notEqual(pocRunKey("scan:0", "code B").id, base.id);
  assert.notEqual(pocRunKey("scan:1", "code A").id, base.id);
});

test("the digest is a sha3-256 hex string and the id is namespaced", () => {
  const { id, digest } = pocRunKey("scan:0", "code");
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.ok(id.startsWith("poc:scan:0:"));
});
