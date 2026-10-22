import test from "node:test";
import assert from "node:assert/strict";
import { describeDbError } from "./db-error.ts";

/** A pg error carries `code`; a network error carries a Node errno. */
const pgError = (message: string, code?: string) => Object.assign(new Error(message), code ? { code } : {});

test("a rejected password is named as a credential problem, not a connectivity one", () => {
  // This is the message that cost several rounds: it reads like the host is
  // wrong, when the host is fine and the secret is stale.
  const out = describeDbError(
    pgError('password authentication failed for user "postgres"', "28P01"),
    { from: "POSTGRES_URL" },
  );
  assert.match(out, /rejected the password in the URL from POSTGRES_URL/);
  assert.match(out, /not a connectivity problem/);
  assert.match(out, /reset it in supabase/i);
  // The instruction must include the rotation duty, because this password was
  // once committed to a public repository.
  assert.match(out, /rotating it is required/);
});

test("the same message without a SQLSTATE is still classified", () => {
  const out = describeDbError(pgError('password authentication failed for user "postgres"'));
  assert.match(out, /rejected the password/);
});

test("the classified text never introduces a connection string", () => {
  const out = describeDbError(pgError('password authentication failed for user "postgres"', "28P01"), {
    from: "POSTGRES_URL",
  });
  assert.ok(!out.includes("://"), "the message must not carry a URL or a password");
  assert.ok(!out.includes("@"), "the message must not carry userinfo");
});

test("an unknown database is distinguished from a rejected password", () => {
  const out = describeDbError(pgError('database "postgres" does not exist', "3D000"), { from: "DATABASE_URL" });
  assert.match(out, /does not exist/);
  assert.ok(!/password/i.test(out), "a missing database must not be blamed on the password");
});

test("an unresolvable host points at the project reference", () => {
  const out = describeDbError(pgError("getaddrinfo ENOTFOUND db.abcdefg.supabase.co", "ENOTFOUND"), {
    from: "POSTGRES_URL_NON_POOLING",
  });
  assert.match(out, /could not be resolved/);
  assert.match(out, /project reference/);
});

test("a refusal or timeout explains the IPv6-only direct host", () => {
  for (const code of ["ECONNREFUSED", "ETIMEDOUT"]) {
    const out = describeDbError(pgError(`connect ${code} 2600:1f18::1:5432`, code), { from: "DATABASE_URL" });
    assert.match(out, /refused the connection or timed out/);
    assert.match(out, /IPv6/);
    assert.match(out, /pooler/);
  }
});

test("anything unrecognised is passed through unchanged", () => {
  assert.equal(describeDbError(pgError("relation \"findings\" does not exist", "42P01")), 'relation "findings" does not exist');
  assert.equal(describeDbError("a plain string failure"), "a plain string failure");
});

test("a missing context still produces a usable sentence", () => {
  const out = describeDbError(pgError("password authentication failed for user \"postgres\"", "28P01"));
  assert.match(out, /the connection URL/);
});
