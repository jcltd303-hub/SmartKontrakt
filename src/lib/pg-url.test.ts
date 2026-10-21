import assert from "node:assert/strict";
import test from "node:test";

import { encodePostgresCredentials, isPercentEncoded, looksLikePlaceholder } from "./pg-url.ts";

/**
 * A raw credential in a connection URL does not fail loudly — the URL silently
 * re-parses, so the connection errors confusingly or points somewhere
 * unintended. These are the shapes that actually occur.
 */
const CASES: [input: string, want: string, label: string][] = [
  ["postgresql://postgres:p@ss#word@db.x.supabase.co:5432/postgres", "postgresql://postgres:p%40ss%23word@db.x.supabase.co:5432/postgres", "raw @ and # in the password"],
  ["postgresql://postgres:p@ss#word@db.x.supabase.co:5432/postgres?sslmode=require", "postgresql://postgres:p%40ss%23word@db.x.supabase.co:5432/postgres?sslmode=require", "raw @ and # in the password, with a query"],
  ["postgresql://postgres:a@b@c@host:5432/db", "postgresql://postgres:a%40b%40c@host:5432/db", "several raw @ in the password"],
  ["postgresql://postgres:pa/ss@host/db", "postgresql://postgres:pa%2Fss@host/db", "raw / in the password"],
  ["postgresql://postgres:abc:def@host/db", "postgresql://postgres:abc%3Adef@host/db", "raw colon in the password"],
  ["postgresql://postgres:100%@host/db", "postgresql://postgres:100%25@host/db", "a bare % must be encoded"],
  ["postgresql://postgres:a b@host/db", "postgresql://postgres:a%20b@host/db", "raw space in the password"],
  ["postgres://postgres:p@ss@host/db", "postgres://postgres:p%40ss@host/db", "postgres:// scheme too"],
  // Already encoded: encoding again would turn %40 into %2540 and break a
  // working password. This is the case the modal/dashboard round-trip hits.
  ["postgresql://postgres.abc:p%40ss%23word@aws-0-x.pooler.supabase.com:6543/postgres", "postgresql://postgres.abc:p%40ss%23word@aws-0-x.pooler.supabase.com:6543/postgres", "already encoded is untouched"],
  ["postgresql://postgres.abc:p%2Fss@aws-0-x.pooler.supabase.com:6543/postgres", "postgresql://postgres.abc:p%2Fss@aws-0-x.pooler.supabase.com:6543/postgres", "pooler user + encoded slash"],
  ["postgresql://postgres:a%20b@host/db", "postgresql://postgres:a%20b@host/db", "already-encoded space is untouched"],
  ["postgresql://postgres:pa%41ss@host/db", "postgresql://postgres:pa%2541ss@host/db", "a literal %41 in a RAW password is still escaped"],
  // Nothing to do.
  ["postgresql://postgres:abc123@host:5432/db", "postgresql://postgres:abc123@host:5432/db", "plain alphanumeric is unchanged"],
  ["postgresql://postgres:secret@host/db?sslmode=require&x=a@b", "postgresql://postgres:secret@host/db?sslmode=require&x=a@b", "an @ in the query is not the delimiter"],
  ["postgresql://host/db", "postgresql://host/db", "no credentials"],
  ["  postgresql://postgres:x@host/db  ", "postgresql://postgres:x@host/db", "trimmed"],
  ["not-a-url", "not-a-url", "not a postgres URL"],
];

test("credentials in a connection URL are percent-encoded", () => {
  for (const [input, want, label] of CASES) {
    assert.equal(encodePostgresCredentials(input), want, label);
  }
});

test("encoding is idempotent — normalising twice changes nothing", () => {
  for (const [input, , label] of CASES) {
    const once = encodePostgresCredentials(input);
    assert.equal(encodePostgresCredentials(once), once, label);
  }
});

test("isPercentEncoded distinguishes encoded from raw", () => {
  assert.equal(isPercentEncoded("p%40ss"), true);
  assert.equal(isPercentEncoded("p@ss"), false);
  assert.equal(isPercentEncoded("abc123"), false, "no escapes means nothing to leave alone");
  assert.equal(isPercentEncoded("100%"), false, "a lone % is not valid encoding");
  assert.equal(isPercentEncoded("%zz"), false);
});

test("unreplaced placeholders are recognised", () => {
  assert.equal(looksLikePlaceholder("postgresql://postgres:[YOUR-PASSWORD]@db.x.supabase.co:5432/postgres"), true);
  assert.equal(looksLikePlaceholder("postgresql://postgres:<password>@host/db"), true);
  assert.equal(looksLikePlaceholder("postgresql://postgres:realpw@host/db"), false);
});
