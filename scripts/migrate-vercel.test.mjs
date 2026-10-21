import test from "node:test";
import assert from "node:assert/strict";
import { resolveMigrateDatabaseUrl } from "./migrate-vercel.mjs";

test("DATABASE_URL wins over Vercel Supabase integration vars", () => {
  assert.equal(
    resolveMigrateDatabaseUrl({
      DATABASE_URL: "postgresql://override",
      POSTGRES_URL_NON_POOLING: "postgres://direct",
      POSTGRES_PRISMA_URL: "postgresql://pooler",
      POSTGRES_URL: "postgresql://pooler2",
    }),
    "postgresql://override",
  );
});

test("migrations prefer direct POSTGRES_URL_NON_POOLING over pooler URLs", () => {
  assert.equal(
    resolveMigrateDatabaseUrl({
      POSTGRES_URL_NON_POOLING: "postgres://direct",
      POSTGRES_PRISMA_URL: "postgresql://pooler",
      POSTGRES_URL: "postgresql://pooler2",
    }),
    "postgres://direct",
  );
});

test("pooler PRISMA URL is used when no direct URL is set", () => {
  assert.equal(
    resolveMigrateDatabaseUrl({
      POSTGRES_PRISMA_URL: "postgresql://pooler",
      POSTGRES_URL: "postgresql://pooler2",
    }),
    "postgresql://pooler",
  );
});

test("empty / whitespace / non-Postgres values are treated as unset", () => {
  assert.equal(
    resolveMigrateDatabaseUrl({
      DATABASE_URL: "   ",
      POSTGRES_URL: "https://example.supabase.co",
    }),
    undefined,
  );
  assert.equal(resolveMigrateDatabaseUrl({}), undefined);
});


test("migration credentials are percent-encoded, and an encoded URL is left alone", () => {
  // A raw `@` or `#` in the password silently re-parses the host, so the
  // migrator would fail on a password the rest of the stack handles.
  assert.equal(
    resolveMigrateDatabaseUrl({
      DATABASE_URL: "postgresql://postgres:p@ss#word@db.x.supabase.co:5432/postgres",
    }),
    "postgresql://postgres:p%40ss%23word@db.x.supabase.co:5432/postgres",
  );
  // What the Supabase dashboard hands you is already encoded; encoding it again
  // would turn %40 into %2540 and break a working password.
  const already = "postgresql://postgres.abc:p%40ss%23word@aws-0-x.pooler.supabase.com:6543/postgres";
  assert.equal(resolveMigrateDatabaseUrl({ DATABASE_URL: already }), already);
});
