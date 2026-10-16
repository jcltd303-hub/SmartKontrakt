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
