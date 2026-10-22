import test from "node:test";
import assert from "node:assert/strict";
import {
  DATABASE_ENV_VARS,
  DIRECT_ENV_VARS,
  cleanEnvUrl,
  databaseEnvInventory,
  resolveDatabaseUrl,
  resolveDirectDatabaseUrl,
  sanitizeForNodePostgres,
} from "./db-env.ts";

const POOLED = "postgresql://postgres.abcdefghij:pw@aws-1-us-east-1.pooler.supabase.com:6543/postgres";
const DIRECT = "postgresql://postgres:pw@db.abcdefghij.supabase.co:5432/postgres";

test("the Vercel Supabase integration's names resolve — POSTGRES_URL alone is enough", () => {
  // This is the case that was broken: the integration injects POSTGRES_URL and
  // the app looked only at DATABASE_URL, so a wired-up deployment read as
  // unconfigured.
  const r = resolveDatabaseUrl({ POSTGRES_URL: POOLED });
  assert.equal(r?.from, "POSTGRES_URL");
  assert.ok(r?.url.startsWith("postgresql://"));
});

test("POSTGRES_URL_NON_POOLING alone resolves too", () => {
  const r = resolveDatabaseUrl({ POSTGRES_URL_NON_POOLING: DIRECT });
  assert.equal(r?.from, "POSTGRES_URL_NON_POOLING");
});

test("an explicit DATABASE_URL wins over the integration's variables", () => {
  const r = resolveDatabaseUrl({ DATABASE_URL: DIRECT, POSTGRES_URL: POOLED });
  assert.equal(r?.from, "DATABASE_URL");
});

test("the pooled preference order is Prisma > pooled > direct", () => {
  assert.equal(resolveDatabaseUrl({ POSTGRES_PRISMA_URL: POOLED, POSTGRES_URL: POOLED })?.from, "POSTGRES_PRISMA_URL");
  assert.equal(resolveDatabaseUrl({ POSTGRES_URL: POOLED, POSTGRES_URL_NON_POOLING: DIRECT })?.from, "POSTGRES_URL");
});

test("empty, whitespace and unreplaced templates are treated as unset", () => {
  // An empty value in a deploy UI is an easy misconfig and must not win.
  assert.equal(resolveDatabaseUrl({ POSTGRES_URL: "" }), undefined);
  assert.equal(resolveDatabaseUrl({ POSTGRES_URL: "   " }), undefined);
  assert.equal(resolveDatabaseUrl({ POSTGRES_URL: "postgresql://u:<PASSWORD>@h:5432/d" }), undefined);
  assert.equal(resolveDatabaseUrl({ POSTGRES_URL: "postgresql://u:[YOUR-PASSWORD]@h:5432/d" }), undefined);
});

test("a value that is not a Postgres URL is ignored", () => {
  assert.equal(resolveDatabaseUrl({ POSTGRES_URL: "mysql://u:p@h:3306/d" }), undefined);
  assert.equal(resolveDatabaseUrl({ POSTGRES_URL: "https://abcdefghij.supabase.co" }), undefined);
});

test("cleanEnvUrl is idempotent, so an already-encoded URL is untouched", () => {
  const once = cleanEnvUrl(DIRECT);
  const twice = cleanEnvUrl(once);
  assert.equal(twice, once);
});

test("migrations prefer a DIRECT url over the pooled one", () => {
  const r = resolveDirectDatabaseUrl({ POSTGRES_URL: POOLED, POSTGRES_URL_NON_POOLING: DIRECT });
  assert.equal(r?.from, "POSTGRES_URL_NON_POOLING");
  assert.equal(r?.url, DIRECT);
});

test("migrations fall back to DATABASE_URL when nothing direct is published", () => {
  assert.equal(resolveDirectDatabaseUrl({ DATABASE_URL: DIRECT, POSTGRES_URL: POOLED })?.from, "DATABASE_URL");
  assert.equal(resolveDirectDatabaseUrl({ POSTGRES_URL: POOLED }), undefined);
});

test("the inventory reports presence and never a value", () => {
  const inv = databaseEnvInventory({ POSTGRES_URL: POOLED });
  assert.deepEqual(
    inv.map((v) => v.name),
    DATABASE_ENV_VARS.map((v) => v.name),
  );
  assert.equal(inv.find((v) => v.name === "POSTGRES_URL")?.present, true);
  assert.equal(inv.find((v) => v.name === "DATABASE_URL")?.present, false);
  // Names only: a status surface must be safe to render.
  assert.ok(!JSON.stringify(inv).includes("pw"));
  assert.ok(!JSON.stringify(inv).includes("postgresql://"));
});

test("every declared direct variable is a declared database variable", () => {
  const names = new Set(DATABASE_ENV_VARS.map((v) => v.name));
  for (const name of DIRECT_ENV_VARS) assert.ok(names.has(name), `${name} is not in DATABASE_ENV_VARS`);
});

test("a missing environment resolves to nothing rather than throwing", () => {
  assert.equal(resolveDatabaseUrl({}), undefined);
  assert.equal(resolveDirectDatabaseUrl({}), undefined);
  assert.equal(resolveDatabaseUrl({ POSTGRES_URL: undefined }), undefined);
});

test("another client's parameters are stripped before node-postgres sees them", () => {
  // POSTGRES_PRISMA_URL carries ?pgbouncer=true, which is Prisma's, not pg's.
  assert.equal(
    sanitizeForNodePostgres("postgresql://u:p@h:6543/db?pgbouncer=true&sslmode=require"),
    "postgresql://u:p@h:6543/db?sslmode=require",
  );
  assert.equal(sanitizeForNodePostgres("postgresql://u:p@h:6543/db?connection_limit=1"), "postgresql://u:p@h:6543/db");
  assert.equal(sanitizeForNodePostgres("postgresql://u:p@h:6543/db"), "postgresql://u:p@h:6543/db");
  // A raw password containing ? or & must not be touched: the authority is
  // never parsed, only the query string.
  assert.equal(
    sanitizeForNodePostgres("postgresql://u:pa?ss@h:6543/db"),
    "postgresql://u:pa?ss@h:6543/db",
  );
});

test("cleanEnvUrl applies that strip, so the Prisma URL resolves pg-safe", () => {
  const r = resolveDatabaseUrl({ POSTGRES_PRISMA_URL: "postgresql://u:p@h:6543/db?pgbouncer=true" });
  assert.equal(r?.from, "POSTGRES_PRISMA_URL");
  assert.ok(!r?.url.includes("pgbouncer"), `pgbouncer survived: ${r?.url}`);
});
