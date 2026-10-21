import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSupabasePostgresUrl,
  maskPostgresUrl,
  DEFAULT_SUPABASE_DB_CONFIG,
} from "./supabase-db.server.ts";

test("buildSupabasePostgresUrl properly URL-encodes special characters in password", () => {
  const url = buildSupabasePostgresUrl({
    projectName: "SmartKontrakt",
    projectRef: "abcdefghijklmnop",
    password: "test+password&only",
    region: "us-east-1",
    mode: "pooler",
    active: true,
  });

  // Verify pooler URL format
  assert.match(url, /^postgresql:\/\/postgres\.abcdefghijklmnop:test%2Bpassword%26only@aws-0-us-east-1\.pooler\.supabase\.com:6543\/postgres$/);
  // Verify + is encoded as %2B and & is encoded as %26
  assert.ok(url.includes("test%2Bpassword%26only"));
  assert.ok(!url.includes("&only@")); // unencoded & would break connection string parameters
});

test("buildSupabasePostgresUrl builds direct 5432 connection URL", () => {
  const url = buildSupabasePostgresUrl({
    projectName: "SmartKontrakt",
    projectRef: "abcdefghijklmnop",
    password: "test+password&only",
    region: "us-east-1",
    mode: "direct",
    active: true,
  });

  assert.equal(url, "postgresql://postgres:test%2Bpassword%26only@db.abcdefghijklmnop.supabase.co:5432/postgres");
});

test("buildSupabasePostgresUrl cleans projectRef containing full URLs", () => {
  const url = buildSupabasePostgresUrl({
    projectName: "SmartKontrakt",
    projectRef: "https://myprojectref12345.supabase.co/rest/v1",
    password: "test+password&only",
    region: "eu-central-1",
    mode: "pooler",
    active: true,
  });

  assert.equal(
    url,
    "postgresql://postgres.myprojectref12345:test%2Bpassword%26only@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
  );
});

test("maskPostgresUrl conceals password safely for UI display", () => {
  const unmasked = "postgresql://postgres:test%2Bpassword%26only@db.abcdefghijklmnop.supabase.co:5432/postgres";
  const masked = maskPostgresUrl(unmasked);

  assert.ok(!masked.includes("test%2Bpassword%26only"));
  assert.ok(masked.includes("••••••"));
  assert.ok(masked.includes("postgres:"));
  assert.ok(masked.includes("@db.abcdefghijklmnop.supabase.co:5432/postgres"));
});

test("default database config contains no password", () => {
  assert.equal(DEFAULT_SUPABASE_DB_CONFIG.projectName, "SmartKontrakt");
  assert.equal(DEFAULT_SUPABASE_DB_CONFIG.password, "");
  assert.equal(DEFAULT_SUPABASE_DB_CONFIG.mode, "pooler");
});


test("missing passwords never use a committed fallback credential", () => {
  assert.equal(buildSupabasePostgresUrl({ ...DEFAULT_SUPABASE_DB_CONFIG, password: "" }), "");
});


// --- credential encoding at the connection-URL boundary (see src/lib/pg-url.ts) ---

test("a pasted custom URL has its raw credentials percent-encoded", () => {
  const url = buildSupabasePostgresUrl({
    ...DEFAULT_SUPABASE_DB_CONFIG,
    mode: "custom",
    customUrl: "postgresql://postgres:p@ss#word@db.x.supabase.co:5432/postgres",
    active: true,
  });
  assert.equal(url, "postgresql://postgres:p%40ss%23word@db.x.supabase.co:5432/postgres");
});

test("an already-encoded custom URL is left alone (no double-encoding)", () => {
  // Supabase's dashboard hands out an encoded URI. Re-encoding it would turn
  // %40 into %2540 and break a password that currently works.
  const already = "postgresql://postgres.abc:p%40ss%23word@aws-0-x.pooler.supabase.com:6543/postgres";
  const url = buildSupabasePostgresUrl({
    ...DEFAULT_SUPABASE_DB_CONFIG,
    mode: "custom",
    customUrl: already,
    active: true,
  });
  assert.equal(url, already);
});

test("the user is encoded as well as the password", () => {
  const url = buildSupabasePostgresUrl({
    ...DEFAULT_SUPABASE_DB_CONFIG,
    mode: "custom",
    customUrl: "",
    host: "db.x.supabase.co",
    user: "weird user",
    password: "p@ss",
    port: 5432,
    database: "postgres",
    active: true,
  });
  assert.ok(url.includes("weird%20user"), `user must be encoded: ${url}`);
  assert.ok(url.includes("p%40ss"), `password must be encoded: ${url}`);
});
