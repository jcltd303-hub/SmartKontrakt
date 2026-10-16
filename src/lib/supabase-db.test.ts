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
    password: "hX*+JxfrR4Q&3BB",
    region: "us-east-1",
    mode: "pooler",
    active: true,
  });

  // Verify pooler URL format
  assert.match(url, /^postgresql:\/\/postgres\.abcdefghijklmnop:hX\*%2BJxfrR4Q%263BB@aws-0-us-east-1\.pooler\.supabase\.com:6543\/postgres$/);
  // Verify + is encoded as %2B and & is encoded as %26
  assert.ok(url.includes("hX*%2BJxfrR4Q%263BB"));
  assert.ok(!url.includes("&3BB@")); // unencoded & would break connection string parameters
});

test("buildSupabasePostgresUrl builds direct 5432 connection URL", () => {
  const url = buildSupabasePostgresUrl({
    projectName: "SmartKontrakt",
    projectRef: "abcdefghijklmnop",
    password: "hX*+JxfrR4Q&3BB",
    region: "us-east-1",
    mode: "direct",
    active: true,
  });

  assert.equal(url, "postgresql://postgres:hX*%2BJxfrR4Q%263BB@db.abcdefghijklmnop.supabase.co:5432/postgres");
});

test("buildSupabasePostgresUrl cleans projectRef containing full URLs", () => {
  const url = buildSupabasePostgresUrl({
    projectName: "SmartKontrakt",
    projectRef: "https://myprojectref12345.supabase.co/rest/v1",
    password: "hX*+JxfrR4Q&3BB",
    region: "eu-central-1",
    mode: "pooler",
    active: true,
  });

  assert.equal(
    url,
    "postgresql://postgres.myprojectref12345:hX*%2BJxfrR4Q%263BB@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
  );
});

test("maskPostgresUrl conceals password safely for UI display", () => {
  const unmasked = "postgresql://postgres:hX*%2BJxfrR4Q%263BB@db.abcdefghijklmnop.supabase.co:5432/postgres";
  const masked = maskPostgresUrl(unmasked);

  assert.ok(!masked.includes("hX*%2BJxfrR4Q%263BB"));
  assert.ok(masked.includes("••••••"));
  assert.ok(masked.includes("postgres:"));
  assert.ok(masked.includes("@db.abcdefghijklmnop.supabase.co:5432/postgres"));
});

test("DEFAULT_SUPABASE_DB_CONFIG has SmartKontrakt and password set", () => {
  assert.equal(DEFAULT_SUPABASE_DB_CONFIG.projectName, "SmartKontrakt");
  assert.equal(DEFAULT_SUPABASE_DB_CONFIG.password, "hX*+JxfrR4Q&3BB");
  assert.equal(DEFAULT_SUPABASE_DB_CONFIG.mode, "pooler");
});
