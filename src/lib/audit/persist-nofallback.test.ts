import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createServer } from "vite";
import { readFileSync } from "node:fs";
// Match the application's bundler resolution for extensionless server imports.
const server = await createServer({
  configFile: false,
  resolve: { alias: { "@": new URL("../../", import.meta.url).pathname } },
  optimizeDeps: { noDiscovery: true },
  server: { middlewareMode: true },
  appType: "custom",
});
after(() => server.close());
const { getDatabaseInfo, getDbConnectionState, getSql, switchDatabase } =
  await server.ssrLoadModule("/src/lib/db.ts");
const { getDatabaseSize, getScansStats, listScanSummaries } = await server.ssrLoadModule(
  "/src/lib/audit/persist.server.ts",
);

/**
 * No-fallback contract (Jer, 2026-10-22: "No fallback duh").
 *
 * The Oct 2026 Records masquerade: the configured database's password was
 * stale, db.ts silently substituted an embedded PGlite store, every
 * archive query "succeeded" against it, and Records rendered TOTAL
 * AUDITS 0 over a database holding 8,931 scans. The substitute is
 * REMOVED. These tests pin the replacement behavior end-to-end through
 * the persist wrappers (the exact functions the Records server fns call):
 *
 *   configured-but-unreachable → getSql REJECTS; list/stats/size return
 *     error payloads with dbState "failed" and the configured identity in
 *     the message — never a successful-looking empty result, and a repeat
 *     call fails the same way (no memoized substitute quietly engaging).
 *   unconfigured → the same payloads report dbState "unconfigured" with
 *     an explicit "No database configured" error — not a local archive.
 *   healthy remote → covered at the query layer by scan-archive.test.ts
 *     (fake Sql) and at the state layer by db-env.test.ts
 *     (classifyDbState remote); a live-PG control cannot run in this
 *     harness, and no test here pretends otherwise.
 *
 * The db.ts source guard at the bottom pins the removal itself: the
 * embedded store must not creep back as a "harmless" code path. It
 * matches code tokens (the import specifier, the factory, the
 * constructor), not the explanatory comments that document the removal.
 */

// Connection-refused target: a configured URL whose host answers nothing.
// Port 1 on loopback refuses instantly, so no timeouts are involved; the
// failure class (target configured, connection fails) is the masquerade
// class regardless of whether the refusal is auth or connectivity.
const BAD_URL = "postgresql://postgres.wvknnljtrsjghfbhylqn:wrong-password@127.0.0.1:1/postgres";

test("configured-but-unreachable: getSql rejects — no substitute store engages", async () => {
  switchDatabase(BAD_URL);
  await assert.rejects(getSql(), /Database connection failed/);
  // A second attempt fails identically: failure is the state, not a
  // one-off that a later call papers over with an empty success.
  await assert.rejects(getSql(), /Database connection failed/);
  const conn = await getDbConnectionState();
  assert.equal(conn.state, "failed");
  assert.equal(conn.configured?.host, "127.0.0.1");
  const info = await getDatabaseInfo();
  assert.equal(info.connected, false);
  assert.equal(info.state, "failed");
  assert.equal(info.ephemeralFallback, false);
});

test("configured-but-unreachable: archive payloads report FAILED, never zeros-as-success", async () => {
  switchDatabase(BAD_URL);
  const list = await listScanSummaries();
  assert.equal(list.dbState, "failed");
  assert.deepEqual(list.summaries, []);
  assert.ok(
    list.error && list.error.includes("could not be reached"),
    `list error was: ${list.error}`,
  );
  assert.ok(list.error && list.error.includes("No fallback"), `list error was: ${list.error}`);
  assert.ok(list.dbError, "dbError carries the classified failure");

  const stats = await getScansStats();
  assert.equal(stats.dbState, "failed");
  assert.ok(stats.error, "stats error is set — the zero counts ride along as inert data only");
  assert.ok(stats.dbError);

  const size = await getDatabaseSize();
  assert.equal(size.dbState, "failed");
  assert.equal(size.totalBytes, null);
  assert.ok(size.error);
});

test("unconfigured: explicit unconfigured payloads, not a local archive", async () => {
  switchDatabase(null);
  // The mirror test process carries no DATABASE_URL-family env vars and
  // no saved config file in its cwd, so nothing is configured here.
  await assert.rejects(getSql(), /No database configured/);
  const list = await listScanSummaries();
  assert.equal(list.dbState, "unconfigured");
  assert.deepEqual(list.summaries, []);
  assert.ok(
    list.error && list.error.includes("No database configured"),
    `list error was: ${list.error}`,
  );

  const stats = await getScansStats();
  assert.equal(stats.dbState, "unconfigured");
  assert.ok(stats.error && stats.error.includes("No database configured"));

  const size = await getDatabaseSize();
  assert.equal(size.dbState, "unconfigured");
  assert.equal(size.totalBytes, null);

  const info = await getDatabaseInfo();
  assert.equal(info.state, "unconfigured");
  assert.equal(info.connected, false);
  switchDatabase(null);
});

test("the embedded substitute is deleted from the DB layer, not relabeled", () => {
  const src = readFileSync(new URL("../db.ts", import.meta.url), "utf8");
  assert.ok(!src.includes("@electric-sql/pglite"), "db.ts must not import PGlite");
  assert.ok(!src.includes("createPgliteSql"), "db.ts must not construct the embedded store");
  assert.ok(!src.includes("new PGlite"), "db.ts must not instantiate PGlite");
  assert.ok(!src.includes("getPglite"), "the embedded-store accessor must be gone");
});
