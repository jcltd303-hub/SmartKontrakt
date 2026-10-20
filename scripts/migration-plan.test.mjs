import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { isMigrationFile, migrationName, pendingMigrations } from "./migration-plan.mjs";
import { projectRoot } from "./with-app-env.mjs";

test("_migrations keys on basename, not path", () => {
  assert.equal(migrationName("/migrations/0002_todos.sql"), "0002_todos.sql");
  assert.equal(migrationName("migrations/nested/0001_x.sql"), "0001_x.sql");
});

test("a file already applied from another directory does not re-apply", () => {
  // Migrations are keyed by basename, so a file that moved directories is not
  // re-run against a database that already recorded it under the same name.
  assert.deepEqual(pendingMigrations(["/migrations/0001_x.sql"], ["0001_x.sql"]), []);
});

test("pending migrations are returned in name order", () => {
  assert.deepEqual(
    pendingMigrations(
      ["/migrations/0003_c.sql", "/migrations/0001_a.sql", "/migrations/0002_b.sql"],
      ["0001_a.sql"],
    ),
    [
      { name: "0002_b.sql", path: "/migrations/0002_b.sql" },
      { name: "0003_c.sql", path: "/migrations/0003_c.sql" },
    ],
  );
});

test("non-.sql entries are dropped (readdir also yields subdirectories)", () => {
  assert.equal(isMigrationFile("nested"), false);
  assert.deepEqual(pendingMigrations(["nested", "README.md"], []), []);
});

test("the migrations directory yields only .sql migrations", () => {
  const entries = readdirSync(join(projectRoot(), "migrations"));
  const sql = entries.filter((name) => name.endsWith(".sql")).sort();
  assert.deepEqual(
    pendingMigrations(entries, []).map((m) => m.name),
    sql,
  );
});
