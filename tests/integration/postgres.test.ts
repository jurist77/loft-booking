import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import type { Pool } from "pg";
import { databaseSettings } from "../../src/server/config";
import { closeDatabasePool, createDatabasePool } from "../../src/server/database";
import { databaseHealth } from "../../src/server/health";
import { migrate, MIGRATION_LOCK } from "../../src/server/migrations";

let app: Pool; let migration: Pool; let safeDatabase = false;
const folders: string[] = [];
let originalSQL = "";

async function fixture(extra: Record<string, string> = {}) {
  const directory = await mkdtemp(join(tmpdir(), "studio-postgres-integration-")); folders.push(directory);
  await writeFile(join(directory, "0001_foundation.sql"), originalSQL);
  for (const [name, sql] of Object.entries(extra)) await writeFile(join(directory, name), sql);
  return directory;
}

function command(directory: string) {
  let output = "";
  const child = spawn(process.execPath, ["--conditions=react-server", "scripts/migrate.mjs"], {
    cwd: process.cwd(), env: { ...process.env, APP_MODE: "server", MIGRATION_DATABASE_URL: process.env.TEST_MIGRATION_DATABASE_URL, MIGRATIONS_DIR: directory },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => { output += chunk; }); child.stderr.on("data", (chunk) => { output += chunk; });
  const done = new Promise<{ code: number | null; output: string }>((resolve, reject) => {
    child.on("error", reject); child.on("close", (code) => resolve({ code, output }));
  });
  return { child, done };
}

beforeAll(async () => {
  // Destructive cleanup is restricted to a dedicated, loopback-only *_test DB.
  let appURL: URL; let migrationURL: URL;
  try {
    appURL = new URL(process.env.TEST_DATABASE_URL || "");
    migrationURL = new URL(process.env.TEST_MIGRATION_DATABASE_URL || "");
  } catch { throw new Error("Valid private test database configuration is required"); }
  const local = ["127.0.0.1", "localhost", "[::1]"];
  if (!local.includes(appURL.hostname) || appURL.host !== migrationURL.host || appURL.pathname !== migrationURL.pathname || !/_test$/.test(appURL.pathname) || appURL.username === migrationURL.username) throw new Error("A separate local test database and two distinct test roles are required");
  process.env.APP_MODE = "server"; process.env.DATABASE_URL = process.env.TEST_DATABASE_URL;
  app = createDatabasePool(databaseSettings());
  migration = createDatabasePool(databaseSettings({ ...process.env, MIGRATION_DATABASE_URL: process.env.TEST_MIGRATION_DATABASE_URL }, true));
  const current = await migration.query<{ name: string }>("SELECT current_database() AS name");
  if (`/${current.rows[0].name}` !== appURL.pathname) throw new Error("Test database identity mismatch");
  const tables = await migration.query<{ tablename: string }>("SELECT tablename FROM pg_tables WHERE schemaname = 'studio'");
  if (tables.rows.some((row) => row.tablename !== "schema_migrations")) throw new Error("The test schema contains non-fixture tables; refusing cleanup");
  safeDatabase = true;
  await migration.query("DROP TABLE IF EXISTS studio.schema_migrations");
  originalSQL = await readFile(resolve("migrations/0001_foundation.sql"), "utf8");
});

afterAll(async () => {
  try { if (safeDatabase) await migration.query("DROP TABLE IF EXISTS studio.schema_migrations"); }
  finally {
    await closeDatabasePool(); await app?.end(); await migration?.end();
    for (const directory of folders) await rm(directory, { recursive: true, force: true });
  }
});

describe("Real PostgreSQL foundation (no mocked database)", () => {
  it("connects with non-superuser roles and no application DDL privileges", async () => {
    const roles = await app.query("SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = current_user");
    expect(roles.rows[0]).toEqual({ rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolbypassrls: false });
    expect((await app.query("SELECT has_schema_privilege(current_user, 'studio', 'CREATE') AS allowed")).rows[0].allowed).toBe(false);
    expect((await migration.query("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")).rows[0].rolsuper).toBe(false);
    const version = await app.query("SHOW server_version");
    console.log(`Real PostgreSQL version: ${version.rows[0].server_version}`);
  });
  it("applies the SQL migration once and preserves history on a second run", async () => {
    expect(await migrate(migration, resolve("migrations"))).toEqual([1]);
    expect(await migrate(migration, resolve("migrations"))).toEqual([]);
    expect((await migration.query("SELECT count(*)::int AS count FROM studio.schema_migrations")).rows[0].count).toBe(1);
    await expect(app.query("SELECT * FROM studio.schema_migrations")).rejects.toMatchObject({ code: "42501" });
  });
  it("refuses altered applied SQL without changing the stored history", async () => {
    const directory = await fixture();
    await writeFile(join(directory, "0001_foundation.sql"), originalSQL + "\n-- unexpected edit\n");
    await expect(migrate(migration, directory)).rejects.toMatchObject({ code: "HISTORY_MISMATCH" });
    const cli = await command(directory).done;
    expect(cli.code).toBe(1); expect(cli.output).toContain("HISTORY_MISMATCH");
    expect((await migration.query("SELECT count(*)::int AS count FROM studio.schema_migrations")).rows[0].count).toBe(1);
  });
  it("prevents two separate migration processes from applying the same pending version", async () => {
    const directory = await fixture({ "0002_concurrency_probe.sql": "SELECT pg_sleep(1);\n" });
    const first = command(directory);
    try {
      let held = false;
      for (let attempt = 0; attempt < 60; attempt++) {
        const locks = await migration.query<{ held: boolean }>("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid = 0 AND objid = $1::oid AND granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database())) AS held", [MIGRATION_LOCK]);
        if (locks.rows[0].held) { held = true; break; }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      expect(held).toBe(true);
      const second = await command(directory).done;
      expect(second.code).toBe(1); expect(second.output).toContain("MIGRATION_LOCKED");
      expect((await first.done).code).toBe(0);
      expect((await migration.query("SELECT version::int FROM studio.schema_migrations ORDER BY version")).rows).toEqual([{ version: 1 }, { version: 2 }]);
    } finally { if (first.child.exitCode === null) first.child.kill("SIGTERM"); await first.done; }
  });
  it("returns nonzero for failed SQL and rolls back its history row", async () => {
    const directory = await fixture({ "0002_concurrency_probe.sql": "SELECT pg_sleep(1);\n", "0003_failure_probe.sql": "SELECT studio.this_function_does_not_exist();\n" });
    const result = await command(directory).done;
    expect(result.code).toBe(1); expect(result.output).toContain("MIGRATION_FAILED");
    expect((await migration.query("SELECT count(*)::int AS count FROM studio.schema_migrations")).rows[0].count).toBe(2);
    expect((await app.query("SELECT to_regclass('studio.bookings') AS bookings, to_regclass('studio.booking_events') AS events")).rows[0]).toEqual({ bookings: null, events: null });
  });
  it("refuses a history whose already applied SQL file is missing", async () => {
    await expect(migrate(migration, await fixture())).rejects.toMatchObject({ code: "HISTORY_MISMATCH" });
    expect((await migration.query("SELECT count(*)::int AS count FROM studio.schema_migrations")).rows[0].count).toBe(2);
  });
  it("returns a minimal uncached health 200 with the real DB", async () => {
    const response = await databaseHealth();
    expect(response.status).toBe(200); expect(await response.json()).toEqual({ status: "ok" });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
  it("returns only a safe 503 when the real connection target is unavailable", async () => {
    await closeDatabasePool();
    const original = process.env.DATABASE_URL!;
    const unavailable = new URL(original); unavailable.port = "1";
    process.env.DATABASE_URL = unavailable.toString();
    try {
      const response = await databaseHealth();
      expect(response.status).toBe(503); expect(await response.text()).toBe('{"status":"unavailable"}');
    } finally { await closeDatabasePool(); process.env.DATABASE_URL = original; }
  });
  it("enforces bounded query timeouts on a real query", async () => {
    const bounded = createDatabasePool(databaseSettings({ ...process.env, DB_QUERY_TIMEOUT_MS: "100" }));
    const start = Date.now();
    try { await expect(bounded.query("SELECT pg_sleep(1)")).rejects.toBeDefined(); expect(Date.now() - start).toBeLessThan(3000); }
    finally { await bounded.end(); }
  });
});
