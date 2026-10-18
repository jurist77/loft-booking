import { afterEach, beforeEach, expect, it } from "vitest";
import { chmodSync, existsSync, linkSync, lstatSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import type Database from "better-sqlite3";
import { databaseSettings } from "../../src/server/config";
import { initializeDatabase, openDatabase, closeDatabase, assertIntegrity } from "../../src/server/database";
import { migrate } from "../../src/server/migrations";
import { backupDatabase, restoreDatabase } from "../../src/server/backup";
import { databaseHealth } from "../../src/server/health";

let folder: string; let path: string; let db: Database.Database;
const migrations = resolve("migrations/sqlite");
const start = Date.parse("2030-01-15T10:00:00+03:00");
const hour = 3600000;
const folders: string[] = [];
const env = () => ({ ...process.env, APP_MODE: "server", SQLITE_PATH: path });
function sqlInsert(id: string, begin = start, end = start + hour) { return db.prepare("INSERT INTO bookings(id, starts_at, ends_at) VALUES (?, ?, ?)").run(id, begin, end); }
function command(args: string[], overrides: Record<string, string> = {}) {
  const child = spawn(process.execPath, ["--conditions=react-server", ...args], { env: { ...env(), ...overrides }, stdio: ["pipe", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; }); child.stderr.on("data", (chunk) => { output += chunk; });
  const done = new Promise<{ code: number | null; output: string }>((resolve, reject) => { child.once("error", reject); child.once("close", (code) => resolve({ code, output })); });
  return { child, done, get output() { return output; } };
}
async function manifest(extra: Record<string, string> = {}) {
  const directory = mkdtempSync(join(tmpdir(), "studio-sqlite-manifest-")); folders.push(directory);
  writeFileSync(join(directory, "0001_foundation.sql"), readFileSync(join(migrations, "0001_foundation.sql")));
  for (const [name, sql] of Object.entries(extra)) writeFileSync(join(directory, name), sql);
  return directory;
}
beforeEach(async () => {
  folder = mkdtempSync(join(tmpdir(), "studio-sqlite-integration-")); folders.push(folder); path = join(folder, "test.sqlite");
  initializeDatabase(databaseSettings(env())); db = openDatabase(databaseSettings(env()));
  await migrate(db, migrations);
});
afterEach(() => {
  closeDatabase(); if (db?.open) db.close();
  for (const directory of folders.splice(0)) { chmodSync(directory, 0o700); rmSync(directory, { recursive: true, force: true }); }
  delete process.env.SQLITE_PATH; delete process.env.APP_MODE;
});
it("runs real SQLite in WAL/FULL with bounded contention and private files", () => {
  expect(db.pragma("journal_mode", { simple: true })).toBe("wal");
  expect(db.pragma("synchronous", { simple: true })).toBe(2);
  expect(db.pragma("busy_timeout", { simple: true })).toBe(1000);
  expect(lstatSync(path).mode & 0o777).toBe(0o600);
  expect(lstatSync(path + "-wal").mode & 0o077).toBe(0);
  console.log(`Real SQLite: ${(db.prepare("SELECT sqlite_version() AS v").get() as { v: string }).v}`);
});
it("restarts without data loss and repeat initialization/migration is idempotent", async () => {
  sqlInsert("fictional-test"); db.close(); initializeDatabase(databaseSettings(env()));
  db = openDatabase(databaseSettings(env())); expect(await migrate(db, migrations)).toEqual([]);
  expect(db.prepare("SELECT count(*) AS n FROM bookings").get()).toEqual({ n: 1 });
  expect(db.prepare("SELECT count(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
});
it("rejects modified applied SQL and returns nonzero from the CLI", async () => {
  const directory = await manifest(); writeFileSync(join(directory, "0001_foundation.sql"), "SELECT 1;\n");
  await expect(migrate(db, directory)).rejects.toMatchObject({ code: "HISTORY_MISMATCH" });
  const result = await command(["scripts/database.mjs", "migrate"], { MIGRATIONS_DIR: directory }).done;
  expect(result.code).toBe(1); expect(result.output).toContain("HISTORY_MISMATCH");
});
it("rejects missing applied files without deleting history", async () => {
  await migrate(db, await manifest({ "0002_probe.sql": "SELECT 1;" }));
  await expect(migrate(db, migrations)).rejects.toMatchObject({ code: "HISTORY_MISMATCH" });
  expect(db.prepare("SELECT count(*) AS n FROM schema_migrations").get()).toEqual({ n: 2 });
});
it("rolls back all pending DDL and history on SQL failure", async () => {
  const directory = await manifest({ "0002_failure.sql": "CREATE TABLE rollback_probe(id INTEGER); SELECT missing_function();" });
  const result = await command(["scripts/database.mjs", "migrate"], { MIGRATIONS_DIR: directory }).done;
  expect(result.code).toBe(1); expect(result.output).toContain("MIGRATION_FAILED");
  expect(db.prepare("SELECT name FROM sqlite_master WHERE name='rollback_probe'").get()).toBeUndefined();
  expect(db.prepare("SELECT count(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
});
it("serializes independent migration processes and fails safely on a held writer lock", async () => {
  const lock = command(["tests/integration/sqlite-worker.mjs", "lock"]);
  try {
    for (let i = 0; i < 100 && !lock.output.includes("LOCKED"); i++) await new Promise((resolve) => setTimeout(resolve, 20));
    expect(lock.output).toContain("LOCKED");
    const blocked = await command(["scripts/database.mjs", "migrate"], { SQLITE_BUSY_TIMEOUT_MS: "50" }).done;
    expect(blocked.code).toBe(1); expect(blocked.output).toContain("MIGRATION_LOCKED");
  } finally { lock.child.stdin.end("release"); await lock.done; }
  const directory = await manifest({ "0002_parallel.sql": "CREATE TABLE parallel_probe(id INTEGER);" });
  const results = await Promise.all([1, 2].map(() => command(["scripts/database.mjs", "migrate"], { MIGRATIONS_DIR: directory }).done));
  expect(results.map((result) => result.code)).toEqual([0, 0]);
  expect(db.prepare("SELECT count(*) AS n FROM schema_migrations").get()).toEqual({ n: 2 });
});
it("enforces half-open overlap guards including updates/cancellation and adjacency", () => {
  sqlInsert("a"); sqlInsert("adjacent", start + hour, start + 2 * hour);
  expect(() => sqlInsert("overlap", start + hour / 2, start + 1.5 * hour)).toThrow("BOOKING_OVERLAP");
  db.prepare("UPDATE bookings SET status='cancelled' WHERE id='a'").run(); sqlInsert("replacement");
  expect(() => db.prepare("UPDATE bookings SET status='confirmed' WHERE id='a'").run()).toThrow("BOOKING_OVERLAP");
  expect(() => db.prepare("UPDATE bookings SET starts_at=?, ends_at=? WHERE id='adjacent'").run(start, start + hour)).toThrow("BOOKING_OVERLAP");
});
it("preserves 09–23 Moscow, 30-minute alignment and the 60-minute minimum", () => {
  const opening = Date.parse("2030-01-15T09:00:00+03:00"); const closing = opening + 14 * hour;
  for (const [begin, end] of [[opening - hour / 2, opening + hour / 2], [closing - hour / 2, closing + hour / 2], [start, start + hour / 2], [start + 900000, start + hour + 900000], [closing - hour, closing + 2 * hour]]) expect(() => sqlInsert("bad", begin, end)).toThrow();
  sqlInsert("last-hour", closing - hour, closing);
});
it("rejects overlap across two independent SQLite connections/processes", async () => {
  const results = await Promise.all(["one", "two"].map((id) => command(["tests/integration/sqlite-worker.mjs", "reserve", id, String(start), String(start + hour)]).done));
  expect(results.map((result) => result.code).sort()).toEqual([0, 1]);
  expect(results.find((result) => result.code === 1)?.output).toContain("CONFLICT");
  expect(db.prepare("SELECT count(*) AS n FROM bookings").get()).toEqual({ n: 1 });
});
it("returns safe health 200/503/200 when the database path disappears and returns", async () => {
  process.env.APP_MODE = "server"; process.env.SQLITE_PATH = path;
  expect((await databaseHealth()).status).toBe(200);
  const unavailable = folder + "-offline"; renameSync(folder, unavailable);
  try { const response = await databaseHealth(); expect(response.status).toBe(503); expect(await response.text()).toBe('{"status":"unavailable"}'); expect(existsSync(folder)).toBe(false); }
  finally { renameSync(unavailable, folder); }
  expect((await databaseHealth()).status).toBe(200);
});
it("fails safely on readonly or exposed file/directory permissions and recovers", async () => {
  process.env.APP_MODE = "server"; process.env.SQLITE_PATH = path;
  for (const mode of [0o400, 0o644]) {
    chmodSync(path, mode); expect((await databaseHealth()).status).toBe(503); chmodSync(path, 0o600);
    expect((await databaseHealth()).status).toBe(200);
  }
  chmodSync(folder, 0o500); expect((await databaseHealth()).status).toBe(503); chmodSync(folder, 0o700);
  expect((await databaseHealth()).status).toBe(200);
});
it("backs up committed WAL data online and restores a verified independent file", async () => {
  sqlInsert("in-wal");
  const snapshot = join(folder, "snapshot.sqlite"); await backupDatabase(db, snapshot);
  sqlInsert("later", start + 2 * hour, start + 3 * hour);
  const restoredPath = join(folder, "restored.sqlite"); await restoreDatabase(snapshot, restoredPath);
  const restored = openDatabase(databaseSettings({ APP_MODE: "server", SQLITE_PATH: restoredPath }));
  try { assertIntegrity(restored, true); expect(restored.prepare("SELECT id FROM bookings").all()).toEqual([{ id: "in-wal" }]); }
  finally { restored.close(); }
  expect(lstatSync(snapshot).mode & 0o777).toBe(0o600);
});
it("can back up while a separate writer commits transactions", async () => {
  db.exec("CREATE TABLE backup_probe(payload BLOB)");
  const seed = db.transaction(() => { for (let i = 0; i < 1000; i++) db.prepare("INSERT INTO backup_probe VALUES (zeroblob(5000))").run(); }); seed();
  const writer = command(["tests/integration/sqlite-worker.mjs", "writes"]);
  for (let i = 0; i < 100 && !writer.output.includes("WRITING"); i++) await new Promise((resolve) => setTimeout(resolve, 10));
  expect(writer.output).toContain("WRITING");
  try { await backupDatabase(db, join(folder, "concurrent.sqlite")); expect((await writer.done).code).toBe(0); }
  finally { if (writer.child.exitCode === null) writer.child.kill(); await writer.done; }
  const copy = openDatabase(databaseSettings({ APP_MODE: "server", SQLITE_PATH: join(folder, "concurrent.sqlite") }));
  try { assertIntegrity(copy, true); expect((copy.prepare("SELECT counter FROM _health").get() as { counter: number }).counter).toBeGreaterThanOrEqual(0); }
  finally { copy.close(); }
});
it("never overwrites the live DB or an existing snapshot during restore/backup", async () => {
  const snapshot = join(folder, "snapshot.sqlite"); await backupDatabase(db, snapshot);
  await expect(restoreDatabase(snapshot, path)).rejects.toBeDefined();
  await expect(backupDatabase(db, snapshot)).rejects.toBeDefined(); assertIntegrity(db, true);
});
it("detects corruption, returns safe 503 and recovers from an actual backup", async () => {
  const snapshot = join(folder, "good.sqlite"); sqlInsert("saved"); await backupDatabase(db, snapshot);
  db.close(); writeFileSync(path, "corrupt-not-a-database");
  process.env.APP_MODE = "server"; process.env.SQLITE_PATH = path;
  const response = await databaseHealth(); expect(response.status).toBe(503); expect(await response.text()).toBe('{"status":"unavailable"}');
  rmSync(path); await restoreDatabase(snapshot, path);
  expect((await databaseHealth()).status).toBe(200);
  db = openDatabase(databaseSettings(env())); expect(db.prepare("SELECT id FROM bookings").all()).toEqual([{ id: "saved" }]);
});
it("reports a real SQLITE_FULL write error and preserves previously committed data", () => {
  sqlInsert("preserved"); db.exec("CREATE TABLE fill_probe(payload BLOB)");
  db.pragma(`max_page_count=${db.pragma("page_count", { simple: true })}`);
  try { db.prepare("INSERT INTO fill_probe VALUES (zeroblob(1000000))").run(); throw new Error("Expected SQLITE_FULL"); } catch (error) { expect(error).toMatchObject({ code: "SQLITE_FULL" }); }
  expect(db.prepare("SELECT id FROM bookings").get()).toEqual({ id: "preserved" });
  assertIntegrity(db, true);
});
it("rejects symlink/hardlink databases and does not create a missing runtime DB", async () => {
  const alias = join(folder, "alias.sqlite"); symlinkSync(path, alias);
  expect(() => openDatabase(databaseSettings({ APP_MODE: "server", SQLITE_PATH: alias }))).toThrow("DATABASE_UNAVAILABLE");
  rmSync(alias); linkSync(path, alias);
  expect(() => openDatabase(databaseSettings(env()))).toThrow("DATABASE_UNAVAILABLE"); rmSync(alias);
  const missing = join(folder, "missing.sqlite"); process.env.APP_MODE = "server"; process.env.SQLITE_PATH = missing;
  expect((await databaseHealth()).status).toBe(503); expect(existsSync(missing)).toBe(false);
});
