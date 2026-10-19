import { afterEach, beforeEach, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import type Database from "better-sqlite3";
import { databaseSettings } from "../../src/server/config";
import { assertIntegrity, initializeDatabase, openDatabase } from "../../src/server/database";
import { migrate } from "../../src/server/migrations";
import { backupDatabase, restoreDatabase } from "../../src/server/backup";
import { BookingModelError, cancelBooking, createBooking, STUDIO_RESOURCE_ID, type CreateBookingInput } from "../../src/server/bookings";

const migrations = resolve("migrations/sqlite");
const now = new Date("2030-01-15T08:00:00+03:00");
const input = (overrides: Partial<CreateBookingInput> = {}): CreateBookingInput => ({ id: "test-booking", resourceId: STUDIO_RESOURCE_ID, date: "2030-01-15", start: 600, end: 660, firstName: "Тест", lastName: "Пример", phone: "+79000000000", ...overrides });
let folder: string; let path: string; let db: Database.Database;
const folders: string[] = [];
const settings = () => databaseSettings({ APP_MODE: "server", SQLITE_PATH: path });
const events = () => db.prepare("SELECT booking_id, event_type, occurred_at FROM booking_events ORDER BY id").all();
const count = () => db.prepare("SELECT count(*) AS n FROM bookings").get();
const otherResource = () => db.prepare("INSERT INTO resources VALUES ('test-room', 'Вымышленное помещение')").run();
function worker(mode: string, id: string, resource = STUDIO_RESOURCE_ID, start = 600, end = 660) {
  const child = spawn(process.execPath, ["--conditions=react-server", "tests/integration/booking-worker.mjs", mode, id, resource, String(start), String(end)], { env: { ...process.env, APP_MODE: "server", SQLITE_PATH: path }, stdio: ["pipe", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; }); child.stderr.on("data", (chunk) => { output += chunk; });
  const done = new Promise<{ code: number | null; output: string }>((resolve, reject) => { child.once("error", reject); child.once("close", (code) => resolve({ code, output })); });
  return { child, done, get output() { return output; } };
}
async function ready(writer: ReturnType<typeof worker>, text = "READY") {
  for (let i = 0; i < 200 && !writer.output.includes(text); i++) {
    if (writer.child.exitCode !== null) break;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  expect(writer.output).toContain(text);
}
async function race(requests: [string, string?, number?, number?][]) {
  const writers = requests.map(([id, resource, start, end]) => worker("create", id, resource, start, end));
  try {
    await Promise.all(writers.map((writer) => ready(writer)));
    for (const writer of writers) writer.child.stdin.write("go");
    return await Promise.all(writers.map((writer) => writer.done));
  } finally {
    for (const writer of writers) if (writer.child.exitCode === null && writer.child.signalCode === null) writer.child.kill("SIGKILL");
    await Promise.all(writers.map((writer) => writer.done));
  }
}
async function oldManifest(brokenUpgrade = false) {
  const directory = mkdtempSync(join(tmpdir(), "studio-booking-manifest-")); folders.push(directory);
  writeFileSync(join(directory, "0001_foundation.sql"), readFileSync(join(migrations, "0001_foundation.sql")));
  if (brokenUpgrade) writeFileSync(join(directory, "0002_booking_model.sql"), readFileSync(join(migrations, "0002_booking_model.sql"), "utf8") + "\nSELECT missing_function();\n");
  return directory;
}
async function legacyDatabase() {
  db.close(); path = join(folder, "legacy.sqlite"); initializeDatabase(settings()); db = openDatabase(settings());
  await migrate(db, await oldManifest());
  const start = Date.parse("2030-01-15T10:00:00+03:00");
  const insert = db.prepare("INSERT INTO bookings(id, starts_at, ends_at, status) VALUES (?, ?, ?, ?)");
  insert.run("old-confirmed", start, start + 3600000, "confirmed");
  insert.run("old-cancelled", start, start + 3600000, "cancelled");
  return db.prepare("SELECT * FROM bookings ORDER BY id").all() as Record<string, unknown>[];
}
beforeEach(async () => {
  folder = mkdtempSync(join(tmpdir(), "studio-booking-model-")); folders.push(folder); path = join(folder, "test.sqlite");
  initializeDatabase(settings()); db = openDatabase(settings()); await migrate(db, migrations);
});
afterEach(() => { if (db?.open) db.close(); for (const directory of folders.splice(0)) rmSync(directory, { recursive: true, force: true }); });

it("creates a complete confirmed booking and minimal event with normalized contacts", () => {
  const booking = createBooking(db, input({ firstName: " Тест ", phone: "8 (900) 000-00-00" }), now);
  expect(booking).toEqual({ id: "test-booking", resourceId: STUDIO_RESOURCE_ID, startsAt: Date.parse("2030-01-15T10:00:00+03:00"), endsAt: Date.parse("2030-01-15T11:00:00+03:00"), status: "confirmed", firstName: "Тест", lastName: "Пример", phone: "+79000000000", createdAt: now.getTime(), updatedAt: now.getTime() });
  expect(events()).toEqual([{ booking_id: booking.id, event_type: "created", occurred_at: now.getTime() }]);
});
it("rejects same-resource overlaps but allows both adjacent intervals", () => {
  createBooking(db, input(), now);
  expect(() => createBooking(db, input({ id: "overlap", start: 630, end: 690 }), now)).toThrow("BOOKING_OVERLAP");
  createBooking(db, input({ id: "left", start: 540, end: 600 }), now);
  createBooking(db, input({ id: "right", start: 660, end: 720 }), now);
  expect(count()).toEqual({ n: 3 }); expect(events()).toHaveLength(3);
});
it("allows simultaneous intervals for different resources and guards resource updates", () => {
  otherResource(); createBooking(db, input(), now); createBooking(db, input({ id: "other", resourceId: "test-room" }), now);
  expect(() => db.prepare("UPDATE bookings SET resource_id=? WHERE id='other'").run(STUDIO_RESOURCE_ID)).toThrow("BOOKING_OVERLAP");
  expect(count()).toEqual({ n: 2 });
});
it("cancels atomically, preserves history and releases time; repeat cancellation is harmless", () => {
  const first = createBooking(db, input(), now); const later = new Date(now.getTime() + 1000);
  const cancelled = cancelBooking(db, first.id, later);
  expect(cancelled).toEqual({ ...first, status: "cancelled", updatedAt: later.getTime() });
  expect(cancelBooking(db, first.id, new Date(later.getTime() + 1000))).toEqual(cancelled);
  expect(events()).toEqual([{ booking_id: first.id, event_type: "created", occurred_at: now.getTime() }, { booking_id: first.id, event_type: "cancelled", occurred_at: later.getTime() }]);
  createBooking(db, input({ id: "replacement" }), later); expect(count()).toEqual({ n: 2 });
  expect(() => db.prepare("DELETE FROM bookings WHERE id=?").run(first.id)).toThrow();
});
it("replays a stable ID without duplicate events even after cancellation or expiry", () => {
  const booking = createBooking(db, input(), now);
  expect(createBooking(db, input({ phone: "9000000000" }), now)).toEqual(booking);
  expect(createBooking(db, input(), new Date("2031-01-01T12:00:00Z"))).toEqual(booking);
  cancelBooking(db, booking.id, now);
  expect(createBooking(db, input(), now).status).toBe("cancelled");
  expect(count()).toEqual({ n: 1 }); expect(events()).toHaveLength(2);
  expect(() => createBooking(db, input({ end: 690 }), now)).toThrow("BOOKING_ID_CONFLICT");
  expect(() => createBooking(db, input({ lastName: "Другое" }), now)).toThrow("BOOKING_ID_CONFLICT");
});
it("permits independent bookings by one phone with distinct IDs", () => {
  createBooking(db, input(), now); createBooking(db, input({ id: "independent", start: 660, end: 720 }), now);
  expect(count()).toEqual({ n: 2 });
});
it.each([
  { start: 510, end: 570 }, { start: 1350, end: 1410 }, { start: 600, end: 630 },
  { start: 615, end: 675 }, { start: 660, end: 600 }, { start: 540, end: 1980 },
  { date: "2030-01-14" }, { date: "2030-04-16" }, { date: "2030-02-30" },
])("rejects invalid workday/horizon interval %j without writes", (overrides) => {
  expect(() => createBooking(db, input(overrides), now)).toThrow(BookingModelError);
  expect(count()).toEqual({ n: 0 }); expect(events()).toEqual([]);
});
it("accepts the whole 14-hour workday, last hour and inclusive three-month endpoint", () => {
  createBooking(db, input({ id: "whole-day", start: 540, end: 1380 }), now);
  createBooking(db, input({ id: "last-hour", date: "2030-04-15", start: 1320, end: 1380 }), now);
  expect(count()).toEqual({ n: 2 });
});
it("uses Moscow midnight, exact current start and calendar-month clamping", () => {
  const jan31 = new Date("2030-01-30T21:00:00Z"); // Already Jan 31 in Moscow.
  createBooking(db, input({ id: "last-day", date: "2030-04-30" }), jan31);
  expect(() => createBooking(db, input({ id: "outside", date: "2030-05-01" }), jan31)).toThrow("INVALID_INTERVAL");
  const atStart = new Date("2030-01-15T10:00:00+03:00");
  createBooking(db, input({ id: "exact-start" }), atStart);
  expect(() => createBooking(db, input({ id: "past" }), new Date(atStart.getTime() + 1))).toThrow("INVALID_INTERVAL");
});
it.each([{ firstName: "" }, { firstName: "🙂" }, { lastName: "a".repeat(81) }, { phone: "+78000000000" }, { phone: "+79000000000extra" }])("reuses contact validation and rejects invalid details %j", (overrides) => {
  expect(() => createBooking(db, input(overrides), now)).toThrow("INVALID_CONTACT"); expect(events()).toEqual([]);
});
it("rejects unknown resources, malformed IDs/clocks and nested transactions safely", () => {
  expect(() => createBooking(db, input({ resourceId: "missing" }), now)).toThrow("RESOURCE_NOT_FOUND");
  expect(() => createBooking(db, input({ id: " bad " }), now)).toThrow("INVALID_INPUT");
  expect(() => createBooking(db, input(), new Date(NaN))).toThrow("INVALID_INPUT");
  expect(() => cancelBooking(db, "missing", now)).toThrow("BOOKING_NOT_FOUND");
  db.exec("BEGIN IMMEDIATE");
  try { expect(() => createBooking(db, input(), now)).toThrow("TRANSACTION_ACTIVE"); } finally { db.exec("ROLLBACK"); }
  expect(count()).toEqual({ n: 0 });
});
it("requires new row contacts and foreign keys even through direct SQL", () => {
  expect(() => db.prepare("INSERT INTO bookings(id,resource_id,starts_at,ends_at) VALUES ('missing',?,0,3600000)").run(STUDIO_RESOURCE_ID)).toThrow("BOOKING_DETAILS_REQUIRED");
  createBooking(db, input(), now);
  expect(() => db.prepare("UPDATE bookings SET resource_id='unknown'").run()).toThrow();
  expect(() => db.prepare("UPDATE bookings SET phone='+78000000000'").run()).toThrow();
  expect(() => db.prepare("UPDATE bookings SET first_name=NULL").run()).toThrow("BOOKING_DETAILS_REQUIRED");
  expect(() => cancelBooking(db, "test-booking", new Date(now.getTime() - 1))).toThrow("INVALID_INPUT");
});
it("rolls back booking creation when its event insert fails", () => {
  db.exec("CREATE TRIGGER fail_event BEFORE INSERT ON booking_events BEGIN SELECT RAISE(ABORT, 'test-only-secret'); END");
  expect(() => createBooking(db, input(), now)).toThrow(/^STORAGE_FAILURE$/);
  expect(count()).toEqual({ n: 0 }); expect(events()).toEqual([]); expect(db.inTransaction).toBe(false);
  db.exec("DROP TRIGGER fail_event"); createBooking(db, input(), now); expect(count()).toEqual({ n: 1 });
});
it("rolls back cancellation and timestamp when its event insert fails", () => {
  const first = createBooking(db, input(), now);
  db.exec("CREATE TRIGGER fail_cancel BEFORE INSERT ON booking_events WHEN NEW.event_type='cancelled' BEGIN SELECT RAISE(ABORT, 'test-only'); END");
  expect(() => cancelBooking(db, first.id, new Date(now.getTime() + 1000))).toThrow("STORAGE_FAILURE");
  expect(createBooking(db, input(), now)).toEqual(first); expect(events()).toHaveLength(1);
  expect(() => createBooking(db, input({ id: "still-blocked" }), now)).toThrow("BOOKING_OVERLAP");
});
it("reports actual SQLITE_FULL safely and preserves previously confirmed booking/history", () => {
  const first = createBooking(db, input(), now);
  db.exec("CREATE TABLE fill_probe(payload BLOB)");
  db.exec("CREATE TRIGGER fill_disk AFTER INSERT ON bookings BEGIN INSERT INTO fill_probe VALUES (zeroblob(1000000)); END");
  db.pragma(`max_page_count=${db.pragma("page_count", { simple: true })}`);
  expect(() => createBooking(db, input({ id: "disk-full", start: 660, end: 720 }), now)).toThrow(/^STORAGE_FAILURE$/);
  expect(createBooking(db, input(), now)).toEqual(first); expect(events()).toHaveLength(1); expect(count()).toEqual({ n: 1 });
  expect(db.inTransaction).toBe(false); assertIntegrity(db, true);
});
it("serializes competing processes: one interval, one confirmed row and event", async () => {
  const results = await race([["first"], ["second"], ["third"]]);
  expect(results.filter((r) => r.code === 0)).toHaveLength(1);
  expect(results.filter((r) => r.code === 1).every((r) => r.output.includes("BOOKING_OVERLAP"))).toBe(true);
  expect(count()).toEqual({ n: 1 }); expect(events()).toHaveLength(1);
});
it("serializes concurrent retries of the same request without duplicates", async () => {
  const results = await race([["retry"], ["retry"], ["retry"]]);
  expect(results.map((r) => r.code)).toEqual([0, 0, 0]); expect(count()).toEqual({ n: 1 }); expect(events()).toHaveLength(1);
});
it("rejects concurrent reuse of one ID for different payloads", async () => {
  const results = await race([["same-id", STUDIO_RESOURCE_ID, 600, 660], ["same-id", STUDIO_RESOURCE_ID, 660, 720]]);
  expect(results.map((r) => r.code).sort()).toEqual([0, 1]);
  expect(results.find((r) => r.code === 1)?.output).toContain("BOOKING_ID_CONFLICT"); expect(events()).toHaveLength(1);
});
it("allows independent processes to book different resources at once", async () => {
  otherResource(); const results = await race([["studio"], ["room", "test-room"]]);
  expect(results.map((r) => r.code)).toEqual([0, 0]); expect(events()).toHaveLength(2);
});
it("fails with bounded DATABASE_BUSY under a held writer, then recovers", () => {
  const locked = openDatabase({ ...settings(), busyTimeout: 50 }); db.exec("BEGIN IMMEDIATE");
  try { expect(() => createBooking(locked, input(), now)).toThrow(/^DATABASE_BUSY$/); expect(count()).toEqual({ n: 0 }); }
  finally { db.exec("ROLLBACK"); locked.close(); }
  createBooking(db, input(), now); expect(events()).toHaveLength(1);
});
it.each(["uncommitted", "committed"])("survives process death with atomic booking/history: %s", async (mode) => {
  createBooking(db, input({ id: "preserved", start: 720, end: 780 }), now); db.close();
  const writer = worker(mode, "crash-test");
  try {
    await ready(writer); writer.child.stdin.write("go"); await ready(writer, mode === "committed" ? "COMMITTED" : "UNCOMMITTED");
    writer.child.kill("SIGKILL"); await writer.done; expect(writer.child.signalCode).toBe("SIGKILL");
    db = openDatabase(settings()); assertIntegrity(db, true);
    expect(count()).toEqual({ n: mode === "committed" ? 2 : 1 }); expect(events()).toHaveLength(mode === "committed" ? 2 : 1);
    createBooking(db, input({ id: "crash-test" }), now); expect(count()).toEqual({ n: 2 }); expect(events()).toHaveLength(2);
  } finally { if (writer.child.exitCode === null && writer.child.signalCode === null) writer.child.kill("SIGKILL"); await writer.done; }
});
it("preserves full records/history across restart and online backup/restore", async () => {
  const first = createBooking(db, input(), now); cancelBooking(db, first.id, now);
  createBooking(db, input({ id: "replacement" }), now); const savedEvents = events();
  const snapshot = join(folder, "backup.sqlite"); await backupDatabase(db, snapshot); db.close();
  db = openDatabase(settings()); expect(await migrate(db, migrations)).toEqual([]); expect(events()).toEqual(savedEvents);
  const restoredPath = join(folder, "restored.sqlite"); await restoreDatabase(snapshot, restoredPath);
  const restored = openDatabase({ ...settings(), path: restoredPath });
  try { assertIntegrity(restored, true); expect(createBooking(restored, input(), now)).toEqual({ ...first, status: "cancelled" }); expect(restored.prepare("SELECT * FROM booking_events ORDER BY id").all()).toEqual(db.prepare("SELECT * FROM booking_events ORDER BY id").all()); }
  finally { restored.close(); }
});
it("upgrades 0001 without rewriting history, intervals or inventing old contacts/events", async () => {
  const previous = await legacyDatabase(); const history = db.prepare("SELECT * FROM schema_migrations").get();
  expect(await migrate(db, migrations)).toEqual([2]); expect(await migrate(db, migrations)).toEqual([]);
  expect(db.prepare("SELECT * FROM schema_migrations WHERE version=1").get()).toEqual(history);
  for (const row of previous) expect(db.prepare("SELECT * FROM bookings WHERE id=?").get(row.id)).toEqual({ ...row, resource_id: STUDIO_RESOURCE_ID, first_name: null, last_name: null, phone: null, created_at: null, updated_at: null });
  expect(events()).toEqual([]); expect(() => createBooking(db, input(), now)).toThrow("BOOKING_OVERLAP");
  cancelBooking(db, "old-confirmed", now); expect(events()).toEqual([{ booking_id: "old-confirmed", event_type: "cancelled", occurred_at: now.getTime() }]);
  createBooking(db, input(), now); assertIntegrity(db, true);
});
it("rolls back a failed schema rebuild without losing any 0001 rows", async () => {
  const previous = await legacyDatabase();
  await expect(migrate(db, await oldManifest(true))).rejects.toMatchObject({ code: "MIGRATION_FAILED" });
  expect(db.prepare("SELECT * FROM bookings ORDER BY id").all()).toEqual(previous);
  expect(db.prepare("SELECT count(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
  expect(db.prepare("SELECT name FROM sqlite_schema WHERE name IN ('resources','booking_events','bookings_v1')").all()).toEqual([]);
  expect(await migrate(db, migrations)).toEqual([2]); assertIntegrity(db, true);
});
