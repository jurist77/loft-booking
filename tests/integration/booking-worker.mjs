// Independent real SQLite writers. Fixtures are synthetic; output contains no contacts.
import { databaseSettings } from "../../src/server/config.ts";
import { openDatabase } from "../../src/server/database.ts";
import { createBooking } from "../../src/server/bookings.ts";
const db = openDatabase(databaseSettings());
try {
  const [mode, id, resourceId = "studio-19-25", start = "600", end = "660"] = process.argv.slice(2);
  process.stdout.write("READY\n");
  await new Promise((resolve) => process.stdin.once("data", resolve));
  const input = { id, resourceId, date: "2030-01-15", start: Number(start), end: Number(end), firstName: "Тест", lastName: "Пример", phone: "+79000000000" };
  if (mode === "uncommitted") {
    db.exec("BEGIN IMMEDIATE");
    db.prepare(`INSERT INTO bookings(id, resource_id, starts_at, ends_at, first_name, last_name, phone, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)`).run(id, resourceId, Date.parse("2030-01-15T10:00:00+03:00"), Date.parse("2030-01-15T11:00:00+03:00"), input.firstName, input.lastName, input.phone);
    process.stdout.write("UNCOMMITTED\n");
    await new Promise((resolve) => process.stdin.once("data", resolve));
    db.exec("ROLLBACK");
  } else {
    createBooking(db, input, new Date("2030-01-15T08:00:00+03:00"));
    process.stdout.write("COMMITTED\n");
    if (mode === "committed") await new Promise((resolve) => process.stdin.once("data", resolve));
  }
} catch (error) {
  console.error(error.name === "BookingModelError" ? error.code : "BOOKING_WORKER_FAILED"); process.exitCode = 1;
} finally { db.close(); process.stdin.pause(); }
