// Test-only direct SQL; no booking API is exposed by the application.
import { databaseSettings } from "../../src/server/config.ts";
import { openDatabase } from "../../src/server/database.ts";
const db = openDatabase(databaseSettings());
try {
  const [command, id, start, end] = process.argv.slice(2);
  if (command === "reserve") db.prepare("INSERT INTO bookings(id, starts_at, ends_at) VALUES (?, ?, ?)").run(id, Number(start), Number(end));
  else if (command === "commit-and-wait") {
    db.prepare("INSERT INTO bookings(id, starts_at, ends_at) VALUES (?, ?, ?)").run(id, Number(start), Number(end));
    process.stdout.write("COMMITTED\n");
    await new Promise((resolve) => process.stdin.once("data", resolve));
  } else if (command === "lock") {
    db.exec("BEGIN IMMEDIATE"); process.stdout.write("LOCKED\n");
    await new Promise((resolve) => process.stdin.once("data", resolve));
    db.exec("COMMIT"); process.stdin.pause();
  } else if (command === "writes") {
    process.stdout.write("WRITING\n");
    for (let i = 0; i < 50; i++) { db.prepare("UPDATE _health SET counter = counter + 1 WHERE id=1").run(); await new Promise((resolve) => setTimeout(resolve, 2)); }
  } else throw new Error();
} catch (error) {
  console.error(error.code === "SQLITE_CONSTRAINT_TRIGGER" ? "CONFLICT" : "SQLITE_TEST_OPERATION_FAILED"); process.exitCode = 1;
} finally { db.close(); }
