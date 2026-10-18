import { resolve } from "node:path";
import { databaseSettings } from "../src/server/config.ts";
import { initializeDatabase, openDatabase, checkDatabase, assertIntegrity } from "../src/server/database.ts";
import { migrate, MigrationError } from "../src/server/migrations.ts";
import { backupDatabase, restoreDatabase } from "../src/server/backup.ts";

let db;
try {
  const [command, flag, file, ...extra] = process.argv.slice(2);
  const settings = databaseSettings();
  if (extra.length || (!["backup", "restore"].includes(command) && (flag || file))) throw new Error();
  if (command === "init") { initializeDatabase(settings); console.log("SQLite initialized; existing data preserved"); }
  else if (command === "restore" && flag === "--from" && file) {
    await restoreDatabase(file, settings.path); console.log("SQLite restored to a NEW database; integrity verified");
  } else {
    db = openDatabase(settings);
    if (command === "migrate") console.log(`Applied migrations: ${(await migrate(db, resolve(process.env.MIGRATIONS_DIR || "migrations/sqlite"))).length}`);
    else if (command === "check") { assertIntegrity(db, true); checkDatabase(db); console.log("SQLite integrity and committed write: ready"); }
    else if (command === "backup" && flag === "--to" && file) { await backupDatabase(db, file); console.log("SQLite online backup: ready; integrity verified"); }
    else throw new Error();
  }
} catch (error) {
  console.error(`Database command failed: ${error instanceof MigrationError ? error.code : "DATABASE_OPERATION_FAILED"}`);
  process.exitCode = 1;
} finally { db?.close(); }
