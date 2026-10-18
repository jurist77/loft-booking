import { resolve } from "node:path";
import { databaseSettings } from "../src/server/config.ts";
import { createDatabasePool } from "../src/server/database.ts";
import { migrate, MigrationError } from "../src/server/migrations.ts";

let pool;
try {
  pool = createDatabasePool(databaseSettings(process.env, true));
  const applied = await migrate(pool, resolve(process.env.MIGRATIONS_DIR || "migrations"));
  console.log(`Applied migrations: ${applied.length}`);
} catch (error) {
  console.error(`Migration failed: ${error instanceof MigrationError ? error.code : "INVALID_CONFIGURATION_OR_CONNECTION"}`);
  process.exitCode = 1;
} finally { await pool?.end(); }
