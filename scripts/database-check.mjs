import { databaseSettings } from "../src/server/config.ts";
import { createDatabasePool } from "../src/server/database.ts";

let pool;
try {
  pool = createDatabasePool(databaseSettings());
  await pool.query("SELECT 1 AS ok");
  console.log("PostgreSQL connection: ready");
} catch {
  console.error("PostgreSQL connection: unavailable; check local configuration and container health");
  process.exitCode = 1;
} finally { await pool?.end(); }
