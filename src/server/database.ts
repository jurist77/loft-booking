import "server-only";
import { Pool } from "pg";
import { databaseSettings, type DatabaseSettings } from "./config.ts";

const registry = globalThis as typeof globalThis & { studioDatabasePool?: Pool };

export function createDatabasePool(settings: DatabaseSettings): Pool {
  const pool = new Pool({
    connectionString: settings.connectionString, max: settings.max,
    connectionTimeoutMillis: settings.connectTimeout, idleTimeoutMillis: 10000,
    query_timeout: settings.queryTimeout, statement_timeout: settings.queryTimeout,
    lock_timeout: Math.min(settings.queryTimeout, 1000),
    application_name: "studio1925", allowExitOnIdle: true,
  });
  // Idle socket errors must not crash the process or expose raw connection details.
  pool.on("error", () => {});
  return pool;
}

export function getDatabasePool(): Pool {
  if (!registry.studioDatabasePool) registry.studioDatabasePool = createDatabasePool(databaseSettings());
  return registry.studioDatabasePool;
}

export async function closeDatabasePool(): Promise<void> {
  const pool = registry.studioDatabasePool;
  delete registry.studioDatabasePool;
  await pool?.end();
}
