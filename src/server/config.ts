import "server-only";
import { appMode } from "../lib/app-mode.ts";

type Env = Record<string, string | undefined>;
export type DatabaseSettings = { connectionString: string; max: number; connectTimeout: number; queryTimeout: number };

export class ConfigurationError extends Error {
  constructor() { super("Invalid server database configuration"); this.name = "ConfigurationError"; }
}

function integer(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new ConfigurationError();
  return parsed;
}

export function databaseSettings(env: Env = process.env, migration = false): DatabaseSettings {
  if (appMode(env.APP_MODE) !== "server") throw new ConfigurationError();
  const connectionString = migration ? env.MIGRATION_DATABASE_URL : env.DATABASE_URL;
  try {
    const url = new URL(connectionString || "");
    if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname || !url.username || !url.password || url.pathname.length < 2) throw new ConfigurationError();
    if (["no-verify", "prefer", "allow"].includes(url.searchParams.get("sslmode") || "")) throw new ConfigurationError();
  } catch { throw new ConfigurationError(); }
  return {
    connectionString: connectionString!,
    max: migration ? 1 : integer(env.DB_POOL_MAX, 5, 1, 20),
    connectTimeout: integer(env.DB_CONNECT_TIMEOUT_MS, 2000, 100, 30000),
    queryTimeout: migration ? integer(env.MIGRATION_QUERY_TIMEOUT_MS, 30000, 100, 300000) : integer(env.DB_QUERY_TIMEOUT_MS, 2000, 100, 30000),
  };
}
