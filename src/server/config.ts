import "server-only";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { appMode } from "../lib/app-mode.ts";

type Env = Record<string, string | undefined>;
export type DatabaseSettings = { path: string; busyTimeout: number };
export class ConfigurationError extends Error {
  constructor() { super("Invalid server database configuration"); this.name = "ConfigurationError"; }
}

export function privateDatabasePath(path: string | undefined): string {
  if (!path || !isAbsolute(path) || !path.endsWith(".sqlite")) throw new ConfigurationError();
  const normalized = resolve(path);
  const fromProject = relative(process.cwd(), normalized);
  if (!fromProject.startsWith(`..${sep}`)) throw new ConfigurationError();
  return normalized;
}

export function databaseSettings(env: Env = process.env): DatabaseSettings {
  if (appMode(env.APP_MODE) !== "server") throw new ConfigurationError();
  const busyTimeout = env.SQLITE_BUSY_TIMEOUT_MS === undefined ? 1000 : Number(env.SQLITE_BUSY_TIMEOUT_MS);
  if (!Number.isSafeInteger(busyTimeout) || busyTimeout < 50 || busyTimeout > 5000) throw new ConfigurationError();
  return { path: privateDatabasePath(env.SQLITE_PATH), busyTimeout };
}
