import "server-only";
import Database from "better-sqlite3";
import { closeSync, constants, lstatSync, mkdirSync, openSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { databaseSettings, type DatabaseSettings } from "./config.ts";

export class DatabaseError extends Error {
  constructor() { super("DATABASE_UNAVAILABLE"); this.name = "DatabaseError"; }
}

export function privateDirectory(directory: string, create = false): void {
  if (create) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const info = lstatSync(directory);
  if (!info.isDirectory() || realpathSync(directory) !== resolve(directory) || (info.mode & 0o077) || !(info.mode & 0o200) || info.uid !== process.getuid?.()) throw new DatabaseError();
}
export function privateFile(file: string): string {
  privateDirectory(dirname(file));
  const info = lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o077) || !(info.mode & 0o200) || info.uid !== process.getuid?.()) throw new DatabaseError();
  return `${info.dev}:${info.ino}`;
}
export function reservePrivateFile(file: string): void {
  privateDirectory(dirname(file), true);
  closeSync(openSync(file, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600));
}

export function assertIntegrity(db: Database.Database, full = false): void {
  const check = db.pragma(full ? "integrity_check" : "quick_check(1)", { simple: true });
  if (check !== "ok" || (db.pragma("foreign_key_check") as unknown[]).length) throw new DatabaseError();
}
export function openDatabase(settings: DatabaseSettings): Database.Database {
  let db: Database.Database | undefined;
  try {
    privateFile(settings.path);
    for (const suffix of ["-wal", "-shm"]) {
      try { lstatSync(settings.path + suffix); privateFile(settings.path + suffix); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    db = new Database(settings.path, { fileMustExist: true, timeout: settings.busyTimeout });
    if (db.pragma("journal_mode = WAL", { simple: true }) !== "wal") throw new DatabaseError();
    db.pragma("synchronous = FULL"); db.pragma("foreign_keys = ON"); db.pragma("trusted_schema = OFF");
    assertIntegrity(db);
    return db;
  } catch { try { db?.close(); } catch {} throw new DatabaseError(); }
}
export function initializeDatabase(settings: DatabaseSettings): void {
  try {
    try { reservePrivateFile(settings.path); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    openDatabase(settings).close();
  } catch { throw new DatabaseError(); }
}

type Handle = { db: Database.Database; identity: string; path: string; busyTimeout: number };
const registry = globalThis as typeof globalThis & { studioDatabase?: Handle };
export function closeDatabase(): void {
  const previous = registry.studioDatabase; delete registry.studioDatabase;
  try { if (previous?.db.open) previous.db.close(); } catch {}
}
export function getDatabase(): Database.Database {
  try {
    const settings = databaseSettings();
    const identity = privateFile(settings.path);
    const previous = registry.studioDatabase;
    if (!previous || previous.identity !== identity || previous.path !== settings.path || previous.busyTimeout !== settings.busyTimeout) {
      closeDatabase();
      registry.studioDatabase = { db: openDatabase(settings), identity, ...settings };
    }
    // Also reject chmod/removal of the directory or database while a cached FD is still open.
    return registry.studioDatabase!.db;
  } catch { closeDatabase(); throw new DatabaseError(); }
}
export function checkDatabase(db: Database.Database): void {
  assertIntegrity(db);
  // A committed tiny write detects readonly/full/I/O failures, unlike SELECT 1 alone.
  const result = db.prepare("UPDATE _health SET counter = (counter + 1) % 1000000 WHERE id = 1").run();
  if (result.changes !== 1) throw new DatabaseError();
}
