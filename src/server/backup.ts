import "server-only";
import Database from "better-sqlite3";
import { closeSync, fsyncSync, linkSync, openSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { privateDatabasePath } from "./config.ts";
import { assertIntegrity, privateFile, reservePrivateFile } from "./database.ts";

// SQLite online backup API includes committed WAL data; never copy the live main file alone.
export async function backupDatabase(db: Database.Database, destination: string): Promise<void> {
  const target = privateDatabasePath(destination);
  const partial = `${target}.${randomUUID()}.partial.sqlite`;
  let created = false;
  try {
    reservePrivateFile(partial); created = true;
    const deadline = Date.now() + 60000;
    await db.backup(partial, { progress() { if (Date.now() > deadline) throw new Error("BACKUP_TIMEOUT"); return 100; } });
    const check = new Database(partial, { readonly: true, fileMustExist: true });
    try { assertIntegrity(check, true); } finally { check.close(); }
    const fd = openSync(partial, "r"); try { fsyncSync(fd); } finally { closeSync(fd); }
    linkSync(partial, target); // atomic, refuses to overwrite an existing backup/database
    unlinkSync(partial); created = false;
    const folder = openSync(dirname(target), "r"); try { fsyncSync(folder); } finally { closeSync(folder); }
  } finally { if (created) { try { unlinkSync(partial); } catch {} } }
}
export async function restoreDatabase(source: string, destination: string): Promise<void> {
  const input = privateDatabasePath(source);
  privateFile(input);
  const db = new Database(input, { readonly: true, fileMustExist: true });
  try { assertIntegrity(db, true); await backupDatabase(db, destination); }
  finally { db.close(); }
}
