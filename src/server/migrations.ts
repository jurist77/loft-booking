import "server-only";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type Database from "better-sqlite3";

type MigrationCode = "INVALID_FILES" | "HISTORY_MISMATCH" | "MIGRATION_LOCKED" | "MIGRATION_FAILED";
export class MigrationError extends Error {
  readonly code: MigrationCode;
  constructor(code: MigrationCode) {
    super(code); this.name = "MigrationError"; this.code = code;
  }
}

export async function migrationFiles(directory: string) {
  try {
    const files = (await readdir(directory, { withFileTypes: true })).filter((entry) => entry.name.endsWith(".sql")).sort((a, b) => a.name.localeCompare(b.name));
    if (!files.length) throw new MigrationError("INVALID_FILES");
    return await Promise.all(files.map(async (entry, index) => {
      const match = /^(\d{4})_[a-z0-9_]+\.sql$/.exec(entry.name);
      if (!entry.isFile() || !match || Number(match[1]) !== index + 1) throw new MigrationError("INVALID_FILES");
      const sql = await readFile(join(directory, entry.name), "utf8");
      return { version: index + 1, name: entry.name, checksum: createHash("sha256").update(sql).digest("hex"), sql };
    }));
  } catch (error) { throw error instanceof MigrationError ? error : new MigrationError("INVALID_FILES"); }
}

export async function migrate(db: Database.Database, directory: string): Promise<number[]> {
  const files = await migrationFiles(directory);
  try {
    return db.transaction(() => {
      db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY CHECK (version > 0),
        name TEXT NOT NULL UNIQUE, checksum TEXT NOT NULL CHECK (length(checksum) = 64),
        applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      ) STRICT`);
      const history = db.prepare("SELECT version, name, checksum FROM schema_migrations ORDER BY version").all() as { version: number; name: string; checksum: string }[];
      for (const [index, row] of history.entries()) {
        const file = files[index];
        if (!file || row.version !== file.version || row.name !== file.name || row.checksum !== file.checksum) throw new MigrationError("HISTORY_MISMATCH");
      }
      const applied = [];
      for (const file of files.slice(history.length)) {
        db.exec(file.sql);
        db.prepare("INSERT INTO schema_migrations (version, name, checksum) VALUES (?, ?, ?)").run(file.version, file.name, file.checksum);
        applied.push(file.version);
      }
      return applied;
    }).immediate();
  } catch (error) {
    if (error instanceof MigrationError) throw error;
    throw new MigrationError((error as { code?: string }).code?.startsWith("SQLITE_BUSY") ? "MIGRATION_LOCKED" : "MIGRATION_FAILED");
  }
}
