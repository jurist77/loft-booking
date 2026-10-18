import "server-only";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Pool } from "pg";

export const MIGRATION_LOCK = 192500210;
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

export async function migrate(pool: Pool, directory: string): Promise<number[]> {
  const files = await migrationFiles(directory);
  const client = await pool.connect().catch(() => { throw new MigrationError("MIGRATION_FAILED"); });
  let locked = false; let transaction = false;
  try {
    const lock = await client.query<{ locked: boolean }>("SELECT pg_try_advisory_lock($1::bigint) AS locked", [MIGRATION_LOCK]);
    if (!lock.rows[0].locked) throw new MigrationError("MIGRATION_LOCKED");
    locked = true;
    await client.query("BEGIN"); transaction = true;
    await client.query(`CREATE TABLE IF NOT EXISTS studio.schema_migrations (
      version bigint PRIMARY KEY CHECK (version > 0),
      name text NOT NULL UNIQUE, checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
      applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
    )`);
    const history = await client.query<{ version: string; name: string; checksum: string }>("SELECT version, name, checksum FROM studio.schema_migrations ORDER BY version");
    for (const [index, row] of history.rows.entries()) {
      const file = files[index];
      if (!file || Number(row.version) !== file.version || row.name !== file.name || row.checksum !== file.checksum) throw new MigrationError("HISTORY_MISMATCH");
    }
    const applied = [];
    for (const file of files.slice(history.rows.length)) {
      await client.query(file.sql);
      await client.query("INSERT INTO studio.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)", [file.version, file.name, file.checksum]);
      applied.push(file.version);
    }
    await client.query("COMMIT"); transaction = false;
    return applied;
  } catch (error) {
    if (transaction) await client.query("ROLLBACK").catch(() => {});
    throw error instanceof MigrationError ? error : new MigrationError("MIGRATION_FAILED");
  } finally {
    // Destroy this session if unlocking failed; session locks must never return to a pool.
    let broken = false;
    if (locked) await client.query("SELECT pg_advisory_unlock($1::bigint)", [MIGRATION_LOCK]).catch(() => { broken = true; });
    client.release(broken);
  }
}
