// Service tool only: fingerprint schema/history, never customer rows.
import { createHash } from "node:crypto";
import { databaseSettings } from "../../src/server/config.ts";
import { openDatabase } from "../../src/server/database.ts";
const db = openDatabase(databaseSettings());
try {
  const schema = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").all();
  const history = db.prepare("SELECT version,name,checksum FROM schema_migrations ORDER BY version").all();
  console.log(createHash("sha256").update(JSON.stringify({ schema, history })).digest("hex"));
} finally { db.close(); }
