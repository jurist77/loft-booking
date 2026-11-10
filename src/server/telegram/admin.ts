import "server-only";
import type Database from "better-sqlite3";
import { createInvite, enqueueTest, getRecipient, revokeRecipient, setRecipientActive, setTelegramEnabled, TelegramModelError } from "./model.ts";
import { expireTelegramJobs } from "./worker.ts";

export type TelegramPrincipal = { authenticated: boolean; subject: string; permissions: readonly string[] };
export type TelegramAuthorizer = () => Promise<TelegramPrincipal | null>;
/** Future UI must supply a verifier for a REAL server session, never client JSON/Telegram IDs. No HTTP transport is exposed. */
export class TelegramAdministration {
  private readonly db: Database.Database;
  private readonly authorize?: TelegramAuthorizer;
  private readonly clock: () => number;
  constructor(db: Database.Database, authorize?: TelegramAuthorizer, clock: () => number = Date.now) {
    this.db = db; this.authorize = authorize; this.clock = clock;
  }
  private async allowed() {
    let principal: TelegramPrincipal | null | undefined;
    try { principal = await this.authorize?.(); } catch { throw new TelegramModelError("AUTHORIZATION_REQUIRED"); }
    if (principal?.authenticated !== true || typeof principal.subject !== "string" || !principal.subject || !Array.isArray(principal.permissions) || !principal.permissions.includes("telegram:manage")) throw new TelegramModelError("AUTHORIZATION_REQUIRED");
  }
  async recipients() { await this.allowed(); return this.db.prepare("SELECT * FROM telegram_recipients ORDER BY created_at,id").all(); }
  async status() { await this.allowed(); expireTelegramJobs(this.db, this.clock()); return this.db.prepare("SELECT enabled,last_error,last_error_at FROM telegram_state WHERE id=1").get(); }
  async invite(name: string) { await this.allowed(); return createInvite(this.db, name, this.clock()); }
  async renew(id: string) { await this.allowed(); return createInvite(this.db, getRecipient(this.db, id).display_name, this.clock(), id); }
  async active(id: string, active: boolean) { await this.allowed(); if (typeof active !== "boolean") throw new TelegramModelError("INVALID_INPUT"); setRecipientActive(this.db, id, active, this.clock()); }
  async revoke(id: string) { await this.allowed(); revokeRecipient(this.db, id, this.clock()); }
  async enabled(enabled: boolean) { await this.allowed(); if (typeof enabled !== "boolean") throw new TelegramModelError("INVALID_INPUT"); setTelegramEnabled(this.db, enabled); }
  async test(id: string) { await this.allowed(); return enqueueTest(this.db, id, this.clock()); }
  async deliveries(offset = 0) {
    await this.allowed(); if (!Number.isSafeInteger(offset) || offset < 0) throw new TelegramModelError("INVALID_INPUT");
    expireTelegramJobs(this.db, this.clock());
    // Pagination, not a limit on recipient count. No payload or client contacts.
    return this.db.prepare("SELECT id,booking_id,recipient_id,kind,status,attempts,created_at,deadline_at,sent_at,finished_at,last_error FROM telegram_outbox ORDER BY created_at DESC,id LIMIT 100 OFFSET ?").all(offset);
  }
}
