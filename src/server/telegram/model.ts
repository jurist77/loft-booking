import "server-only";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import type { TelegramUpdate } from "./client.ts";

export const DELIVERY_WINDOW = 86400000;
export class TelegramModelError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; this.name = "TelegramModelError"; }
}
export type TelegramState = { enabled: number; bot_id: string | null; bot_username: string | null; update_offset: number; worker_owner: string | null; worker_until: number; next_send_at: number };
export type Recipient = { id: string; display_name: string; telegram_user_id: string | null; chat_id: string | null; connection_status: "invited" | "connected" | "revoked"; active: number; created_at: number; updated_at: number };
export function telegramState(db: Database.Database): TelegramState { return db.prepare("SELECT * FROM telegram_state WHERE id=1").get() as TelegramState; }
export const digestToken = (value: string) => createHash("sha256").update(value).digest("hex");
export function telegramTransaction<T>(db: Database.Database, work: () => T): T {
  if (db.inTransaction) throw new TelegramModelError("TRANSACTION_ACTIVE");
  try { return db.transaction(work).immediate(); }
  catch (error) { if (error instanceof TelegramModelError) throw error; throw new TelegramModelError("TELEGRAM_STORAGE_UNAVAILABLE"); }
}
export function getRecipient(db: Database.Database, id: string): Recipient {
  const value = db.prepare("SELECT * FROM telegram_recipients WHERE id=?").get(id) as Recipient | undefined;
  if (!value) throw new TelegramModelError("RECIPIENT_NOT_FOUND"); return value;
}
export function createInvite(db: Database.Database, name: string, now: number, recipientId?: string, owner = false) {
  if (typeof name !== "string" || !name.trim() || name.trim().length > 100 || /[\p{Cc}\p{Cf}]/u.test(name)) throw new TelegramModelError("INVALID_RECIPIENT_NAME");
  return telegramTransaction(db, () => {
    const state = telegramState(db);
    if (!state.bot_username) throw new TelegramModelError("BOT_NOT_READY");
    if (owner && (db.prepare("SELECT owner_recipient_id FROM telegram_state WHERE id=1").get() as { owner_recipient_id: string | null }).owner_recipient_id) throw new TelegramModelError("OWNER_ALREADY_BOOTSTRAPPED");
    const id = recipientId ?? randomUUID();
    if (recipientId) {
      getRecipient(db, id);
      db.prepare("UPDATE telegram_recipients SET display_name=?,active=1,connection_status='invited',telegram_user_id=NULL,chat_id=NULL,updated_at=? WHERE id=?").run(name.trim(), now, id);
      db.prepare("UPDATE telegram_invitations SET revoked_at=? WHERE recipient_id=? AND used_at IS NULL AND revoked_at IS NULL").run(now, id);
    } else db.prepare("INSERT INTO telegram_recipients(id,display_name,created_at,updated_at) VALUES (?,?,?,?)").run(id, name.trim(), now, now);
    const token = randomBytes(32).toString("base64url"); const expiresAt = now + 3600000;
    db.prepare("INSERT INTO telegram_invitations(token_hash,recipient_id,created_at,expires_at) VALUES (?,?,?,?)").run(digestToken(token), id, now, expiresAt);
    if (owner) db.prepare("UPDATE telegram_state SET owner_recipient_id=? WHERE id=1").run(id);
    return { recipientId: id, link: `https://t.me/${state.bot_username}?start=${token}`, expiresAt };
  });
}
export function setRecipientActive(db: Database.Database, id: string, active: boolean, now: number) {
  return telegramTransaction(db, () => {
    const r = getRecipient(db, id); if (active && r.connection_status === "revoked") throw new TelegramModelError("INVITATION_REQUIRED");
    db.prepare("UPDATE telegram_recipients SET active=?,updated_at=? WHERE id=?").run(active ? 1 : 0, now, id);
  });
}
export function revokeRecipient(db: Database.Database, id: string, now: number) {
  return telegramTransaction(db, () => {
    getRecipient(db, id);
    db.prepare("UPDATE telegram_recipients SET active=0,connection_status='revoked',updated_at=? WHERE id=?").run(now, id);
    db.prepare("UPDATE telegram_invitations SET revoked_at=? WHERE recipient_id=? AND revoked_at IS NULL AND used_at IS NULL").run(now, id);
  });
}
export function setTelegramEnabled(db: Database.Database, enabled: boolean) { telegramTransaction(db, () => db.prepare("UPDATE telegram_state SET enabled=? WHERE id=1").run(enabled ? 1 : 0)); }
export function enqueueTest(db: Database.Database, recipientId: string, now: number) {
  return telegramTransaction(db, () => {
    const r = getRecipient(db, recipientId);
    if (!r.active || r.connection_status !== "connected" || !telegramState(db).enabled) throw new TelegramModelError("RECIPIENT_OR_NOTIFICATIONS_DISABLED");
    const id = randomUUID();
    db.prepare("INSERT INTO telegram_outbox(id,kind,recipient_id,created_at,deadline_at,next_attempt_at) VALUES (?,'test',?,?,?,?)").run(id, recipientId, now, now + DELIVERY_WINDOW, now); return id;
  });
}
export function registerBot(db: Database.Database, bot: { id: number; username: string }) {
  if (!bot || !Number.isSafeInteger(bot.id) || bot.id <= 0 || typeof bot.username !== "string" || !/^[A-Za-z][A-Za-z0-9_]{4,31}$/.test(bot.username)) throw new TelegramModelError("INVALID_BOT_RESPONSE");
  telegramTransaction(db, () => {
    const state = telegramState(db);
    if (state.bot_id !== null && state.bot_id !== String(bot.id)) throw new TelegramModelError("BOT_CHANGED_RELINK_REQUIRED");
    db.prepare("UPDATE telegram_state SET bot_id=?,bot_username=?,last_error=NULL,last_error_at=NULL WHERE id=1").run(String(bot.id), bot.username);
  });
}
export function acquireWorker(db: Database.Database, owner: string, now: number): boolean {
  return telegramTransaction(db, () => db.prepare("UPDATE telegram_state SET worker_owner=?,worker_until=? WHERE id=1 AND (worker_owner=? OR worker_until<=?)").run(owner, now + 60000, owner, now).changes === 1);
}
export function ownsWorker(db: Database.Database, owner: string, now: number) { const s = telegramState(db); return s.worker_owner === owner && s.worker_until > now; }
export function acceptUpdates(db: Database.Database, owner: string, updates: TelegramUpdate[], now: number) {
  if (!Array.isArray(updates) || updates.length > 50) throw new TelegramModelError("INVALID_UPDATE_RESPONSE");
  for (const update of updates) telegramTransaction(db, () => {
    if (!ownsWorker(db, owner, now)) throw new TelegramModelError("WORKER_LEASE_LOST");
    if (!Number.isSafeInteger(update?.update_id) || update.update_id < 0 || !Number.isSafeInteger(update.update_id+1)) throw new TelegramModelError("INVALID_UPDATE_RESPONSE");
    if (update.update_id < telegramState(db).update_offset) return;
    const message = update.message; const user = message?.from?.id; const chat = message?.chat?.id;
    const token = typeof message?.text === "string" ? /^\/start ([A-Za-z0-9_-]{43})$/.exec(message.text)?.[1] : undefined;
    if (token && Number.isSafeInteger(user) && Number(user) > 0 && user === chat && message?.chat?.type === "private" && message.from?.is_bot === false) {
      const sender = digestToken(String(user));
      db.prepare(`INSERT INTO telegram_invite_limits(sender_hash,window_at,attempts) VALUES (?,?,1)
        ON CONFLICT(sender_hash) DO UPDATE SET attempts=CASE WHEN window_at<=?-60000 THEN 1 ELSE attempts+1 END,
        window_at=CASE WHEN window_at<=?-60000 THEN ? ELSE window_at END`).run(sender, now, now, now, now);
      const limit = db.prepare("SELECT attempts FROM telegram_invite_limits WHERE sender_hash=?").get(sender) as { attempts: number };
      if (limit.attempts <= 10) {
        const invite = db.prepare(`SELECT i.recipient_id FROM telegram_invitations i JOIN telegram_recipients r ON r.id=i.recipient_id
          WHERE i.token_hash=? AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>? AND r.active=1 AND r.connection_status='invited'`).get(digestToken(token), now) as { recipient_id: string } | undefined;
        const bound = db.prepare("SELECT id FROM telegram_recipients WHERE telegram_user_id=? OR chat_id=?").get(String(user), String(chat));
        if (invite && !bound) {
          db.prepare("UPDATE telegram_recipients SET telegram_user_id=?,chat_id=?,connection_status='connected',updated_at=? WHERE id=?").run(String(user), String(chat), now, invite.recipient_id);
          db.prepare("UPDATE telegram_invitations SET used_at=? WHERE token_hash=?").run(now, digestToken(token));
        }
      }
    }
    db.prepare("UPDATE telegram_state SET update_offset=? WHERE id=1").run(update.update_id + 1);
    db.prepare("DELETE FROM telegram_invite_limits WHERE window_at<?").run(now - 3600000);
  });
}
