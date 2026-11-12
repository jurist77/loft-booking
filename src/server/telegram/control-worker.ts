import "server-only";
import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import type { TelegramMarkup, TelegramResult, TelegramTransport } from "./client.ts";
import { DELIVERY_WINDOW, ownsWorker, telegramState, telegramTransaction, TelegramModelError } from "./model.ts";
import { bootstrapValue, callbackValue, SUBSCRIBE, UNSUBSCRIBE, MANAGE, type ControlPayload } from "./interactions.ts";

type ControlJob = { id: string; recipient_id: string; owner_epoch: number | null; payload: string; attempts: number; deadline_at: number; chat_id: string };
export function renderControl(db: Database.Database, row: ControlJob, key: string, now: number): { text: string; markup?: TelegramMarkup; callbackId?: string } {
  const value = JSON.parse(row.payload) as ControlPayload;
  if (value.callbackId) return { text: "", callbackId: value.callbackId };
  let text = value.text;
  if (value.claimId) {
    const claim = db.prepare("SELECT id FROM telegram_bootstrap_claims WHERE id=? AND recipient_id=? AND used_at IS NULL AND expires_at>?").get(value.claimId, row.recipient_id, now);
    if (!claim) throw new TelegramModelError("BOOTSTRAP_EXPIRED");
    text = "Одноразовое подключение первого владельца Studio 19.25\nКод: " + bootstrapValue(key, value.claimId, row.recipient_id) +
      "\nДействует 15 минут. Передайте код только доверенному техническому администратору для временного GitHub Secret STUDIO_TELEGRAM_OWNER_CONFIRMATION. Не публикуйте его. Сам код и Start не предоставляют права без подтверждения через Actions.";
  }
  if (typeof text !== "string" || text.length > 4096) throw new TelegramModelError("UI_PAYLOAD_LIMIT");
  let markup: TelegramMarkup | undefined;
  if (value.buttons) markup = { inline_keyboard: value.buttons.map((buttons) => buttons.map((b) => ({ text: b.text, callback_data: callbackValue(key, b.action, row.recipient_id) }))) };
  else if (value.keyboard) markup = { keyboard: [[{ text: SUBSCRIBE }], [{ text: UNSUBSCRIBE }], ...(value.keyboard === "owner" ? [[{ text: MANAGE }]] : [])], resize_keyboard: true };
  return { text, markup };
}
export class TelegramControlWorker {
  private readonly db: Database.Database;
  private readonly owner: string;
  private readonly api: TelegramTransport;
  private readonly key: string;
  private readonly clock: () => number;
  private readonly guard: () => void;
  private readonly signal?: AbortSignal;
  constructor(db: Database.Database, owner: string, api: TelegramTransport, key: string,
    clock: () => number = Date.now, guard = () => {}, signal?: AbortSignal) {
    this.db = db; this.owner = owner; this.api = api; this.key = key; this.clock = clock; this.guard = guard; this.signal = signal;
  }

  async dispatch(): Promise<boolean> {
    let job: ControlJob | undefined; let attempt: Promise<TelegramResult<number>> | undefined;
    const claim = randomUUID(); this.guard();
    telegramTransaction(this.db, () => {
      const now = this.clock(); if (!ownsWorker(this.db, this.owner, now)) throw new TelegramModelError("WORKER_LEASE_LOST");
      this.db.prepare("UPDATE telegram_control_outbox SET status='failed',last_error='DELIVERY_EXPIRED',finished_at=?,claim_token=NULL,lease_until=NULL WHERE status IN ('pending','sending') AND deadline_at<=?").run(now, now);
      this.db.prepare("UPDATE telegram_control_outbox SET status='pending',last_error='NETWORK_UNCERTAIN',claim_token=NULL,lease_until=NULL,next_attempt_at=? WHERE status='sending' AND lease_until<=? AND deadline_at>?").run(now, now, now);
      this.db.prepare("DELETE FROM telegram_control_outbox WHERE status IN ('sent','failed','cancelled') AND finished_at<?").run(now - 7 * DELIVERY_WINDOW);
      const state = telegramState(this.db); if (state.next_send_at > now || this.signal?.aborted) return;
      this.db.prepare("UPDATE telegram_control_outbox SET status='cancelled',finished_at=?,claim_token=NULL,lease_until=NULL WHERE status IN ('pending','sending') AND owner_epoch IS NOT NULL AND (owner_epoch<>? OR recipient_id<>coalesce(?,''))").run(now, state.owner_epoch, state.owner_recipient_id);
      job = this.db.prepare(`SELECT o.*,r.chat_id FROM telegram_control_outbox o JOIN telegram_recipients r ON r.id=o.recipient_id
        WHERE o.status='pending' AND o.next_attempt_at<=? AND o.deadline_at>? AND r.chat_id IS NOT NULL ORDER BY o.created_at,o.id LIMIT 1`).get(now, now) as ControlJob | undefined;
      if (!job) return;
      let rendered: ReturnType<typeof renderControl>;
      try { rendered = renderControl(this.db, job, this.key, now); }
      catch { this.db.prepare("UPDATE telegram_control_outbox SET status='cancelled',finished_at=?,last_error='UI_EXPIRED' WHERE id=?").run(now, job.id); job = undefined; return; }
      this.db.prepare("UPDATE telegram_control_outbox SET status='sending',attempts=attempts+1,claim_token=?,lease_until=? WHERE id=?").run(claim, now + 60000, job.id);
      this.db.prepare("UPDATE telegram_state SET next_send_at=? WHERE id=1").run(now + 1100);
      try {
        attempt = rendered.callbackId
          ? this.api.answerCallback?.(rendered.callbackId, this.signal).then((r): TelegramResult<number> => r.ok ? { ok: true, value: 0 } : r)
          : this.api.send(job.chat_id, rendered.text, Math.max(1, Math.min(8000, job.deadline_at - now)), this.signal, rendered.markup);
        attempt ??= Promise.resolve({ ok: false, code: "API_REJECTED", permanent: true, retryAfter: 0 });
      } catch { attempt = Promise.resolve({ ok: false, code: "NETWORK_UNCERTAIN", permanent: false, retryAfter: 0 }); }
    });
    if (!job || !attempt) return false;
    let result: TelegramResult<number>;
    try { result = await attempt; } catch { result = { ok: false, code: "NETWORK_UNCERTAIN", permanent: false, retryAfter: 0 }; }
    this.guard();
    telegramTransaction(this.db, () => {
      const now = this.clock(); const current = this.db.prepare("SELECT attempts FROM telegram_control_outbox WHERE id=? AND claim_token=? AND status='sending'").get(job!.id, claim) as { attempts: number } | undefined;
      if (!current) return;
      if (result.ok) { this.db.prepare("UPDATE telegram_control_outbox SET status='sent',sent_at=?,finished_at=?,last_error=NULL,claim_token=NULL,lease_until=NULL WHERE id=? AND claim_token=?").run(now, now, job!.id, claim); return; }
      if (result.code === "RATE_LIMITED") this.db.prepare("UPDATE telegram_state SET next_send_at=max(next_send_at,?) WHERE id=1").run(now + result.retryAfter);
      const failed = result.permanent || now >= job!.deadline_at;
      const backoff = Math.max(result.retryAfter, Math.min(900000, 1000 * 2 ** Math.min(current.attempts, 10)));
      this.db.prepare("UPDATE telegram_control_outbox SET status=?,last_error=?,finished_at=?,next_attempt_at=?,claim_token=NULL,lease_until=NULL WHERE id=? AND claim_token=?")
        .run(failed ? "failed" : "pending", now >= job!.deadline_at ? "DELIVERY_EXPIRED" : result.code, failed ? now : null, Math.min(now + backoff, job!.deadline_at), job!.id, claim);
    });
    return true;
  }
}
