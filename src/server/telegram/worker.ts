import "server-only";
import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import type { StoredBooking } from "../bookings.ts";
import type { TelegramResult, TelegramTransport } from "./client.ts";
import { bookingMessage } from "./format.ts";
import { acceptUpdates, acquireWorker, ownsWorker, registerBot, telegramState, telegramTransaction, TelegramModelError } from "./model.ts";

export type Clock = () => number;
type Job = StoredBooking & { jobId: string; kind: string; chatId: string; deadline: number; attempts: number };
export function expireTelegramJobs(db: Database.Database, now: number) {
  db.prepare(`UPDATE telegram_outbox SET status='failed',last_error='DELIVERY_EXPIRED',finished_at=?,claim_token=NULL,lease_until=NULL
    WHERE status IN ('pending','sending') AND deadline_at<=?`).run(now, now);
}
export class TelegramDeliveryWorker {
  private readonly db: Database.Database;
  readonly owner: string;
  private readonly api: TelegramTransport;
  private readonly clock: Clock;
  private readonly guard: () => void;
  private readonly signal?: AbortSignal;
  constructor(db: Database.Database, owner: string, api: TelegramTransport,
    clock: Clock = Date.now, guard = () => {}, signal?: AbortSignal) {
    this.db = db; this.owner = owner; this.api = api; this.clock = clock; this.guard = guard; this.signal = signal;
  }

  async dispatch(): Promise<boolean> {
    let job: Job | undefined; let attempt: Promise<TelegramResult<number>> | undefined; const token = randomUUID();
    this.guard();
    telegramTransaction(this.db, () => {
      const now = this.clock(); if (!ownsWorker(this.db, this.owner, now)) throw new TelegramModelError("WORKER_LEASE_LOST");
      expireTelegramJobs(this.db, now);
      this.db.prepare(`UPDATE telegram_outbox SET status='pending',last_error='NETWORK_UNCERTAIN',claim_token=NULL,lease_until=NULL,next_attempt_at=?
        WHERE status='sending' AND lease_until<=? AND deadline_at>?`).run(now, now, now);
      const state = telegramState(this.db); if (!state.enabled || state.next_send_at > now || this.signal?.aborted) return;
      job = this.db.prepare(`SELECT o.id AS jobId,o.kind,o.deadline_at AS deadline,o.attempts,r.chat_id AS chatId,
        b.id,b.resource_id AS resourceId,b.starts_at AS startsAt,b.ends_at AS endsAt,b.status,
        b.first_name AS firstName,b.last_name AS lastName,b.phone,b.created_at AS createdAt,b.updated_at AS updatedAt
        FROM telegram_outbox o JOIN telegram_recipients r ON r.id=o.recipient_id LEFT JOIN bookings b ON b.id=o.booking_id
        WHERE o.status='pending' AND o.next_attempt_at<=? AND o.deadline_at>? AND r.active=1 AND r.connection_status='connected'
          AND (o.kind='test' OR b.status='confirmed') ORDER BY o.next_attempt_at,o.created_at,o.id LIMIT 1`).get(now, now) as Job | undefined;
      if (!job) return;
      const text = job.kind === "test" ? "✅ Тест уведомлений — Studio 19.25\nTelegram подключён. Это тест, без данных клиента." : bookingMessage(job);
      this.db.prepare("UPDATE telegram_outbox SET status='sending',attempts=attempts+1,claim_token=?,lease_until=? WHERE id=?").run(token, now + 60000, job.jobId);
      this.db.prepare("UPDATE telegram_state SET next_send_at=? WHERE id=1").run(now + 1100);
      // Linearization boundary: active/enabled checks + initiation of fetch are
      // under one SHORT writer transaction. No await/network wait holds this lock.
      // Disable committed first => no call. Send initiated first => already in-flight.
      try { attempt = this.api.send(job.chatId, text, Math.max(1, Math.min(8000, job.deadline - now)), this.signal); }
      catch { attempt = Promise.resolve({ ok: false, code: "NETWORK_UNCERTAIN", permanent: false, retryAfter: 0 }); }
    });
    if (!job || !attempt) return false;
    let outcome: TelegramResult<number>;
    try { outcome = await attempt; }
    catch { outcome = { ok: false, code: "NETWORK_UNCERTAIN", permanent: false, retryAfter: 0 }; }
    this.guard();
    telegramTransaction(this.db, () => {
      const now = this.clock();
      if (!outcome.ok && outcome.code === "RATE_LIMITED") this.db.prepare("UPDATE telegram_state SET next_send_at=max(next_send_at,?) WHERE id=1").run(now + outcome.retryAfter);
      const current = this.db.prepare("SELECT attempts FROM telegram_outbox WHERE id=? AND claim_token=? AND status='sending'").get(job!.jobId, token) as { attempts: number } | undefined;
      if (!current) return; // disabled/revoked/cancelled/reclaimed while HTTP was in flight
      if (outcome.ok) {
        this.db.prepare("UPDATE telegram_outbox SET status='sent',sent_at=?,finished_at=?,last_error=NULL,claim_token=NULL,lease_until=NULL WHERE id=? AND claim_token=?").run(now, now, job!.jobId, token); return;
      }
      const backoff = Math.max(outcome.retryAfter, Math.min(900000, 1000 * 2 ** Math.min(current.attempts, 10)));
      const failed = outcome.permanent || now >= job!.deadline;
      this.db.prepare(`UPDATE telegram_outbox SET status=?,last_error=?,finished_at=?,next_attempt_at=?,claim_token=NULL,lease_until=NULL WHERE id=? AND claim_token=?`)
        .run(failed ? "failed" : "pending", now >= job!.deadline ? "DELIVERY_EXPIRED" : outcome.code,
          failed ? now : null, Math.min(now + backoff, job!.deadline), job!.jobId, token);
    });
    return true;
  }
}

function pause(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve) => {
    if (signal.aborted) { resolve(); return; }
    const finish = () => { clearTimeout(timer); signal.removeEventListener("abort", finish); resolve(); };
    const timer = setTimeout(finish, ms); signal.addEventListener("abort", finish, { once: true });
  });
}
export async function runTelegramSession(db: Database.Database, api: TelegramTransport, parent: AbortSignal,
  guard = () => {}, clock: Clock = Date.now, owner: string = randomUUID()): Promise<void> {
  if (!acquireWorker(db, owner, clock())) return;
  const controller = new AbortController(); const abort = () => controller.abort();
  parent.addEventListener("abort", abort, { once: true }); if (parent.aborted) abort();
  const signal = controller.signal; const tasks: Promise<void>[] = [];
  try {
    expireTelegramJobs(db, clock());
    const me = await api.getMe(signal);
    if (!me.ok) throw new TelegramModelError(me.code);
    if (!ownsWorker(db, owner, clock())) throw new TelegramModelError("WORKER_LEASE_LOST");
    registerBot(db, me.value);
    const worker = new TelegramDeliveryWorker(db, owner, api, clock, guard, signal);
    tasks.push((async () => { while (!signal.aborted) { await pause(10000, signal); if (signal.aborted) break;
      guard(); if (!acquireWorker(db, owner, clock())) throw new TelegramModelError("WORKER_LEASE_LOST"); } })());
    tasks.push((async () => { while (!signal.aborted) {
      guard(); if (!ownsWorker(db, owner, clock())) throw new TelegramModelError("WORKER_LEASE_LOST");
      const result = await api.getUpdates(telegramState(db).update_offset, signal);
      if (signal.aborted) break;
      if (result.ok) acceptUpdates(db, owner, result.value, clock());
      else {
        db.prepare("UPDATE telegram_state SET last_error=?,last_error_at=? WHERE id=1").run(result.code, clock());
        if (result.permanent) throw new TelegramModelError(result.code);
      }
      await pause(result.ok ? 1000 : Math.max(2000, result.retryAfter), signal);
    } })());
    tasks.push((async () => { while (!signal.aborted) { await worker.dispatch(); await pause(500, signal); } })());
    await Promise.all(tasks);
  } finally {
    controller.abort(); await Promise.allSettled(tasks); parent.removeEventListener("abort", abort);
    try { db.prepare("UPDATE telegram_state SET worker_until=0,worker_owner=NULL WHERE id=1 AND worker_owner=?").run(owner); } catch {}
  }
}
