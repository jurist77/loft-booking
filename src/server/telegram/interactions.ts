import "server-only";
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type Database from "better-sqlite3";
import type { TelegramUpdate, TelegramUser } from "./client.ts";
import { digestToken, telegramState, TelegramModelError, telegramTransaction, type Recipient } from "./model.ts";

export type UiButton = { text: string; action: string };
export type ControlPayload = { text: string; buttons?: UiButton[][]; keyboard?: "staff" | "owner"; claimId?: string; callbackId?: string };
type Person = Recipient & { username: string | null; subscription_version: number };
type Action = { id: string; actor_id: string; kind: string; target: string | null; target_version: number | null; owner_epoch: number; expires_at: number; used_at: number | null };
type Request = { id: string; recipient_id: string; status: string; expires_at: number };
const MINUTE = 60000, DAY = 86400000;
export const SUBSCRIBE = "Подписаться на рассылку", UNSUBSCRIBE = "Отключить рассылку", MANAGE = "Управление студией";
const clean = (v: string, max = 80) => v.normalize("NFKC").replace(/[\p{Cc}\p{Cf}]/gu, " ").trim().slice(0, max);
export function signedValue(key: string, purpose: string): string { return createHmac("sha256", key).update(purpose).digest("base64url"); }
export function callbackValue(key: string, id: string, actor: string): string { return `a:${id}:${signedValue(key, `callback:${id}:${actor}`).slice(0, 20)}`; }
export function bootstrapValue(key: string, id: string, actor: string): string { return signedValue(key, `bootstrap:${id}:${actor}`); }
export function ownerIs(db: Database.Database, id: string): boolean {
  return !!db.prepare(`SELECT 1 FROM telegram_state s JOIN telegram_recipients r ON r.id=s.owner_recipient_id
    WHERE s.id=1 AND r.id=? AND r.connection_status='connected' AND r.telegram_user_id IS NOT NULL`).get(id);
}
export function controlMessage(db: Database.Database, recipientId: string, dedupe: string, payload: ControlPayload, now: number, ownerOnly = false) {
  const text = JSON.stringify(payload); if (text.length > 16000) throw new TelegramModelError("UI_PAYLOAD_LIMIT");
  db.prepare(`INSERT OR IGNORE INTO telegram_control_outbox(id,dedupe_key,recipient_id,owner_epoch,payload,created_at,deadline_at,next_attempt_at)
    VALUES (?,?,?,?,?,?,?,?)`).run(randomUUID(), dedupe, recipientId, ownerOnly ? telegramState(db).owner_epoch : null, text, now, now + (payload.callbackId ? 30000 : DAY), now);
}
function action(db: Database.Database, actor: string, kind: string, now: number, target: string | null = null, version: number | null = null): string {
  const id = randomUUID(); db.prepare(`INSERT INTO telegram_ui_actions(id,actor_id,kind,target,target_version,owner_epoch,created_at,expires_at)
    VALUES (?,?,?,?,?,?,?,?)`).run(id, actor, kind, target, version, telegramState(db).owner_epoch, now, now + 900000); return id;
}
const button = (db: Database.Database, actor: string, text: string, kind: string, now: number, target: string | null = null, version: number | null = null): UiButton => ({ text, action: action(db, actor, kind, now, target, version) });
const person = (db: Database.Database, id: string) => db.prepare("SELECT * FROM telegram_recipients WHERE id=?").get(id) as Person;
const label = (r: Person) => clean(r.display_name) + (r.username ? ` (@${r.username})` : "");
function allowed(db: Database.Database, key: string, now: number, duration: number, limit: number): boolean {
  db.prepare(`INSERT INTO telegram_interaction_limits(key,window_at,attempts) VALUES (?,?,1)
    ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN window_at<=? THEN 1 ELSE attempts+1 END,
      window_at=CASE WHEN window_at<=? THEN excluded.window_at ELSE window_at END`).run(key, now, now - duration, now - duration);
  return (db.prepare("SELECT attempts FROM telegram_interaction_limits WHERE key=?").get(key) as { attempts: number }).attempts <= limit;
}
export function expireInteractions(db: Database.Database, now: number) {
  db.prepare("UPDATE telegram_subscription_requests SET status='expired',updated_at=? WHERE status='pending' AND expires_at<=?").run(now, now);
  db.prepare("UPDATE telegram_owner_transfers SET status='expired',finished_at=? WHERE status='pending' AND expires_at<=?").run(now, now);
  db.prepare("DELETE FROM telegram_ui_actions WHERE expires_at<?").run(now - DAY);
  db.prepare("DELETE FROM telegram_bootstrap_claims WHERE expires_at<?").run(now - DAY);
  db.prepare("DELETE FROM telegram_interaction_limits WHERE window_at<?").run(now - DAY);
}
function rootMenu(db: Database.Database, id: string, now: number): ControlPayload {
  return { text: "Управление Telegram — Studio 19.25", buttons: [
    [button(db, id, "Сотрудники", "menu:employees:0", now), button(db, id, "Заявки", "menu:requests:0", now)],
    [button(db, id, "Рассылка", "menu:broadcast:0", now), button(db, id, "Тест сообщения", "test", now)],
    [button(db, id, "Статус системы", "menu:status:0", now), button(db, id, "Передача прав", "menu:transfer:0", now)],
  ] };
}
function back(db: Database.Database, actor: string, now: number): UiButton[] { return [button(db, actor, "Главное меню", "menu:root:0", now)]; }
function menu(db: Database.Database, actor: string, section: string, page: number, now: number): ControlPayload {
  if (!ownerIs(db, actor)) throw new TelegramModelError("OWNER_REQUIRED");
  const state = telegramState(db); if (section === "root") return rootMenu(db, actor, now);
  if (section === "broadcast") return { text: `Уведомления о бронированиях: ${state.enabled ? "включены" : "приостановлены"}. Приём бронирований продолжает работать.`,
    buttons: [[button(db, actor, state.enabled ? "Приостановить" : "Включить", state.enabled ? "pause" : "resume", now)], back(db, actor, now)] };
  if (section === "status") {
    const count = (sql: string) => (db.prepare(sql).get() as { n: number }).n;
    const pending = count("SELECT count(*) n FROM telegram_outbox WHERE status IN ('pending','sending')");
    const failed = count("SELECT count(*) n FROM telegram_outbox WHERE status='failed'");
    const expired = count("SELECT count(*) n FROM telegram_outbox WHERE last_error='DELIVERY_EXPIRED'");
    return { text: `Worker: ${state.worker_until > now ? "работает" : "нет свежего heartbeat"}\nПодписчики: ${count("SELECT count(*) n FROM telegram_recipients WHERE active=1 AND connection_status='connected'")}\nЗаявки: ${count("SELECT count(*) n FROM telegram_subscription_requests WHERE status='pending'")}\nОчередь бронирований: ${pending}; ошибки: ${failed}; истекли 24 часа: ${expired}\nРассылка: ${state.enabled ? "включена" : "приостановлена"}`, buttons: [back(db, actor, now)] };
  }
  const rows: UiButton[][] = []; const descriptions: string[] = []; const offset = page * 8;
  let more = false;
  if (section === "requests") {
    const requests = db.prepare("SELECT * FROM telegram_subscription_requests WHERE status='pending' ORDER BY created_at,id LIMIT 9 OFFSET ?").all(offset) as Request[];
    more = requests.length > 8;
    for (const r of requests.slice(0, 8)) { const p = person(db, r.recipient_id); descriptions.push(label(p));
      rows.push([button(db, actor, `Одобрить: ${clean(p.display_name, 25)}`, "approve", now, r.id), button(db, actor, "Отклонить", "reject", now, r.id)]); }
  } else if (section === "employees" || section === "transfer") {
    const people = db.prepare(`SELECT * FROM telegram_recipients WHERE telegram_user_id IS NOT NULL ${section === "transfer" ? "AND connection_status='connected' AND id<>?" : "AND id<>?"}
      ORDER BY created_at,id LIMIT 9 OFFSET ?`).all(section === "transfer" ? actor : "", offset) as Person[];
    more = people.length > 8;
    for (const p of people.slice(0, 8)) {
      descriptions.push(`${label(p)} — ${p.connection_status === "revoked" ? "доступ удалён" : p.active ? "подписан" : "не подписан"}`);
      if (section === "transfer") rows.push([button(db, actor, `Выбрать: ${clean(p.display_name, 30)}`, "transfer-ask", now, p.id, p.subscription_version)]);
      else if (p.id !== actor && p.connection_status !== "revoked") rows.push([
        ...(p.active ? [button(db, actor, `Отключить: ${clean(p.display_name, 20)}`, "disable", now, p.id, p.subscription_version)] : []),
        button(db, actor, "Удалить доступ…", "remove-ask", now, p.id, p.subscription_version),
      ]);
    }
  } else throw new TelegramModelError("INVALID_MENU");
  if (page > 0) rows.push([button(db, actor, "← Назад", `menu:${section}:${page - 1}`, now)]);
  if (more) rows.push([button(db, actor, "Далее →", `menu:${section}:${page + 1}`, now)]);
  rows.push(back(db, actor, now));
  return { text: `${section === "requests" ? "Ожидающие заявки" : section === "transfer" ? "Выберите нового владельца (он должен открыть бота)" : "Сотрудники и подписки"}\n${descriptions.join("\n") || "Список пуст"}`, buttons: rows };
}
function notifyOwner(db: Database.Database, dedupe: string, payload: ControlPayload, now: number) {
  const id = telegramState(db).owner_recipient_id;
  if (id && ownerIs(db, id)) controlMessage(db, id, dedupe, payload, now, true);
}
function subscribe(db: Database.Database, r: Person, now: number, key: string) {
  if (r.active && r.connection_status === "connected") { controlMessage(db, r.id, `already:${r.id}:${r.subscription_version}`, { text: "Подписка уже активна." }, now); return; }
  if (ownerIs(db, r.id)) {
    // A request may predate bootstrap/role transfer. Owner authority removes
    // the approval requirement, but subscription still needs this explicit click.
    db.prepare("UPDATE telegram_recipients SET active=1,subscription_version=subscription_version+1,updated_at=? WHERE id=?").run(now, r.id);
    db.prepare("UPDATE telegram_subscription_requests SET status='approved',updated_at=? WHERE recipient_id=? AND status='pending'").run(now, r.id);
    controlMessage(db, r.id, key, { text: "Ваша подписка включена. Права владельца от неё не зависят." }, now); return;
  }
  const pending = db.prepare("SELECT id FROM telegram_subscription_requests WHERE recipient_id=? AND status='pending'").get(r.id);
  if (pending) return; // No duplicate request or owner notification.
  db.prepare("UPDATE telegram_recipients SET connection_status='connected',subscription_version=subscription_version+1,updated_at=? WHERE id=?").run(now, r.id);
  const id = randomUUID();
  db.prepare("INSERT INTO telegram_subscription_requests(id,recipient_id,status,created_at,updated_at,expires_at) VALUES (?,?,'pending',?,?,?)").run(id, r.id, now, now, now + 7 * DAY);
  controlMessage(db, r.id, key, { text: "Заявка отправлена владельцу. До одобрения уведомления о бронированиях недоступны." }, now);
  const owner = telegramState(db).owner_recipient_id;
  if (owner && ownerIs(db, owner)) notifyOwner(db, `request:${id}`, { text: `Новая заявка на подписку\nСотрудник: ${label(r)}`,
    buttons: [[button(db, owner, "Одобрить", "approve", now, id), button(db, owner, "Отклонить", "reject", now, id)]] }, now);
}
function unsubscribe(db: Database.Database, r: Person, now: number, key: string) {
  const pending = db.prepare("SELECT id FROM telegram_subscription_requests WHERE recipient_id=? AND status='pending'").get(r.id);
  if (!r.active && !pending) { controlMessage(db, r.id, `off:${r.id}:${r.subscription_version}`, { text: "Рассылка уже отключена." }, now); return; }
  db.prepare("UPDATE telegram_recipients SET active=0,subscription_version=subscription_version+1,updated_at=? WHERE id=?").run(now, r.id);
  db.prepare("UPDATE telegram_subscription_requests SET status='cancelled',updated_at=? WHERE recipient_id=? AND status='pending'").run(now, r.id);
  controlMessage(db, r.id, key, { text: "Рассылка отключена. Для повторного подключения потребуется одобрение (владельцу — нет)." }, now);
  if (!ownerIs(db, r.id)) notifyOwner(db, key + ":owner", { text: `Сотрудник отключил рассылку: ${label(r)}` }, now);
}
function bootstrapChallenge(db: Database.Database, r: Person, key: string, now: number) {
  const current = telegramState(db).owner_recipient_id;
  if (current && ownerIs(db, current)) return;
  if (!allowed(db, `bootstrap:${digestToken(r.id)}`, now, 3600000, 3)) return;
  const live = db.prepare("SELECT id FROM telegram_bootstrap_claims WHERE recipient_id=? AND used_at IS NULL AND expires_at>?").get(r.id, now);
  if (live) return;
  const id = randomUUID(); const value = bootstrapValue(key, id, r.id);
  db.prepare("INSERT INTO telegram_bootstrap_claims(id,recipient_id,token_hash,created_at,expires_at) VALUES (?,?,?,?,?)").run(id, r.id, digestToken(value), now, now + 900000);
  controlMessage(db, r.id, `bootstrap:${id}`, { text: "", claimId: id }, now);
}
export function confirmBootstrap(db: Database.Database, value: string, now: number) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new TelegramModelError("BOOTSTRAP_CONFIRMATION_INVALID");
  return telegramTransaction(db, () => {
    const state = telegramState(db);
    if (state.owner_recipient_id && ownerIs(db, state.owner_recipient_id)) {
      const used = db.prepare("SELECT 1 FROM telegram_bootstrap_claims WHERE token_hash=? AND recipient_id=? AND used_at IS NOT NULL").get(digestToken(value), state.owner_recipient_id);
      if (used) return;
      throw new TelegramModelError("OWNER_ALREADY_BOOTSTRAPPED");
    }
    const claim = db.prepare(`SELECT c.* FROM telegram_bootstrap_claims c JOIN telegram_recipients r ON r.id=c.recipient_id
      WHERE c.token_hash=? AND c.used_at IS NULL AND c.expires_at>? AND r.connection_status='connected'`).get(digestToken(value), now) as { id: string; recipient_id: string } | undefined;
    if (!claim) throw new TelegramModelError("BOOTSTRAP_CONFIRMATION_INVALID");
    if (state.owner_recipient_id) db.prepare("UPDATE telegram_invitations SET revoked_at=? WHERE recipient_id=? AND used_at IS NULL AND revoked_at IS NULL").run(now, state.owner_recipient_id);
    db.prepare("UPDATE telegram_state SET owner_recipient_id=?,owner_epoch=owner_epoch+1 WHERE id=1").run(claim.recipient_id);
    db.prepare("UPDATE telegram_bootstrap_claims SET used_at=? WHERE used_at IS NULL").run(now);
    controlMessage(db, claim.recipient_id, `owner-bootstrap:${claim.id}`, { text: "Вы подтверждены как владелец Telegram. Подписка на бронирования включается отдельно. Проверьте раздел «Заявки»: там могут быть ожидающие решения.", keyboard: "owner" }, now, true);
  });
}
function execute(db: Database.Database, actor: Person, a: Action, now: number, dedupe: string): ControlPayload | undefined {
  const state = telegramState(db);
  if (a.kind === "accept-transfer" || a.kind === "decline-transfer") {
    const t = db.prepare("SELECT * FROM telegram_owner_transfers WHERE id=? AND status='pending' AND expires_at>?").get(a.target, now) as { id: string; from_id: string; to_id: string; owner_epoch: number } | undefined;
    if (!t || actor.connection_status !== "connected" || t.to_id !== actor.id || state.owner_recipient_id !== t.from_id || t.owner_epoch !== state.owner_epoch) return;
    db.prepare("UPDATE telegram_owner_transfers SET status=?,finished_at=? WHERE id=?").run(a.kind === "accept-transfer" ? "accepted" : "declined", now, t.id);
    if (a.kind === "decline-transfer") { controlMessage(db, t.from_id, dedupe + ":old", { text: "Передача прав отклонена." }, now); return { text: "Вы отклонили передачу прав." }; }
    db.prepare("UPDATE telegram_state SET owner_recipient_id=?,owner_epoch=owner_epoch+1 WHERE id=1").run(actor.id);
    db.prepare("UPDATE telegram_control_outbox SET status='cancelled',finished_at=? WHERE owner_epoch IS NOT NULL AND status IN ('pending','sending')").run(now);
    controlMessage(db, t.from_id, dedupe + ":old", { text: "Права владельца переданы. Административные действия теперь недоступны. Подписка на бронирования не изменена.", keyboard: "staff" }, now);
    return { text: "Вы приняли права владельца. Подписки сотрудников сохранены. Откройте «Заявки» для ожидающих решений.", keyboard: "owner" };
  }
  if (!ownerIs(db, actor.id) || a.owner_epoch !== state.owner_epoch) return;
  const match = /^menu:(root|employees|requests|broadcast|status|transfer):(\d{1,5})$/.exec(a.kind);
  if (match) return menu(db, actor.id, match[1], Number(match[2]), now);
  if (a.kind === "pause" || a.kind === "resume") { db.prepare("UPDATE telegram_state SET enabled=? WHERE id=1").run(a.kind === "resume" ? 1 : 0); return menu(db, actor.id, "broadcast", 0, now); }
  if (a.kind === "test") return { text: "✅ Тест уведомлений — Studio 19.25\nЭто техническое сообщение без данных клиентов." };
  if (a.kind === "approve" || a.kind === "reject") {
    const request = db.prepare("SELECT * FROM telegram_subscription_requests WHERE id=? AND status='pending' AND expires_at>?").get(a.target, now) as Request | undefined;
    if (!request) return;
    const r = person(db, request.recipient_id);
    if (r.connection_status !== "connected") return;
    db.prepare("UPDATE telegram_subscription_requests SET status=?,updated_at=? WHERE id=?").run(a.kind === "approve" ? "approved" : "rejected", now, request.id);
    db.prepare("UPDATE telegram_recipients SET active=?,subscription_version=subscription_version+1,updated_at=? WHERE id=?").run(a.kind === "approve" ? 1 : 0, now, r.id);
    controlMessage(db, r.id, dedupe + ":staff", { text: a.kind === "approve" ? "Подписка одобрена. Вы будете получать новые бронирования." : "Заявка отклонена. Доступ к уведомлениям не предоставлен." }, now);
    return { text: `Заявка ${a.kind === "approve" ? "одобрена" : "отклонена"}: ${label(r)}` };
  }
  const r = a.target ? person(db, a.target) : undefined;
  if (!r || r.id === actor.id || r.subscription_version !== a.target_version || r.connection_status !== "connected") return;
  if (a.kind === "remove-ask") return { text: `Удалить доступ сотрудника ${label(r)}?`, buttons: [[button(db, actor.id, "Подтвердить удаление", "remove", now, r.id, r.subscription_version)], back(db, actor.id, now)] };
  if (a.kind === "disable" || a.kind === "remove") {
    db.prepare("UPDATE telegram_recipients SET active=0,connection_status=?,subscription_version=subscription_version+1,updated_at=? WHERE id=?").run(a.kind === "remove" ? "revoked" : "connected", now, r.id);
    db.prepare("UPDATE telegram_subscription_requests SET status='cancelled',updated_at=? WHERE recipient_id=? AND status='pending'").run(now, r.id);
    db.prepare("UPDATE telegram_invitations SET revoked_at=? WHERE recipient_id=? AND used_at IS NULL AND revoked_at IS NULL").run(now, r.id);
    if (a.kind === "remove") db.prepare("UPDATE telegram_owner_transfers SET status='declined',finished_at=? WHERE to_id=? AND status='pending'").run(now, r.id);
    controlMessage(db, r.id, dedupe + ":staff", { text: a.kind === "remove" ? "Владелец удалил ваш доступ к рассылке. Повторная подписка требует нового одобрения." : "Владелец отключил вашу подписку. Повторное подключение требует одобрения." }, now);
    return { text: "Доступ сотрудника изменён." };
  }
  if (a.kind === "transfer-ask") return { text: `Передать права владельца пользователю ${label(r)}? Вы утратите административные полномочия после его принятия.`, buttons: [[button(db, actor.id, "Подтверждаю передачу", "transfer-confirm", now, r.id, r.subscription_version)], back(db, actor.id, now)] };
  if (a.kind === "transfer-confirm") {
    if (db.prepare("SELECT 1 FROM telegram_owner_transfers WHERE status='pending'").get()) return { text: "Передача уже ожидает подтверждения." };
    const id = randomUUID(); db.prepare("INSERT INTO telegram_owner_transfers(id,from_id,to_id,owner_epoch,status,created_at,expires_at) VALUES (?,?,?,?,'pending',?,?)").run(id, actor.id, r.id, state.owner_epoch, now, now + 900000);
    controlMessage(db, r.id, dedupe + ":new", { text: "Вам предлагают принять права владельца Telegram Studio 19.25. Подписки не изменятся.", buttons: [[button(db, r.id, "Принять права", "accept-transfer", now, id), button(db, r.id, "Отклонить", "decline-transfer", now, id)]] }, now);
    return { text: "Предложение отправлено. Оно действует 15 минут; права сохраняются у вас до принятия." };
  }
}
export function handleInteraction(db: Database.Database, update: TelegramUpdate, now: number, key: string): void {
  // Called inside acceptUpdates' transaction: state + UI outbox + cursor COMMIT together.
  if (!db.inTransaction) throw new TelegramModelError("TRANSACTION_REQUIRED");
  const callback = update.callback_query; if (callback && update.message) return;
  const user = callback ? callback.from : update.message?.from;
  const chat = callback ? callback.message?.chat : update.message?.chat;
  if (!user || user.is_bot !== false || !Number.isSafeInteger(user.id) || Number(user.id) <= 0 || user.id !== chat?.id || chat?.type !== "private") return;
  const text = typeof update.message?.text === "string" ? update.message.text : "";
  if (!callback && ![SUBSCRIBE, UNSUBSCRIBE, MANAGE, "/owner"].includes(text) && !/^\/start(?: [A-Za-z0-9_-]{1,64})?$/.test(text)) return;
  const found = db.prepare("SELECT * FROM telegram_recipients WHERE telegram_user_id=?").get(String(user.id)) as Person | undefined;
  // Opt-out must remain available even after a user exhausts the interaction
  // quota. Verified private identity above still applies; unchanged opt-outs
  // are deduplicated and cannot flood the owner or create new recipients.
  if (found && !callback && text === UNSUBSCRIBE) {
    expireInteractions(db, now); unsubscribe(db, found, now, `update:${update.update_id}`); return;
  }
  const owner = !!found && ownerIs(db, found.id);
  if (!allowed(db, `user:${digestToken(String(user.id))}`, now, MINUTE, owner ? 40 : 8) || (!owner && !allowed(db, "public", now, MINUTE, 20))) return;
  const r = found ?? ensurePerson(db, user, now);
  if (found && !callback) {
    const profile = profileOf(user);
    db.prepare("UPDATE telegram_recipients SET display_name=?,username=? WHERE id=?").run(profile.name, profile.username, r.id);
    r.display_name = profile.name; r.username = profile.username;
  }
  expireInteractions(db, now);
  const dedupe = `update:${update.update_id}`;
  if (callback) {
    if (typeof callback.id === "string" && callback.id.length <= 128) controlMessage(db, r.id, dedupe + ":ack", { text: "", callbackId: callback.id }, now);
    const match = typeof callback.data === "string" && /^a:([0-9a-f-]{36}):([A-Za-z0-9_-]{20})$/.exec(callback.data);
    if (!match) return;
    const expected = callbackValue(key, match[1], r.id); const actual = callback.data!;
    if (actual.length !== expected.length || !timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) return;
    const a = db.prepare("SELECT * FROM telegram_ui_actions WHERE id=? AND actor_id=? AND used_at IS NULL AND expires_at>?").get(match[1], r.id, now) as Action | undefined;
    if (!a) { controlMessage(db, r.id, `stale:${match[1]}:${r.id}`, { text: "Кнопка устарела или уже использована. Откройте меню заново." }, now); return; }
    db.prepare("UPDATE telegram_ui_actions SET used_at=? WHERE id=?").run(now, a.id);
    const response = execute(db, r, a, now, dedupe);
    if (response) controlMessage(db, r.id, dedupe, response, now, ownerIs(db, r.id));
  } else if (text === SUBSCRIBE) subscribe(db, r, now, dedupe);
  else if (text === UNSUBSCRIBE) unsubscribe(db, r, now, dedupe);
  else if (text === MANAGE || text === "/owner") {
    if (ownerIs(db, r.id)) controlMessage(db, r.id, dedupe, rootMenu(db, r.id, now), now, true);
    else if (text === "/owner") bootstrapChallenge(db, r, key, now);
  } else controlMessage(db, r.id, dedupe, { text: "Добро пожаловать в Studio 19.25. Подписка на бронирования включается только после одобрения. Для первого владельца: меню команд Telegram → /owner (одноразовое подключение).", keyboard: owner ? "owner" : "staff" }, now);
}
function profileOf(user: TelegramUser) {
  const name = clean([user.first_name, user.last_name].filter((s) => typeof s === "string").join(" ")) || "Пользователь Telegram";
  const username = typeof user.username === "string" && /^[A-Za-z0-9_]{1,32}$/.test(user.username) ? user.username : null;
  return { name, username };
}
function ensurePerson(db: Database.Database, user: TelegramUser, now: number): Person {
  const { name, username } = profileOf(user);
  const id = randomUUID(); db.prepare(`INSERT INTO telegram_recipients(id,display_name,telegram_user_id,chat_id,connection_status,active,created_at,updated_at,username)
    VALUES (?,?,?,?,'connected',0,?,?,?)`).run(id, name, String(user.id), String(user.id), now, now, username);
  return person(db, id);
}
