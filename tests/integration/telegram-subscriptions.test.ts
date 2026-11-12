import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type Database from "better-sqlite3";
import { databaseSettings } from "../../src/server/config";
import { initializeDatabase, openDatabase } from "../../src/server/database";
import { migrate } from "../../src/server/migrations";
import { backupDatabase, restoreDatabase } from "../../src/server/backup";
import { createBooking } from "../../src/server/bookings";
import { TelegramClient, type TelegramMarkup, type TelegramTransport, type TelegramUpdate } from "../../src/server/telegram/client";
import { acceptUpdates, acquireWorker, digestToken, registerBot, setTelegramEnabled, telegramState } from "../../src/server/telegram/model";
import { bootstrapValue, confirmBootstrap, handleInteraction, MANAGE, ownerIs, SUBSCRIBE, UNSUBSCRIBE } from "../../src/server/telegram/interactions";
import { TelegramControlWorker } from "../../src/server/telegram/control-worker";
import { runTelegramSession, TelegramDeliveryWorker } from "../../src/server/telegram/worker";
import { manageTelegram, technicalStatus } from "../../src/server/telegram/management";
import { loadTelegramConfiguration, saveTelegramConfiguration, telegramConfigPath, telegramInstance } from "../../src/server/telegram/config";

const KEY = "S".repeat(43), TOKEN = "123456:" + "T".repeat(35), WORKER = "fixture-worker";
let folder: string, path: string, db: Database.Database, now: number, update: number;
let messages: { chat: string; text: string; markup?: TelegramMarkup }[];
let api: TelegramTransport;
const recipient = (user: number) => db.prepare("SELECT * FROM telegram_recipients WHERE telegram_user_id=?").get(String(user)) as { id: string; active: number; connection_status: string; subscription_version: number };
function received(user: number, text: string, name = `Тест ${user}`) {
  acquireWorker(db, WORKER, now);
  const value: TelegramUpdate = { update_id: update++, message: { text, from: { id: user, is_bot: false, first_name: name, username: `fixture_${user}` }, chat: { id: user, type: "private" } } };
  acceptUpdates(db, WORKER, [value], now, (u) => handleInteraction(db, u, now, KEY));
  return value;
}
async function drain() {
  for (let n = 0; n < 150; n++) {
    acquireWorker(db, WORKER, now); const sent = await new TelegramControlWorker(db, WORKER, api, KEY, () => now).dispatch();
    now += 1200;
    if (!sent && !(db.prepare("SELECT 1 FROM telegram_control_outbox WHERE status='pending' AND next_attempt_at<=?").get(now))) return;
  }
  throw new Error("FIXTURE_QUEUE_DID_NOT_DRAIN");
}
async function bootstrap(user = 111) {
  received(user, "/start"); received(user, "/owner"); await drain();
  const row = db.prepare("SELECT * FROM telegram_bootstrap_claims WHERE recipient_id=?").get(recipient(user).id) as { id: string; token_hash: string };
  const value = bootstrapValue(KEY, row.id, recipient(user).id);
  expect(row.token_hash).toBe(digestToken(value)); confirmBootstrap(db, value, now); await drain(); return value;
}
function button(user: number, text: string, containing = "") {
  for (const m of [...messages].reverse()) if (m.chat === String(user) && m.text.includes(containing) && m.markup && "inline_keyboard" in m.markup) {
    const b = m.markup.inline_keyboard.flat().find((v) => v.text.startsWith(text)); if (b) return b.callback_data;
  }
  throw new Error("FIXTURE_BUTTON_NOT_FOUND: " + text);
}
async function tap(user: number, data: string) {
  acquireWorker(db, WORKER, now);
  const value: TelegramUpdate = { update_id: update++, callback_query: { id: `callback_${update}`, data, from: { id: user, is_bot: false }, message: { chat: { id: user, type: "private" } } } };
  acceptUpdates(db, WORKER, [value], now, (u) => handleInteraction(db, u, now, KEY)); await drain(); return value;
}
async function menu(user: number, section: string) { received(user, MANAGE); await drain(); await tap(user, button(user, section)); }
function booking(id = "fixture-booking") {
  return createBooking(db, { id, resourceId: "studio-19-25", date: "2030-01-15", start: 600, end: 660, firstName: "Тест", lastName: "Пример", phone: "+79000000000" }, new Date(now));
}
beforeEach(async () => {
  now = Date.parse("2030-01-15T08:00:00+03:00"); update = 1; messages = [];
  folder = mkdtempSync(join(tmpdir(), "studio-tg-ui-")); path = join(folder, "studio.sqlite");
  initializeDatabase(databaseSettings({ APP_MODE: "server", SQLITE_PATH: path })); db = openDatabase(databaseSettings({ APP_MODE: "server", SQLITE_PATH: path }));
  await migrate(db, resolve("migrations/sqlite")); registerBot(db, { id: 123456, username: "StudioFixtureBot" }); acquireWorker(db, WORKER, now);
  api = { getMe: async () => ({ ok: true, value: { id: 123456, username: "StudioFixtureBot" } }),
    webhookInfo: async () => ({ ok: true, value: { url: "" } }), getUpdates: async () => ({ ok: true, value: [] }),
    answerCallback: async () => ({ ok: true, value: true }),
    send: async (chat, text, _timeout, _signal, markup) => { messages.push({ chat, text, markup }); return { ok: true, value: messages.length }; } };
});
afterEach(() => { if (db?.open) db.close(); rmSync(folder, { recursive: true, force: true }); });

it("Start never subscribes or assigns owner; private bootstrap is bound, hashed, expiring, single-use and not first-come", async () => {
  received(222, "/owner"); await drain(); expect(telegramState(db).owner_recipient_id).toBeNull();
  const code = await bootstrap(111); expect(ownerIs(db, recipient(111).id)).toBe(true); expect(ownerIs(db, recipient(222).id)).toBe(false);
  expect(recipient(111).active).toBe(0); expect(recipient(222).active).toBe(0);
  confirmBootstrap(db, code, now); // exact retry of already successful owner confirmation
  expect(telegramState(db).owner_epoch).toBe(1);
  const stored = JSON.stringify(db.prepare("SELECT * FROM telegram_bootstrap_claims").all()) + JSON.stringify(db.prepare("SELECT payload FROM telegram_control_outbox").all());
  expect(stored).not.toContain(code); expect(stored).not.toContain(KEY); expect(stored).not.toContain(TOKEN);
  expect(messages.filter((m) => m.text.includes(code)).map((m) => m.chat)).toEqual(["111"]);
  const other = db.prepare("SELECT id FROM telegram_bootstrap_claims WHERE recipient_id=?").get(recipient(222).id) as { id: string };
  expect(() => confirmBootstrap(db, bootstrapValue(KEY, other.id, recipient(222).id), now)).toThrow("OWNER_ALREADY_BOOTSTRAPPED");
});
it("expired bootstrap and spoofed/group/bot identities never gain any role", () => {
  received(111, "/owner"); const id = (db.prepare("SELECT id FROM telegram_bootstrap_claims").get() as { id: string }).id;
  expect(() => confirmBootstrap(db, bootstrapValue(KEY, id, recipient(111).id), now + 900001)).toThrow("BOOTSTRAP_CONFIRMATION_INVALID");
  for (const value of [
    { update_id: update++, message: { text: SUBSCRIBE, from: { id: 222, is_bot: false }, chat: { id: 111, type: "private" } } },
    { update_id: update++, message: { text: SUBSCRIBE, from: { id: 222, is_bot: true }, chat: { id: 222, type: "private" } } },
    { update_id: update++, message: { text: SUBSCRIBE, from: { id: 222, is_bot: false }, chat: { id: 222, type: "group" } } },
  ]) acceptUpdates(db, WORKER, [value], now, (u) => handleInteraction(db, u, now, KEY));
  expect(db.prepare("SELECT count(*) n FROM telegram_recipients").get()).toEqual({ n: 1 }); expect(telegramState(db).owner_recipient_id).toBeNull();
});
it("approves/rejects subscription requests once, sends owner info independently of pause/subscription and never backfills bookings", async () => {
  await bootstrap(); received(222, "/start", "Сотрудник"); received(222, SUBSCRIBE, "Сотрудник"); received(222, SUBSCRIBE); await drain();
  expect(db.prepare("SELECT count(*) n FROM telegram_subscription_requests").get()).toEqual({ n: 1 });
  expect(messages.filter((m) => m.chat === "111" && m.text.includes("Новая заявка"))).toHaveLength(1);
  expect(messages.find((m) => m.text.includes("Новая заявка"))?.text).toContain("@fixture_222");
  expect(recipient(222).active).toBe(0); booking(); expect(db.prepare("SELECT count(*) n FROM telegram_outbox").get()).toEqual({ n: 0 });
  const approve = button(111, "Одобрить"); const event = await tap(111, approve);
  expect(recipient(222).active).toBe(1);
  acceptUpdates(db, WORKER, [event], now, (u) => handleInteraction(db, u, now, KEY)); await tap(111, approve);
  expect(db.prepare("SELECT count(*) n FROM telegram_subscription_requests WHERE status='approved'").get()).toEqual({ n: 1 });
  received(333, SUBSCRIBE, "Отказ"); await drain(); await tap(111, button(111, "Отклонить", "Отказ")); expect(recipient(333).active).toBe(0);
  expect(messages.some((m) => m.chat === "333" && m.text.includes("отклонена"))).toBe(true);
  expect(db.prepare("SELECT count(*) n FROM telegram_outbox").get()).toEqual({ n: 0 });
});
it("callback forgery, different actor and stale decision cannot mutate subscriptions", async () => {
  await bootstrap(); received(222, SUBSCRIBE); await drain(); const approve = button(111, "Одобрить");
  await tap(222, approve); expect(recipient(222).active).toBe(0);
  await tap(111, approve.slice(0, -1) + (approve.endsWith("a") ? "b" : "a")); expect(recipient(222).active).toBe(0);
  now += 900001; acquireWorker(db, WORKER, now); await tap(111, approve); expect(recipient(222).active).toBe(0);
});
it("owner subscription is independent; pause/test/status and owner notifications work while unsubscribed", async () => {
  await bootstrap(); expect(recipient(111).active).toBe(0); received(111, SUBSCRIBE); await drain(); expect(recipient(111).active).toBe(1);
  received(111, UNSUBSCRIBE); await drain(); expect(ownerIs(db, recipient(111).id)).toBe(true); expect(recipient(111).active).toBe(0);
  await menu(111, "Рассылка"); await tap(111, button(111, "Включить")); expect(telegramState(db).enabled).toBe(1);
  await menu(111, "Рассылка"); await tap(111, button(111, "Приостановить")); expect(telegramState(db).enabled).toBe(0);
  received(111, MANAGE); await drain(); await tap(111, button(111, "Тест сообщения"));
  expect(messages.some((m) => m.chat === "111" && m.text.includes("техническое сообщение без данных клиентов"))).toBe(true);
  await menu(111, "Статус системы"); const status = [...messages].reverse().find((m) => m.text.startsWith("Worker:"))!;
  expect(status.text).toContain("Подписчики: 0"); expect(status.text).not.toContain("+7"); expect(status.text).not.toContain(TOKEN);
});
it("unsubscribe/removal cancel pending booking deliveries; reconnect requires new approval and destructive confirmation", async () => {
  await bootstrap(); received(222, SUBSCRIBE); await drain(); await tap(111, button(111, "Одобрить")); booking();
  expect(db.prepare("SELECT count(*) n FROM telegram_outbox").get()).toEqual({ n: 1 });
  received(222, UNSUBSCRIBE); await drain(); expect(db.prepare("SELECT status FROM telegram_outbox").get()).toEqual({ status: "cancelled" });
  received(222, SUBSCRIBE); await drain(); expect(recipient(222).active).toBe(0); await tap(111, button(111, "Одобрить"));
  await menu(111, "Сотрудники"); await tap(111, button(111, "Удалить доступ")); expect(recipient(222).connection_status).toBe("connected");
  await tap(111, button(111, "Подтвердить удаление")); expect(recipient(222).connection_status).toBe("revoked");
  received(222, SUBSCRIBE); await drain(); expect(recipient(222).active).toBe(0); await tap(111, button(111, "Одобрить"));
  expect(recipient(222).active).toBe(1); expect(ownerIs(db, recipient(111).id)).toBe(true);
});
it("two-sided ownership transfer is atomic; old owner loses callbacks immediately and subscribers stay", async () => {
  await bootstrap(); received(222, "/start"); received(111, SUBSCRIBE); await drain();
  await menu(111, "Рассылка"); const oldResume = button(111, "Включить");
  await menu(111, "Передача прав"); await tap(111, button(111, "Выбрать"));
  expect(ownerIs(db, recipient(111).id)).toBe(true); await tap(111, button(111, "Подтверждаю передачу"));
  expect(ownerIs(db, recipient(111).id)).toBe(true); await tap(222, button(222, "Принять права"));
  expect(ownerIs(db, recipient(222).id)).toBe(true); expect(ownerIs(db, recipient(111).id)).toBe(false); expect(recipient(111).active).toBe(1);
  await tap(111, oldResume); expect(telegramState(db).enabled).toBe(0);
  await menu(222, "Рассылка"); await tap(222, button(222, "Включить")); expect(telegramState(db).enabled).toBe(1);
});
it("subscription spam is bounded without limiting recipient count and pending requests expire safely", async () => {
  await bootstrap(); for (let n = 0; n < 25; n++) received(222, SUBSCRIBE); await drain();
  expect(db.prepare("SELECT count(*) n FROM telegram_subscription_requests WHERE status='pending'").get()).toEqual({ n: 1 });
  expect(messages.filter((m) => m.chat === "111" && m.text.includes("Новая заявка"))).toHaveLength(1);
  now += 7 * 86400000 + 1; acquireWorker(db, WORKER, now); received(222, SUBSCRIBE); await drain();
  expect(db.prepare("SELECT count(*) n FROM telegram_subscription_requests WHERE status='pending'").get()).toEqual({ n: 1 });
  expect(db.prepare("SELECT count(*) n FROM telegram_subscription_requests WHERE status='expired'").get()).toEqual({ n: 1 });
});
it("controls share backoff/429 and 24h expiry, survive DB restart and backup with hashes and users intact", async () => {
  await bootstrap(); received(222, SUBSCRIBE); const snapshot = join(folder, "snapshot.sqlite"); await backupDatabase(db, snapshot); db.close();
  const restored = join(folder, "restored.sqlite"); await restoreDatabase(snapshot, restored); db = openDatabase(databaseSettings({ APP_MODE: "server", SQLITE_PATH: restored }));
  expect(await migrate(db, resolve("migrations/sqlite"))).toEqual([]); expect(ownerIs(db, recipient(111).id)).toBe(true);
  api.send = vi.fn<TelegramTransport["send"]>(async () => ({ ok: false, code: "RATE_LIMITED", permanent: false, retryAfter: 30000 }));
  acquireWorker(db, WORKER, now); await new TelegramControlWorker(db, WORKER, api, KEY, () => now).dispatch();
  expect(db.prepare("SELECT count(*) n FROM telegram_control_outbox WHERE last_error='RATE_LIMITED'").get()).toEqual({ n: 1 });
  now += 86400001; acquireWorker(db, WORKER, now); await new TelegramControlWorker(db, WORKER, api, KEY, () => now).dispatch();
  expect(db.prepare("SELECT count(*) n FROM telegram_control_outbox WHERE status IN ('pending','sending')").get()).toEqual({ n: 0 });
});
it("only active approved recipients get transactional booking jobs; Telegram failure does not undo booking", async () => {
  await bootstrap(); received(222, SUBSCRIBE); received(333, "/start"); await drain(); await tap(111, button(111, "Одобрить"));
  setTelegramEnabled(db, true); booking(); booking();
  expect(db.prepare("SELECT recipient_id FROM telegram_outbox").all()).toEqual([{ recipient_id: recipient(222).id }]);
  api.send = async () => ({ ok: false, code: "TEMPORARY_FAILURE", permanent: false, retryAfter: 1000 });
  acquireWorker(db, WORKER, now); await new TelegramDeliveryWorker(db, WORKER, api, () => now).dispatch();
  expect(db.prepare("SELECT status FROM bookings").get()).toEqual({ status: "confirmed" });
});
it("token configuration is verified, atomic/private, same-bot-only, idempotent and preserves queue/signing key", async () => {
  await bootstrap(); const before = db.prepare("SELECT * FROM telegram_recipients").all();
  const factory = () => api;
  const plan = await manageTelegram(db, path, "plan", { token: TOKEN }, factory, now);
  expect(plan).toHaveProperty("planned");
  const expected = (plan as { planned: { bot: string; token: string; instance: string } }).planned;
  await manageTelegram(db, path, "configure", { token: TOKEN, expected }, factory, now);
  const file = telegramConfigPath(path); const config = loadTelegramConfiguration(file);
  expect(statSync(file).mode & 0o777).toBe(0o600); expect(statSync(join(folder, "settings")).mode & 0o777).toBe(0o700);
  expect(db.prepare("SELECT * FROM telegram_recipients").all()).toEqual(before);
  const bytes = readFileSync(file); const token2 = "123456:" + "U".repeat(35);
  const invalid = () => ({ ...api, getMe: async () => ({ ok: false as const, code: "AUTH_INVALID" as const, permanent: true, retryAfter: 0 }) });
  await expect(manageTelegram(db, path, "plan", { token: token2 }, invalid, now)).rejects.toThrow("AUTH_INVALID"); expect(readFileSync(file)).toEqual(bytes);
  const other = () => ({ ...api, getMe: async () => ({ ok: true as const, value: { id: 654321, username: "OtherFixtureBot" } }) });
  await expect(manageTelegram(db, path, "plan", { token: token2 }, other, now)).rejects.toThrow("BOT_CHANGED_RELINK_REQUIRED"); expect(readFileSync(file)).toEqual(bytes);
  const planned = await manageTelegram(db, path, "plan", { token: token2 }, factory, now) as { planned: typeof expected };
  await manageTelegram(db, path, "configure", { token: token2, expected: planned.planned }, factory, now);
  expect(loadTelegramConfiguration(file).key).toBe(config.key); expect(loadTelegramConfiguration(file).token).toBe(token2);
  expect(db.prepare("SELECT * FROM telegram_recipients").all()).toEqual(before);
  expect(JSON.stringify(db.prepare("SELECT * FROM telegram_state").all())).not.toContain(token2);
});
it("normal updates retain host binding; restored settings cannot poll with a missing or different host nonce", async () => {
  const instance = telegramInstance(path, true); const file = telegramConfigPath(path);
  saveTelegramConfiguration(file, { token: TOKEN, botId: "123456", instance, key: KEY });
  expect(technicalStatus(db, path, now).instanceBound).toBe(true);
  expect(telegramInstance(path, true)).toBe(instance); // repeated configure/update retains the local nonce
  rmSync(join(folder, ".telegram-instance")); // existing restore swaps DATA; nonce is not in the backup
  expect(technicalStatus(db, path, now)).toMatchObject({ instanceBound: false, workerState: "INSTANCE_MISMATCH" });
  writeFileSync(join(folder, ".telegram-instance"), "a".repeat(64), { mode: 0o600 });
  expect(technicalStatus(db, path, now).instanceBound).toBe(false);
  chmodSync(file, 0o644); expect(() => loadTelegramConfiguration(file)).toThrow("TELEGRAM_CONFIGURATION_UNAVAILABLE");
});
it("concurrent-polling API conflict is permanent and a new session never starts sending before successful poll", async () => {
  const fetcher: typeof fetch = async () => new Response(JSON.stringify({ ok: false, error_code: 409 }), { status: 409 });
  const client = new TelegramClient(TOKEN, fetcher); expect(await client.getUpdates(0)).toMatchObject({ ok: false, code: "CONCURRENT_POLLING", permanent: true });
  await bootstrap(); const send = vi.fn<TelegramTransport["send"]>(); api.send = send;
  api.getUpdates = async () => ({ ok: false, code: "CONCURRENT_POLLING", permanent: true, retryAfter: 0 });
  db.prepare("UPDATE telegram_state SET worker_until=0,worker_owner=NULL").run();
  await expect(runTelegramSession(db, api, new AbortController().signal, () => {}, () => now, "new-worker", KEY)).rejects.toThrow("CONCURRENT_POLLING");
  expect(send).not.toHaveBeenCalled();
});

it("real Node operator CLI accepts private stdin, sanitizes failures and never needs a token for diagnostics", () => {
  const run = (input: unknown) => spawnSync(process.execPath, ["--conditions=react-server", "scripts/telegram.mjs", "manage", "--local-operator"], {
    cwd: process.cwd(), env: { ...process.env, APP_MODE: "server", SQLITE_PATH: path }, input: JSON.stringify(input), encoding: "utf8", timeout: 15000,
  });
  const ok = run({ operation: "diagnose" }); expect(ok.status).toBe(0); expect(JSON.parse(ok.stdout)).toMatchObject({ status: "OK", configured: false, ownerReady: false });
  const denied = run({ operation: "untrusted", token: TOKEN, firstName: "Private synthetic field" });
  expect(denied.status).toBe(1); expect(JSON.parse(denied.stdout)).toEqual({ status: "FAILED", code: "COMMAND_REJECTED" });
  expect(denied.stdout + denied.stderr).not.toContain(TOKEN); expect(denied.stdout + denied.stderr).not.toContain("Private synthetic field");
});
it("a current configuration heartbeat cannot masquerade as successful polling of a rotated token", async () => {
  const instance = telegramInstance(path, true); const file = telegramConfigPath(path);
  const old = { token: TOKEN, botId: "123456", instance, key: KEY }; saveTelegramConfiguration(file, old);
  db.prepare("UPDATE telegram_state SET last_poll_at=?,worker_config=? WHERE id=1").run(now, digestToken(JSON.stringify(old)));
  expect(technicalStatus(db, path, now).workerLive).toBe(true);
  saveTelegramConfiguration(file, { ...old, token: "123456:" + "U".repeat(35) });
  expect(technicalStatus(db, path, now).workerLive).toBe(false);
  expect(technicalStatus(db, path, now + 60001).workerLive).toBe(false);
});
it("update cursor, pending request and owner notification all roll back on a control queue write failure", async () => {
  await bootstrap(); received(222, "/start"); await drain();
  const before = telegramState(db).update_offset;
  db.exec("CREATE TRIGGER fixture_control_failure BEFORE INSERT ON telegram_control_outbox BEGIN SELECT RAISE(ABORT,'fixture_write_failure'); END");
  expect(() => received(222, SUBSCRIBE)).toThrow();
  expect(telegramState(db).update_offset).toBe(before);
  expect(db.prepare("SELECT count(*) n FROM telegram_subscription_requests").get()).toEqual({ n: 0 });
  db.exec("DROP TRIGGER fixture_control_failure");
  received(222, SUBSCRIBE); await drain(); expect(db.prepare("SELECT count(*) n FROM telegram_subscription_requests").get()).toEqual({ n: 1 });
});
it("removal invalidates an outstanding transfer; old-owner queued decisions are cancelled on role change", async () => {
  await bootstrap(); received(222, "/start"); await drain();
  await menu(111, "Передача прав"); await tap(111, button(111, "Выбрать")); await tap(111, button(111, "Подтверждаю передачу"));
  const accept = button(222, "Принять права");
  await menu(111, "Сотрудники"); await tap(111, button(111, "Удалить доступ")); await tap(111, button(111, "Подтвердить удаление"));
  received(222, SUBSCRIBE); await drain(); await tap(222, accept); expect(ownerIs(db, recipient(111).id)).toBe(true);
  await menu(111, "Передача прав"); await tap(111, button(111, "Выбрать")); await tap(111, button(111, "Подтверждаю передачу"));
  received(333, SUBSCRIBE); const deliveredBefore = messages.filter(m => m.chat === "111" && m.text.includes("Новая заявка")).length;
  await tap(222, button(222, "Принять права"));
  expect(ownerIs(db, recipient(222).id)).toBe(true);
  expect(messages.filter(m => m.chat === "111" && m.text.includes("Новая заявка"))).toHaveLength(deliveredBefore);
  expect(db.prepare("SELECT count(*) n FROM telegram_control_outbox WHERE owner_epoch IS NOT NULL AND recipient_id=? AND status='pending'").get(recipient(111).id)).toEqual({ n: 0 });
});

it("official Bot API methods carry literal text/buttons and callbacks without leaking a token to logs", async () => {
  const bodies: { method: string; body: Record<string, unknown> }[] = [];
  const fake: typeof fetch = async (input, options) => {
    const method = new URL(String(input)).pathname.split("/").pop()!;
    bodies.push({ method, body: JSON.parse(String(options?.body)) });
    const result = method === "getWebhookInfo" ? { url: "" } : method === "sendMessage" ? { message_id: 1 } : method === "getUpdates" ? [] : true;
    return new Response(JSON.stringify({ ok: true, result }), { status: 200 });
  };
  const client = new TelegramClient(TOKEN, fake);
  await client.webhookInfo(); await client.commands(); await client.getUpdates(19); await client.answerCallback("fixture_callback");
  const markup: TelegramMarkup = { inline_keyboard: [[{ text: "Одобрить", callback_data: "fixture" }]] };
  await client.send("111", "<script> & [literal] Тест", 5000, undefined, markup);
  expect(bodies.map(b => b.method)).toEqual(["getWebhookInfo", "setMyCommands", "getUpdates", "answerCallbackQuery", "sendMessage"]);
  expect(bodies[2].body).toMatchObject({ offset: 19, allowed_updates: ["message", "callback_query"] });
  expect(bodies[4].body).toMatchObject({ text: "<script> & [literal] Тест", reply_markup: markup });
  expect(bodies[4].body).not.toHaveProperty("parse_mode"); expect(JSON.stringify(bodies)).not.toContain(TOKEN);
});
it("the existing long-poll session routes Telegram updates to subscription UI and reports the actual configuration", async () => {
  await bootstrap(); db.prepare("UPDATE telegram_state SET worker_until=0,worker_owner=NULL,next_send_at=0").run();
  const controller = new AbortController(); const event: TelegramUpdate = { update_id: update++, message: { text: SUBSCRIBE,
    from: { id: 222, is_bot: false, first_name: "Тест сотрудник" }, chat: { id: 222, type: "private" } } };
  const fingerprint = digestToken("fixture-current-configuration");
  api.getUpdates = async (offset) => ({ ok: true, value: offset <= event.update_id ? [event] : [] });
  api.send = async (chat, text, _timeout, _signal, markup) => {
    messages.push({ chat, text, markup });
    if (chat === "111" && text.includes("Новая заявка")) controller.abort();
    return { ok: true, value: messages.length };
  };
  const advance = setInterval(() => { now += 1200; }, 100);
  const timeout = setTimeout(() => controller.abort(), 5000);
  try { await runTelegramSession(db, api, controller.signal, () => {}, () => now, "session-owner", KEY, fingerprint); }
  finally { clearInterval(advance); clearTimeout(timeout); }
  expect(db.prepare("SELECT status FROM telegram_subscription_requests WHERE recipient_id=?").get(recipient(222).id)).toEqual({ status: "pending" });
  expect(messages.some(m => m.chat === "111" && m.text.includes("Новая заявка"))).toBe(true);
  expect(telegramState(db)).toMatchObject({ worker_config: fingerprint, update_offset: event.update_id + 1, worker_until: 0, worker_owner: null });
  expect(recipient(222).active).toBe(0);
});
