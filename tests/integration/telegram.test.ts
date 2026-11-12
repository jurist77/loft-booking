import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import type Database from "better-sqlite3";
import { databaseSettings } from "../../src/server/config";
import { initializeDatabase, openDatabase } from "../../src/server/database";
import { migrate } from "../../src/server/migrations";
import { backupDatabase, restoreDatabase } from "../../src/server/backup";
import { createBooking, cancelBooking } from "../../src/server/bookings";
import { TelegramAdministration } from "../../src/server/telegram/admin";
import { acceptUpdates, acquireWorker, createInvite, digestToken, registerBot, setRecipientActive, setTelegramEnabled, revokeRecipient } from "../../src/server/telegram/model";
import { expireTelegramJobs, runTelegramSession, TelegramDeliveryWorker } from "../../src/server/telegram/worker";
import { loadTelegramConfiguration } from "../../src/server/telegram/config";
import type { TelegramResult, TelegramTransport, TelegramUpdate } from "../../src/server/telegram/client";

let folder: string; let path: string; let db: Database.Database; let at: number; let update: number;
const migrations = resolve("migrations/sqlite"); const owner = "fixture-worker";
const now = () => at;
const rows = () => db.prepare("SELECT * FROM telegram_outbox ORDER BY recipient_id,id").all() as Record<string, unknown>[];
const base = () => ({ id: "fictional-booking", resourceId: "studio-19-25", date: "2030-01-15", start: 600, end: 660, firstName: "Тест", lastName: "Пример", phone: "+79000000000" });
function book(extra = {}) { return createBooking(db, { ...base(), ...extra }, new Date(at)); }
const api = (send: TelegramTransport["send"] = async () => ({ ok: true, value: 1 })): TelegramTransport => ({
  getMe: async () => ({ ok: true, value: { id: 123456, username: "StudioFixtureBot" } }), getUpdates: async () => ({ ok: true, value: [] }), send,
});
function connect(id: number, name = "Вымышленный сотрудник") {
  const invite = createInvite(db, name, at); const token = new URL(invite.link).searchParams.get("start")!;
  acceptUpdates(db, owner, [{ update_id: update++, message: { text: "/start " + token, from: { id, is_bot: false }, chat: { id, type: "private" } } }], at);
  return invite.recipientId;
}
beforeEach(async () => {
  at = Date.parse("2030-01-15T08:00:00+03:00"); update = 1;
  folder = mkdtempSync(join(tmpdir(), "studio-telegram-test-")); path = join(folder, "studio.sqlite");
  const settings = databaseSettings({ APP_MODE: "server", SQLITE_PATH: path }); initializeDatabase(settings); db = openDatabase(settings);
  await migrate(db, migrations); acquireWorker(db, owner, at); registerBot(db, { id: 123456, username: "StudioFixtureBot" }); setTelegramEnabled(db, true);
});
afterEach(() => { if (db?.open) db.close(); rmSync(folder, { recursive: true, force: true }); });

it("creates one atomic job per active connected recipient, never on replay or historical migration", () => {
  connect(111); connect(222); const off = connect(333); setRecipientActive(db, off, false, at);
  createInvite(db, "Не подключён", at); book(); book();
  expect(rows()).toHaveLength(2); expect(rows().every((r) => r.booking_id === base().id && r.status === "pending")).toBe(true);
  expect(() => book({ firstName: "Изменено" })).toThrow("BOOKING_ID_CONFLICT"); expect(rows()).toHaveLength(2);
});
it("rolls back booking, event and outbox together on a failed queue write", () => {
  connect(111);
  db.exec("CREATE TRIGGER fixture_queue_failure BEFORE INSERT ON telegram_outbox BEGIN SELECT RAISE(ABORT,'fixture'); END");
  expect(() => book()).toThrow("STORAGE_FAILURE");
  expect(db.prepare("SELECT count(*) AS n FROM bookings").get()).toEqual({ n: 0 });
  expect(db.prepare("SELECT count(*) AS n FROM booking_events").get()).toEqual({ n: 0 }); expect(rows()).toEqual([]);
});
it("sends independently to multiple recipients and permanent failure never cancels a booking", async () => {
  connect(111); connect(222); book();
  const send = vi.fn<TelegramTransport["send"]>(async (chat) => chat === "111" ? { ok: false, code: "RECIPIENT_UNREACHABLE", permanent: true, retryAfter: 0 } : { ok: true, value: 1 });
  const worker = new TelegramDeliveryWorker(db, owner, api(send), now);
  await worker.dispatch(); at += 1200; await worker.dispatch();
  expect(send).toHaveBeenCalledTimes(2); expect(rows().map((r) => r.status).sort()).toEqual(["failed", "sent"]);
  expect(db.prepare("SELECT status FROM bookings").get()).toEqual({ status: "confirmed" });
});
it("disabled, revoked or rebound recipients cancel existing tasks and never get future tasks", async () => {
  const id = connect(111); book(); setRecipientActive(db, id, false, at);
  const send = vi.fn<TelegramTransport["send"]>(async () => ({ ok: true, value: 1 }));
  await new TelegramDeliveryWorker(db, owner, api(send), now).dispatch(); expect(send).not.toHaveBeenCalled();
  expect(rows()[0].status).toBe("cancelled"); setRecipientActive(db, id, true, at);
  await new TelegramDeliveryWorker(db, owner, api(send), now).dispatch(); expect(send).not.toHaveBeenCalled();
  revokeRecipient(db, id, at); book({ id: "another", start: 660, end: 720 }); expect(rows()).toHaveLength(1);
});
it("serializes recipient/global disable against send initiation without holding SQLite during network wait", async () => {
  const id = connect(111); book();
  const other = openDatabase(databaseSettings({ APP_MODE: "server", SQLITE_PATH: path, SQLITE_BUSY_TIMEOUT_MS: "50" }));
  let resolveSend!: (r: TelegramResult<number>) => void;
  const send = vi.fn<TelegramTransport["send"]>(() => {
    expect(() => other.prepare("UPDATE telegram_recipients SET active=0 WHERE id=?").run(id)).toThrow();
    return new Promise((resolve) => { resolveSend = resolve; });
  });
  try {
    const pending = new TelegramDeliveryWorker(db, owner, api(send), now).dispatch();
    // HTTP has begun and the short DB lock has ALREADY been released.
    setRecipientActive(other, id, false, at); setTelegramEnabled(other, false);
    resolveSend({ ok: true, value: 1 }); await pending;
    expect(rows()[0].status).toBe("cancelled"); expect(send).toHaveBeenCalledTimes(1);
    await new TelegramDeliveryWorker(db, owner, api(send), now).dispatch(); expect(send).toHaveBeenCalledTimes(1);
  } finally { other.close(); }
});
it("disable committed before dispatch prevents any HTTP initiation", async () => {
  const id = connect(111); book(); setRecipientActive(db, id, false, at);
  const send = vi.fn<TelegramTransport["send"]>(); await new TelegramDeliveryWorker(db, owner, api(send), now).dispatch(); expect(send).not.toHaveBeenCalled();
});
it("retries temporary failure with backoff, handles 429 globally and respects the full 24h deadline", async () => {
  connect(111); book();
  const send = vi.fn<TelegramTransport["send"]>().mockResolvedValueOnce({ ok: false, code: "RATE_LIMITED", permanent: false, retryAfter: 30000 }).mockResolvedValue({ ok: true, value: 1 });
  const worker = new TelegramDeliveryWorker(db, owner, api(send), now);
  await worker.dispatch(); expect(rows()[0].status).toBe("pending"); at += 2000; await worker.dispatch(); expect(send).toHaveBeenCalledTimes(1);
  at += 28000; await worker.dispatch(); expect(rows()[0].status).toBe("sent");
  at += 1200; book({ id: "late", start: 660, end: 720 });
  send.mockResolvedValue({ ok: false, code: "TEMPORARY_FAILURE", permanent: false, retryAfter: 86400000 });
  await worker.dispatch(); const pending = rows().find((r) => r.booking_id === "late")!; expect(pending.status).toBe("pending"); expect(pending.attempts).toBe(1);
  at = Number(pending.deadline_at); acquireWorker(db, owner, at); await worker.dispatch();
  expect(rows().find((r) => r.booking_id === "late")?.last_error).toBe("DELIVERY_EXPIRED"); expect(send).toHaveBeenCalledTimes(3);
});
it("global off pauses both old/new tasks; re-enable sends fresh tasks but never expired ones", async () => {
  connect(111); setTelegramEnabled(db, false); book();
  const send = vi.fn<TelegramTransport["send"]>(async () => ({ ok: true, value: 1 })); const worker = new TelegramDeliveryWorker(db, owner, api(send), now);
  await worker.dispatch(); expect(send).not.toHaveBeenCalled(); setTelegramEnabled(db, true); await worker.dispatch(); expect(send).toHaveBeenCalledTimes(1);
  setTelegramEnabled(db, false); book({ id: "expired", start: 660, end: 720 }); at += 86400000;
  acquireWorker(db, owner, at); await worker.dispatch(); setTelegramEnabled(db, true); await worker.dispatch();
  expect(send).toHaveBeenCalledTimes(1); expect(rows().find((r) => r.booking_id === "expired")?.status).toBe("failed");
});
it("restart/backup/restore preserve recipients, settings, update position, jobs and idempotency", async () => {
  connect(111); book(); const offset = db.prepare("SELECT update_offset FROM telegram_state").get();
  const snapshot = join(folder, "snapshot.sqlite"); await backupDatabase(db, snapshot); db.close();
  const restoredPath = join(folder, "restored.sqlite"); await restoreDatabase(snapshot, restoredPath);
  db = openDatabase(databaseSettings({ APP_MODE: "server", SQLITE_PATH: restoredPath })); expect(await migrate(db, migrations)).toEqual([]);
  expect(db.prepare("SELECT update_offset FROM telegram_state").get()).toEqual(offset); expect(rows()).toHaveLength(1);
  book(); expect(rows()).toHaveLength(1); at += 61000; expect(acquireWorker(db, "replacement", at)).toBe(true);
  const send = vi.fn<TelegramTransport["send"]>(async () => ({ ok: true, value: 1 }));
  await new TelegramDeliveryWorker(db, "replacement", api(send), now).dispatch(); expect(send).toHaveBeenCalledTimes(1); expect(rows()[0].status).toBe("sent");
});
it("recovers an abandoned sending claim, rejects concurrent workers and stale acknowledgements", async () => {
  connect(111); book(); let finish!: (r: TelegramResult<number>) => void;
  const pending = new TelegramDeliveryWorker(db, owner, api(() => new Promise((resolve) => { finish = resolve; })), now).dispatch();
  expect(acquireWorker(db, "other", at)).toBe(false); at += 61000; expect(acquireWorker(db, "other", at)).toBe(true);
  const send = vi.fn<TelegramTransport["send"]>(async () => ({ ok: true, value: 2 }));
  await new TelegramDeliveryWorker(db, "other", api(send), now).dispatch(); finish({ ok: false, code: "NETWORK_UNCERTAIN", permanent: false, retryAfter: 0 }); await pending;
  expect(rows()[0].status).toBe("sent"); expect(rows()[0].attempts).toBe(2);
});
it("recovers a committed pending attempt after a real worker SIGKILL without duplicating the job", async () => {
  connect(111); book();db.prepare('UPDATE telegram_state SET worker_until=0').run();
  const child=spawn(process.execPath,['--conditions=react-server','tests/integration/telegram-crash-worker.mjs'],{
    env:{...process.env,APP_MODE:'server',SQLITE_PATH:path,TELEGRAM_TEST_NOW:String(at)},stdio:['ignore','pipe','pipe']});
  let output='';child.stdout.on('data',(chunk)=>{output+=chunk;});child.stderr.on('data',()=>{});
  const ended=new Promise<void>((resolve)=>child.once('close',()=>resolve()));
  try {
    await vi.waitFor(()=>expect(output.includes('CLAIM_COMMITTED')).toBe(true),{timeout:4000,interval:20});
    expect(rows()[0].status).toBe('sending');child.kill('SIGKILL');await ended;expect(child.signalCode).toBe('SIGKILL');
    at+=61000;expect(acquireWorker(db,'restart',at)).toBe(true);
    const send=vi.fn<TelegramTransport['send']>(async()=>({ok:true,value:1}));
    await new TelegramDeliveryWorker(db,'restart',api(send),now).dispatch();
    expect(rows()).toHaveLength(1);expect(rows()[0].status).toBe('sent');expect(rows()[0].attempts).toBe(2);
  } finally {if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await ended;}
});
it("polling and sending stop cleanly, persist update position and restart under a new lease owner", async () => {
  connect(111);book();db.prepare('UPDATE telegram_state SET worker_until=0').run();
  const stop=new AbortController();let polls=0;
  const send=vi.fn<TelegramTransport['send']>(async()=>({ok:true,value:1}));
  const transport=api(send);
  transport.getUpdates=async()=>{polls++;return {ok:true,value:[{update_id:999}]};};
  const session=runTelegramSession(db,transport,stop.signal,()=>{},now,'session-one');
  await vi.waitFor(()=>expect(rows()[0].status).toBe('sent'),{timeout:2000});stop.abort();await session;
  expect(polls).toBeGreaterThan(0);expect(db.prepare('SELECT update_offset FROM telegram_state').get()).toEqual({update_offset:1000});
  at+=1200;book({id:'second',start:660,end:720});
  const again=new AbortController();const offsets:number[]=[];
  const second=api(send);second.getUpdates=async(offset,signal)=>{
    offsets.push(offset);return new Promise((resolve)=>{if(signal?.aborted)resolve({ok:true,value:[]});else signal?.addEventListener('abort',()=>resolve({ok:true,value:[]}),{once:true});});};
  const restarted=runTelegramSession(db,second,again.signal,()=>{},now,'session-two');
  await vi.waitFor(()=>expect(rows().filter(r=>r.status==='sent')).toHaveLength(2),{timeout:2000});again.abort();await restarted;
  expect(offsets[0]).toBe(1000);expect(send).toHaveBeenCalledTimes(2);
});
it("uses hashed expiring single-use invitations and persists token use with update cursor atomically", () => {
  const invitation = createInvite(db, "Сотрудник", at); const token = new URL(invitation.link).searchParams.get("start")!;
  expect(JSON.stringify(db.prepare("SELECT * FROM telegram_invitations").all()).includes(token)).toBe(false);
  const message: TelegramUpdate = { update_id: 1, message: { text: "/start " + token, from: { id: 111, is_bot: false }, chat: { id: 111, type: "private" } } };
  acceptUpdates(db, owner, [message], at); acceptUpdates(db, owner, [message], at);
  expect(db.prepare("SELECT count(*) AS n FROM telegram_recipients WHERE connection_status='connected'").get()).toEqual({ n: 1 });
  expect(db.prepare("SELECT used_at FROM telegram_invitations WHERE token_hash=?").get(digestToken(token))).toEqual({ used_at: at });
  expect(db.prepare("SELECT update_offset FROM telegram_state").get()).toEqual({ update_offset: 2 });
  const another = { ...message, update_id: 2, message: { ...message.message!, from: { id: 222, is_bot: false }, chat: { id: 222, type: "private" } } };
  acceptUpdates(db, owner, [another], at);
  expect(db.prepare("SELECT telegram_user_id FROM telegram_recipients").get()).toEqual({ telegram_user_id: "111" });
});
it("rejects spoofed/group/bot identities, expiry and excessive attempts; never treats submitted IDs as proof", () => {
  const invitation = createInvite(db, "Сотрудник", at); const token = new URL(invitation.link).searchParams.get("start")!;
  for (const message of [
    { from: { id: 111, is_bot: false }, chat: { id: 222, type: "private" } },
    { from: { id: 111, is_bot: false }, chat: { id: 111, type: "group" } },
    { from: { id: 111, is_bot: true }, chat: { id: 111, type: "private" } },
  ]) acceptUpdates(db, owner, [{ update_id: update++, message: { ...message, text: "/start " + token } }], at);
  for (let n = 0; n < 10; n++) acceptUpdates(db, owner, [{ update_id: update++, message: { text: "/start " + "a".repeat(43), from: { id: 111, is_bot: false }, chat: { id: 111, type: "private" } } }], at);
  acceptUpdates(db, owner, [{ update_id: update++, message: { text: "/start " + token, from: { id: 111, is_bot: false }, chat: { id: 111, type: "private" } } }], at);
  expect(db.prepare("SELECT connection_status FROM telegram_recipients").get()).toEqual({ connection_status: "invited" });
  at += 3600001; acquireWorker(db, owner, at);
  acceptUpdates(db, owner, [{ update_id: update++, message: { text: "/start " + token, from: { id: 222, is_bot: false }, chat: { id: 222, type: "private" } } }], at);
  expect(db.prepare("SELECT used_at FROM telegram_invitations").get()).toEqual({ used_at: null });
});
it("rolls back invitation consumption if durable cursor write fails, and supports more than one/small handful of recipients", () => {
  const invite = createInvite(db, "Сотрудник", at); const token = new URL(invite.link).searchParams.get("start")!;
  db.exec("CREATE TRIGGER fixture_cursor_failure BEFORE UPDATE OF update_offset ON telegram_state BEGIN SELECT RAISE(ABORT,'fixture'); END");
  expect(() => acceptUpdates(db, owner, [{ update_id: 1, message: { text: "/start " + token, from: { id: 111, is_bot: false }, chat: { id: 111, type: "private" } } }], at)).toThrow("TELEGRAM_STORAGE_UNAVAILABLE");
  expect(db.prepare("SELECT used_at FROM telegram_invitations").get()).toEqual({ used_at: null });
  db.exec("DROP TRIGGER fixture_cursor_failure"); for (let i = 1; i <= 40; i++) connect(1000 + i); book(); expect(rows()).toHaveLength(40);
});
it("requires verified administrative rights, keeps bootstrap local and exposes only technical delivery fields", async () => {
  const no = new TelegramAdministration(db); await expect(no.enabled(true)).rejects.toThrow("AUTHORIZATION_REQUIRED");
  const denied = new TelegramAdministration(db, async () => ({ authenticated: true, subject: "fixture", permissions: [] }));
  await expect(denied.invite("name")).rejects.toThrow("AUTHORIZATION_REQUIRED");
  const admin = new TelegramAdministration(db, async () => ({ authenticated: true, subject: "fixture-owner", permissions: ["telegram:manage"] }), now);
  const bootstrap = createInvite(db, "Владелец", at, undefined, true); expect(bootstrap.recipientId).toBeTruthy();
  expect(() => createInvite(db, "Другой владелец", at, undefined, true)).toThrow("OWNER_ALREADY_BOOTSTRAPPED");
  const id = connect(111); book(); await admin.test(id);
  const statuses = await admin.deliveries(); const text = JSON.stringify(statuses);
  expect(text.includes(base().phone)).toBe(false); expect(text.includes(base().firstName)).toBe(false); expect(rows()).toHaveLength(2);
});
it("cancellation cancels pending creation notifications without sending a cancellation message", async () => {
  connect(111); book(); cancelBooking(db, base().id, new Date(at));
  const send = vi.fn<TelegramTransport["send"]>(); await new TelegramDeliveryWorker(db, owner, api(send), now).dispatch();
  expect(send).not.toHaveBeenCalled(); expect(rows()[0].last_error).toBe("BOOKING_CANCELLED");
});
it("configuration stays outside SQLite, private across updates, and refuses exposed/symlinked settings", () => {
  const settings = join(folder, "settings"); mkdirSync(settings, { mode: 0o700 }); const file = join(settings, "telegram-bot.json");
  const token = "123456:" + "Z".repeat(35); writeFileSync(file, JSON.stringify({ version: 1, token }), { mode: 0o600 });
  expect(loadTelegramConfiguration(file).token === token).toBe(true); chmodSync(file, 0o644);
  expect(() => loadTelegramConfiguration(file)).toThrow("TELEGRAM_CONFIGURATION_UNAVAILABLE");
  expect(JSON.stringify(db.prepare("SELECT * FROM telegram_state").get()).includes(token)).toBe(false);
});
it("upgrades an old database without changing old SQL/history/bookings or creating retrospective jobs", async () => {
  db.close(); const old = join(folder, "old"); mkdirSync(old);
  for (const name of ["0001_foundation.sql", "0002_booking_model.sql"]) writeFileSync(join(old, name), readFileSync(join(migrations, name)));
  const legacyPath = join(folder, "legacy.sqlite"); const settings = databaseSettings({ APP_MODE: "server", SQLITE_PATH: legacyPath }); initializeDatabase(settings); db = openDatabase(settings);
  await migrate(db, old); book(); const saved = db.prepare("SELECT * FROM bookings").all(); const history = db.prepare("SELECT * FROM schema_migrations").all();
  expect(await migrate(db, migrations)).toEqual([3, 4]); expect(db.prepare("SELECT * FROM bookings").all()).toEqual(saved);
  expect(db.prepare("SELECT * FROM schema_migrations WHERE version<3").all()).toEqual(history); expect(rows()).toEqual([]);
  expireTelegramJobs(db, at + 86400000);
});

it("runs the actual Node operator CLI with OS-only authorization and protected invitation output", () => {
  const cli = (...args: string[]) => spawnSync(process.execPath, ["--conditions=react-server", "scripts/telegram.mjs", ...args], {
    cwd: process.cwd(), env: { ...process.env, APP_MODE: "server", SQLITE_PATH: path }, encoding: "utf8", timeout: 10000,
  });
  const status = cli("status"); expect(status.status, status.stderr).toBe(0);
  expect(JSON.parse(status.stdout)).toMatchObject({ enabled: true, botReady: true, configurationReady: false });
  expect(cli("disable").status).toBe(1); expect(db.prepare("SELECT enabled FROM telegram_state").get()).toEqual({ enabled: 1 });
  expect(cli("disable", "--local-operator").status).toBe(0);
  const file = join(folder, "owner-link.txt"); const result = cli("bootstrap-owner", "--local-operator", "--invite-file", file);
  expect(result.status, result.stderr).toBe(0); expect(JSON.parse(result.stdout).invitationWritten).toBe(true);
  const link = readFileSync(file,"utf8").trim(); expect(link).toMatch(/^https:\/\/t\.me\/StudioFixtureBot\?start=/);
  expect(statSync(file).mode & 0o777).toBe(0o600); expect(result.stdout + result.stderr).not.toContain(link);
  expect(cli("bootstrap-owner", "--local-operator", "--invite-file", join(folder,"second.txt")).stderr).toContain("OWNER_ALREADY_BOOTSTRAPPED");
});
