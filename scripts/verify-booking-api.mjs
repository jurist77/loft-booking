// Actual production Next.js + private real SQLite. No mocks, fixed dates or real contacts.
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { chmodSync, mkdtempSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { databaseSettings } from "../src/server/config.ts";
import { initializeDatabase, openDatabase, assertIntegrity } from "../src/server/database.ts";
import { migrate } from "../src/server/migrations.ts";
import { createBooking, cancelBooking } from "../src/server/bookings.ts";
import { addDays, dateRange } from "../src/lib/availability.ts";
import { waitForHealth } from "./lib/health-probe.mjs";

const port = 3012; const base = `http://127.0.0.1:${port}`; const origin = "https://studio.example";
const root = mkdtempSync(join(tmpdir(), "studio-booking-http-"));
const directory = join(root, "data"); const path = join(directory, "test.sqlite");
const dbConfig = databaseSettings({ APP_MODE: "server", SQLITE_PATH: path, SQLITE_BUSY_TIMEOUT_MS: "100" });
const range = dateRange(); const date = addDays(range.first, 1);
const body = (overrides = {}) => ({ requestId: randomUUID(), resourceId: "studio-19-25", date, start: "12:00", end: "14:00", firstName: "Тест", lastName: "Пример", phone: "8 (900) 000-00-00", ...overrides });
let db; let server; let exited; let serverDone; let logs = ""; let ipCounter = 0; let checks = 0; let phase = "setup"; let offline = false;
async function check(name, run) { phase = name; await run(); checks++; console.log(`API check passed: ${name}`); }
function alive() { if (exited) throw new Error("NEXT_EXITED"); }
async function stop() {
  if (!server || !serverDone) return;
  server.kill("SIGTERM");
  if (!await Promise.race([serverDone.then(() => true), delay(5000, false, { ref: false })])) server.kill("SIGKILL");
  if (!await Promise.race([serverDone.then(() => true), delay(3000, false, { ref: false })])) throw new Error("NEXT_CLEANUP_FAILED");
  server = undefined;
}
async function start(trustProxy) {
  exited = undefined;
  server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", String(port)], {
    env: { ...process.env, APP_MODE: "server", DEPLOY_TARGET: "node", NEXT_PUBLIC_APP_MODE: "server", NEXT_PUBLIC_BASE_PATH: "", NEXT_PUBLIC_API_BASE_URL: "", SQLITE_PATH: path, SQLITE_BUSY_TIMEOUT_MS: "100", API_PUBLIC_ORIGIN: origin, API_TRUST_PROXY: String(trustProxy), NEXT_TELEMETRY_DISABLED: "1" }, stdio: ["ignore", "pipe", "pipe"],
  });
  for (const stream of [server.stdout, server.stderr]) stream.on("data", (chunk) => { logs = (logs + chunk).slice(-65536); });
  serverDone = new Promise((resolve) => {
    server.once("error", () => { exited = "LAUNCH_FAILED"; resolve(); });
    server.once("exit", (code, signal) => { exited = { code, signal }; resolve(); });
  });
  await waitForHealth(base + "/api/health", { phase: "api-startup", expectedStatus: 200, timeoutMs: 15000, assertAlive: alive });
}
function http(url, options = {}) {
  const method = options.method ?? "GET";
  const raw = options.raw ?? (options.body === undefined ? undefined : JSON.stringify(options.body));
  const bytes = raw === undefined ? undefined : Buffer.from(raw);
  return new Promise((resolve, reject) => {
    const headers = { "x-studio-client-ip": `2001:db8::${(++ipCounter).toString(16)}`, ...(method === "POST" ? { origin, "content-type": "application/json" } : {}), ...(bytes && !options.chunked && !options.slow ? { "content-length": bytes.length } : {}), ...options.headers };
    for (const key of Object.keys(headers)) if (headers[key] === null) delete headers[key];
    const req = httpRequest(base + url, { method, headers, agent: false, signal: AbortSignal.timeout(10000) }, (res) => {
      if (options.loseReply) {
        const status = res.statusCode; res.destroy(); req.destroy();
        if (status !== 201) reject(new Error("LOST_REPLY_UNEXPECTED_STATUS")); else resolve({ status: 201 });
        return;
      }
      let text = "";
      res.setEncoding("utf8"); res.on("data", (chunk) => { text += chunk; if (text.length > 16384) req.destroy(new Error("RESPONSE_TOO_LARGE")); });
      res.on("error", reject);
      res.on("end", () => { resolve({ status: res.statusCode, headers: res.headers, text }); if (options.slow) req.destroy(); });
    });
    req.on("error", reject);
    if (options.slow) req.write("{");
    else if (options.chunked && bytes) { req.write(bytes.subarray(0, 10)); req.end(bytes.subarray(10)); }
    else req.end(bytes);
  });
}
const post = (value, options = {}) => http("/api/bookings", { method: "POST", body: value, ...options });
const get = (day = date, resource) => http(`/api/availability?date=${day}${resource ? `&resourceId=${encodeURIComponent(resource)}` : ""}`);
function json(response, status) {
  assert.equal(response.status, status); assert.match(response.headers["cache-control"], /no-store/);
  assert.equal(response.headers["access-control-allow-origin"], undefined);
  for (const value of ["Тест", "Пример", "+79000000000", path, "SQLITE_", "stack", "firstName", "lastName", "phone"]) assert.ok(!response.text.includes(value));
  return JSON.parse(response.text);
}
function error(response, status, code) { const value = json(response, status); assert.deepEqual(Object.keys(value), ["error"]); assert.deepEqual(Object.keys(value.error).sort(), ["code", "message"]); assert.equal(value.error.code, code); }
const total = () => db.prepare("SELECT count(*) AS n FROM bookings").get().n;
const eventCount = (id) => db.prepare("SELECT count(*) AS n FROM booking_events WHERE booking_id=?").get(id).n;
try {
  await new Promise((resolve, reject) => { const probe = createServer(); probe.once("error", reject); probe.listen(port, "127.0.0.1", () => probe.close(resolve)); });
  initializeDatabase(dbConfig); db = openDatabase(dbConfig); await migrate(db, "migrations/sqlite");
  db.prepare("INSERT INTO resources VALUES ('test-room','Вымышленное помещение')").run();
  await start(true);
  await check("empty availability and inclusive horizon", async () => {
    assert.deepEqual(json(await get(), 200), { date, resourceId: "studio-19-25", timezone: "Europe/Moscow", busy: [] });
    json(await get(range.first), 200); json(await get(range.last), 200);
    error(await get(addDays(range.first, -1)), 400, "INVALID_DATE"); error(await get(addDays(range.last, 1)), 400, "INVALID_DATE");
    error(await get("2026-02-30"), 400, "INVALID_DATE");
    error(await http("/api/availability"), 400, "INVALID_INPUT");
    error(await http(`/api/availability?date=${date}&date=${date}`), 400, "INVALID_INPUT");
    error(await get(date, "missing"), 404, "RESOURCE_NOT_FOUND");
    error(await get(date, "x' OR 1=1--"), 404, "RESOURCE_NOT_FOUND");
  });
  const first = body();
  await check("confirmed booking and normalized phone with one creation event", async () => {
    assert.deepEqual(json(await post(first), 201), { bookingId: first.requestId, status: "confirmed", date, start: "12:00", end: "14:00", resourceId: "studio-19-25" });
    assert.equal(db.prepare("SELECT phone FROM bookings WHERE id=?").get(first.requestId).phone, "+79000000000"); assert.equal(eventCount(first.requestId), 1);
    assert.deepEqual(json(await get(), 200).busy, [{ start: "12:00", end: "14:00" }]);
  });
  await check("same ID retry, canonical contacts and changed payload conflict", async () => {
    json(await post({ ...first, phone: "+79000000000", requestId: first.requestId.toUpperCase() }), 201);
    assert.equal(total(), 1); assert.equal(eventCount(first.requestId), 1);
    error(await post({ ...first, end: "14:30" }), 409, "BOOKING_ID_CONFLICT");
    error(await post(body()), 409, "BOOKING_OVERLAP");
  });
  await check("lost HTTP reply is recovered by retrying the same ID", async () => {
    const lost = body({ date: addDays(date, 1) }); await post(lost, { loseReply: true });
    json(await post(lost), 201); assert.equal(eventCount(lost.requestId), 1);
  });
  await check("concurrent POST writes and concurrent retries", async () => {
    const otherDay = addDays(date, 2);
    const results = await Promise.all([post(body({ date: otherDay })), post(body({ date: otherDay }))]);
    assert.deepEqual(results.map((r) => r.status).sort(), [201, 409]);
    error(results.find((r) => r.status === 409), 409, "BOOKING_OVERLAP");
    const retry = body({ date: addDays(date, 3) });
    for (const response of await Promise.all([post(retry), post(retry)])) json(response, 201);
    assert.equal(eventCount(retry.requestId), 1);
  });
  await check("adjacent intervals and different resources", async () => {
    json(await post(body({ start: "14:00", end: "15:00" })), 201);
    json(await post(body({ resourceId: "test-room" })), 201);
    assert.deepEqual(json(await get(date, "test-room"), 200).busy, [{ start: "12:00", end: "14:00" }]);
    assert.deepEqual(json(await get(), 200).busy, [{ start: "12:00", end: "14:00" }, { start: "14:00", end: "15:00" }]);
    error(await post(body({ resourceId: "missing" })), 404, "RESOURCE_NOT_FOUND");
  });
  await check("cancellation stays private, frees time and cannot be reactivated by retry", async () => {
    cancelBooking(db, first.requestId);
    error(await post(first), 409, "BOOKING_CANCELLED"); assert.equal(eventCount(first.requestId), 2);
    assert.deepEqual(json(await get(), 200).busy, [{ start: "14:00", end: "15:00" }]);
    json(await post(body()), 201);
    assert.equal((await http("/api/bookings", { method: "GET" })).status, 405);
    assert.equal((await http(`/api/bookings/${first.requestId}`)).status, 404);
    assert.equal((await http(`/api/bookings/${first.requestId}/cancel`, { method: "POST", raw: "{}" })).status, 404);
  });
  await check("past confirmed retry returns original result without creating a new booking", async () => {
    const pastDate = addDays(range.first, -1); const old = body({ date: pastDate });
    createBooking(db, { id: old.requestId, resourceId: old.resourceId, date: pastDate, start: 720, end: 840, firstName: old.firstName, lastName: old.lastName, phone: old.phone }, new Date(`${pastDate}T08:00:00+03:00`));
    json(await post(old), 201); assert.equal(eventCount(old.requestId), 1);
    error(await post(body({ date: pastDate })), 400, "INVALID_INTERVAL");
  });
  await check("workday, minimum, step, contacts, UUID and closed schema", async () => {
    json(await post(body({ date: range.last, start: "22:00", end: "23:00" })), 201);
    for (const changes of [{ start: "08:30", end: "09:30" }, { start: "22:30", end: "23:00" }, { start: "12:15", end: "13:15" }]) error(await post(body(changes)), 400, "INVALID_INTERVAL");
    error(await post(body({ start: "9:00" })), 400, "INVALID_TIME");
    error(await post(body({ date: "2026-02-30" })), 400, "INVALID_DATE");
    error(await post(body({ phone: "+78000000000" })), 400, "INVALID_CONTACT");
    error(await post(body({ firstName: "a".repeat(81) })), 400, "INVALID_INPUT");
    error(await post(body({ requestId: "not-a-uuid" })), 400, "INVALID_INPUT");
    error(await post(body({ admin: "true" })), 400, "INVALID_INPUT");
  });
  await check("strict JSON, media type, UTF-8, duplicate keys and actual byte limit", async () => {
    error(await post(undefined, { raw: "{" }), 400, "INVALID_JSON");
    error(await post(undefined, { raw: '{"phone":"a","ph\\u006fne":"b"}' }), 400, "INVALID_JSON");
    error(await post(undefined, { raw: Buffer.from([0xc3, 0x28]) }), 400, "INVALID_JSON");
    error(await post(first, { headers: { "content-type": "text/plain" } }), 415, "UNSUPPORTED_MEDIA_TYPE");
    error(await post(first, { headers: { "content-encoding": "gzip" } }), 415, "UNSUPPORTED_MEDIA_TYPE");
    error(await post(undefined, { raw: "x".repeat(4097) }), 413, "BODY_TOO_LARGE");
    error(await post(undefined, { raw: "x".repeat(4097), chunked: true }), 413, "BODY_TOO_LARGE");
    error(await post(undefined, { slow: true }), 408, "REQUEST_TIMEOUT");
  });
  await check("fixed Origin rejects forgery through Host and forwarding headers", async () => {
    error(await post(first, { headers: { origin: "https://attacker.example", "x-forwarded-host": "attacker.example", "x-forwarded-proto": "https", "x-forwarded-for": "192.0.2.1" } }), 403, "ORIGIN_NOT_ALLOWED");
    error(await post(first, { headers: { origin: null } }), 403, "ORIGIN_NOT_ALLOWED");
    error(await post(first, { headers: { "sec-fetch-site": "cross-site" } }), 403, "ORIGIN_NOT_ALLOWED");
    error(await post(first, { headers: { "x-studio-client-ip": "192.0.2.1, 192.0.2.2" } }), 503, "API_UNAVAILABLE");
  });
  await check("database writer lock returns 503 and recovers with same ID", async () => {
    const pending = body({ date: addDays(date, 5) }); db.exec("BEGIN IMMEDIATE");
    try { json(await get(), 200); error(await post(pending), 503, "DATABASE_BUSY"); assert.equal((await http("/api/health")).status, 503); }
    finally { db.exec("ROLLBACK"); }
    json(await post(pending), 201); assert.equal(eventCount(pending.requestId), 1); assert.equal((await http("/api/health")).status, 200);
  });
  await check("missing DB gives safe 503 in GET/POST/health, then recovers", async () => {
    const pending = body({ date: addDays(date, 6) }); renameSync(directory, directory + "-offline"); offline = true;
    try {
      error(await get(), 503, "STORAGE_UNAVAILABLE"); error(await post(pending), 503, "STORAGE_UNAVAILABLE");
      assert.equal((await http("/api/health")).status, 503);
    } finally { renameSync(directory + "-offline", directory); offline = false; }
    json(await get(), 200); json(await post(pending), 201); assert.equal((await http("/api/health")).status, 200);
  });
  await check("readonly database fails safely and confirmed data survives", async () => {
    chmodSync(path, 0o400);
    try { error(await get(), 503, "STORAGE_UNAVAILABLE"); } finally { chmodSync(path, 0o600); }
    json(await get(), 200); assert.equal(eventCount(first.requestId), 2); assertIntegrity(db, true);
  });
  await stop(); await start(true);
  await check("real server restart preserves availability and idempotency", async () => { json(await get(), 200); error(await post(first), 409, "BOOKING_CANCELLED"); });
  await stop(); await start(true); // Fresh limiter for deterministic limits, not for DB recovery.
  await check("POST rate limit counts failed requests, ignores spoofed XFF and supplies Retry-After", async () => {
    for (let i = 0; i < 10; i++) error(await post(undefined, { raw: "{", headers: { "x-studio-client-ip": "198.51.100.1", "x-forwarded-for": `203.0.113.${i}` } }), 400, "INVALID_JSON");
    const limited = await post(undefined, { raw: "{", headers: { "x-studio-client-ip": "198.51.100.1" } }); error(limited, 429, "RATE_LIMITED"); assert.ok(Number(limited.headers["retry-after"]) > 0);
    for (let i = 0; i < 50; i++) error(await post(undefined, { raw: "{" }), 400, "INVALID_JSON");
    error(await post(undefined, { raw: "{" }), 429, "RATE_LIMITED");
  });
  await check("GET has a separate limit and health remains available", async () => {
    for (let i = 0; i < 60; i++) json(await http(`/api/availability?date=${date}`, { headers: { "x-studio-client-ip": "198.51.100.2" } }), 200);
    error(await http(`/api/availability?date=${date}`, { headers: { "x-studio-client-ip": "198.51.100.2" } }), 429, "RATE_LIMITED");
    assert.equal((await http("/api/health")).status, 200);
  });
  await stop(); await start(false);
  await check("untrusted deployment uses shared budget despite forged IP headers", async () => {
    for (let i = 0; i < 10; i++) error(await post(undefined, { raw: "{", headers: { "x-forwarded-for": `203.0.113.${i}` } }), 400, "INVALID_JSON");
    error(await post(undefined, { raw: "{" }), 429, "RATE_LIMITED");
  });
  for (const value of ["Тест", "Пример", "+79000000000"]) assert.ok(!logs.includes(value));
  console.log(`Booking API HTTP: ${checks} checks passed; real SQLite, real Next.js, no contact data in responses/logs`);
} catch (failure) {
  const safe = (v) => typeof v === "number" || (typeof v === "string" && /^[A-Z_]+$/.test(v)) ? v : "suppressed";
  const line = /verify-booking-api\.mjs:(\d+):/.exec(failure.stack ?? "")?.[1] ?? "unknown";
  console.error(`Booking API HTTP failed; phase=${phase}; kind=${failure.name}; expected=${safe(failure.expected)}; actual=${safe(failure.actual)}; testLine=${line}; Next=${exited ? "exited" : "running"}`);
  process.exitCode = 1;
} finally {
  try { if (offline) { renameSync(directory + "-offline", directory); offline = false; } await stop(); }
  finally { if (db?.open) db.close(); rmSync(root, { recursive: true, force: true }); }
}
