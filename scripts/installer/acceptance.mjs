// Isolated technical acceptance: never points at the production SQLite file.
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { initializeDatabase, openDatabase } from "../../src/server/database.ts";
import { migrate } from "../../src/server/migrations.ts";

const root = await mkdtemp(join(process.env.STUDIO_ACCEPTANCE_DIR || "/backups", "acceptance-"));
const path = join(root, "test.sqlite");
let child; let done;
const port = await new Promise((resolve, reject) => {
  const server = createServer(); server.once("error", reject);
  server.listen(0, "127.0.0.1", () => { const value = server.address().port; server.close(() => resolve(value)); });
});
const origin = `http://127.0.0.1:${port}`;
const env = { ...process.env, APP_MODE: "server", DEPLOY_TARGET: "node", SQLITE_PATH: path,
  API_PUBLIC_ORIGIN: origin, API_TRUST_PROXY: "false", NEXT_TELEMETRY_DISABLED: "1" };
async function stop() {
  if (!child) return;
  child.kill("SIGTERM");
  if (!await Promise.race([done.then(() => true), delay(5000, false, { ref: false })])) child.kill("SIGKILL");
  if (!await Promise.race([done.then(() => true), delay(3000, false, { ref: false })])) throw new Error("CLEANUP_FAILED");
  child = undefined;
}
async function start() {
  child = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", String(port)], { env, stdio: "ignore" });
  done = new Promise((resolve) => { child.once("error", resolve); child.once("exit", resolve); });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(origin + "/api/health", { signal: AbortSignal.timeout(1000) })).status === 200) return; } catch {}
    await delay(100);
  }
  throw new Error("ACCEPTANCE_START_FAILED");
}
try {
  const settings = { path, busyTimeout: 1000 }; initializeDatabase(settings);
  const db = openDatabase(settings); try { await migrate(db, "migrations/sqlite"); } finally { db.close(); }
  await start();
  const date = new Date(Date.now() + 2 * 86400000).toISOString().slice(0, 10);
  const available = await fetch(origin + "/api/availability?date=" + date);
  if (available.status !== 200 || (await available.json()).busy.length !== 0) throw new Error("AVAILABILITY_FAILED");
  const body = { requestId: randomUUID(), resourceId: "studio-19-25", date, start: "12:00", end: "13:00",
    firstName: "Тестовый", lastName: "Персонаж", phone: "+79991234567" };
  const send = (data) => fetch(origin + "/api/bookings", { method: "POST", headers: { "Content-Type": "application/json", Origin: origin }, body: JSON.stringify(data) });
  if ((await send(body)).status !== 201 || (await send({ ...body, requestId: randomUUID() })).status !== 409) throw new Error("BOOKING_CONFLICT_FAILED");
  await stop(); await start();
  const busy = await (await fetch(origin + "/api/availability?date=" + date)).json();
  if (busy.busy.length !== 1 || busy.busy[0].start !== "12:00") throw new Error("PERSISTENCE_FAILED");
  console.log("TECHNICAL_ACCEPTANCE_OK: isolated SQLite, real HTTP, booking/conflict/restart");
} catch {
  console.error("TECHNICAL_ACCEPTANCE_FAILED"); process.exitCode = 1;
} finally { try { await stop(); } finally { await rm(root, { recursive: true, force: true }); } }
