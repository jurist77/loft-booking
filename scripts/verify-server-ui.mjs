import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { get } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { databaseSettings } from "../src/server/config.ts";
import { initializeDatabase, openDatabase } from "../src/server/database.ts";
import { migrate } from "../src/server/migrations.ts";
import { waitForHealth } from "./lib/health-probe.mjs";

const root = mkdtempSync(join(tmpdir(), "studio-server-ui-")); const path = join(root, "test.sqlite");
const children = []; const port = 3014; const demoPort = 4174;
const env = { ...process.env, APP_MODE: "server", DEPLOY_TARGET: "node", NEXT_PUBLIC_APP_MODE: "server", NEXT_PUBLIC_BASE_PATH: "", NEXT_PUBLIC_API_BASE_URL: "", SQLITE_PATH: path, STUDIO_E2E_DB: path, SQLITE_BUSY_TIMEOUT_MS: "100", API_PUBLIC_ORIGIN: `http://127.0.0.1:${port}`, API_TRUST_PROXY: "true", NEXT_TELEMETRY_DISABLED: "1", SERVER_BASE_URL: `http://127.0.0.1:${port}/`, DEMO_BASE_URL: `http://127.0.0.1:${demoPort}/loft-booking/` };
function start(args, childEnv) {
  const child = spawn(process.execPath, args, { env: childEnv, stdio: "ignore" });
  const item = { child, exited: false, done: null };
  item.done = new Promise((resolve) => { child.once("error", () => { item.exited = true; resolve(); }); child.once("exit", () => { item.exited = true; resolve(); }); });
  children.push(item); return item;
}
async function command(args, childEnv = env) {
  const child = spawn(process.execPath, args, { env: childEnv, stdio: "inherit" });
  const done = new Promise((resolve) => { child.once("error", () => resolve(1)); child.once("exit", (code) => resolve(code ?? 1)); });
  const item = { child, done }; children.push(item);
  if (await done !== 0) throw new Error("UI_CHECK_FAILED");
}
try {
  for (const p of [port, demoPort]) await new Promise((resolve, reject) => { const probe = createServer(); probe.once("error", reject); probe.listen(p, "127.0.0.1", () => probe.close(resolve)); });
  const settings = databaseSettings(env); initializeDatabase(settings); const db = openDatabase(settings);
  try { await migrate(db, "migrations/sqlite"); } finally { db.close(); }
  const server = start(["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", String(port)], env);
  await waitForHealth(env.SERVER_BASE_URL + "api/health", { phase: "ui-startup", expectedStatus: 200, timeoutMs: 15000, assertAlive() { if (server.exited) throw new Error("NEXT_EXITED"); } });
  start(["scripts/serve-demo.mjs"], { ...env, DEMO_PORT: String(demoPort), NEXT_PUBLIC_BASE_PATH: "/loft-booking" });
  let ready = false;
  for (let i = 0; i < 30; i++) {
    try { ready = await new Promise((resolve, reject) => { const r = get(env.DEMO_BASE_URL, { agent: false }, (response) => { response.resume(); resolve(response.statusCode === 200); }); r.on("error", reject); }); } catch {}
    if (ready) break; await delay(100);
  }
  if (!ready) throw new Error("DEMO_NOT_READY");
  if (!process.argv.includes("--capture-only")) {
    await command(["node_modules/@playwright/test/cli.js", "test", "--config=playwright.server.config.ts", `--output=${join(root, "server-results")}`]);
    await command(["node_modules/@playwright/test/cli.js", "test", `--output=${join(root, "demo-results")}`], { ...env, PLAYWRIGHT_BASE_URL: env.DEMO_BASE_URL });
  }
  if (process.argv.includes("--capture") || process.argv.includes("--capture-only")) await command(["scripts/capture-v24.mjs"]);
  console.log("SERVER/DEMO browser checks passed; real SQLite, isolated private data");
} catch (error) { console.error(`SERVER UI check failed: ${error.name}; details are in the test output above`); process.exitCode = 1; }
finally {
  try {
    for (const item of children.reverse()) {
      item.child.kill("SIGTERM");
      if (!await Promise.race([item.done.then(() => true), delay(5000, false, { ref: false })])) item.child.kill("SIGKILL");
      if (!await Promise.race([item.done.then(() => true), delay(3000, false, { ref: false })])) throw new Error("UI_PROCESS_CLEANUP_FAILED");
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
}
