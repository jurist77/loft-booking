import { spawn } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve, sep } from "node:path";
import { createServer } from "node:net";
import { get } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { databaseSettings } from "../src/server/config.ts";
import { initializeDatabase, openDatabase } from "../src/server/database.ts";
import { migrate } from "../src/server/migrations.ts";
import { waitForHealth } from "./lib/health-probe.mjs";
import { insecureBrowserProxy } from "./lib/insecure-browser-proxy.mjs";

const root = mkdtempSync(join(tmpdir(), "studio-server-ui-"));
const children = []; const proxies = []; const serverOnly = process.argv.includes("--server-only");
const port = 3014; const demoPort = 4174;
const env = { ...process.env, APP_MODE: "server", DEPLOY_TARGET: "node", NEXT_PUBLIC_APP_MODE: "server", NEXT_PUBLIC_BASE_PATH: "", NEXT_PUBLIC_API_BASE_URL: "", SQLITE_BUSY_TIMEOUT_MS: "100", API_TRUST_PROXY: "true", NEXT_TELEMETRY_DISABLED: "1", DEMO_BASE_URL: `http://127.0.0.1:${demoPort}/loft-booking/` };
// Release CI can start the exact extracted package instead of checkout's build.
// Data always lives in our newly created private temporary directory.
let appRoot = process.cwd(); let runtime = process.execPath;
function releaseLocation() {
  const release = process.env.STUDIO_E2E_RELEASE_ROOT;
  if (!release) return;
  const location = realpathSync(release);
  const temporaryBases = [tmpdir(), process.env.RUNNER_TEMP].filter(Boolean).map((p) => realpathSync(p));
  if (location !== resolve(release) || !basename(location).startsWith("studio-browser-package-") || !temporaryBases.some((p) => location.startsWith(p + sep))) throw new Error("PRIVATE_RELEASE_FIXTURE_REQUIRED");
  appRoot = join(location, "root/app"); runtime = join(location, "root/usr/bin/node");
}
function start(args, childEnv, cwd = process.cwd(), executable = process.execPath) {
  const child = spawn(executable, args, { cwd, env: childEnv, stdio: "ignore" });
  const item = { child, exited: false, done: null };
  item.done = new Promise((resolve) => { child.once("error", () => { item.exited = true; resolve(); }); child.once("exit", () => { item.exited = true; resolve(); }); });
  children.push(item); return item;
}
async function command(args, childEnv = env) {
  const child = spawn(process.execPath, args, { env: childEnv, stdio: "inherit" });
  const done = new Promise((resolve) => { child.once("error", () => resolve(1)); child.once("exit", (code) => resolve(code ?? 1)); });
  children.push({ child, done });
  if (await done !== 0) throw new Error("UI_CHECK_FAILED");
}
async function available(p) {
  await new Promise((resolve, reject) => { const probe = createServer(); probe.once("error", reject); probe.listen(p, "127.0.0.1", () => probe.close(resolve)); });
}
async function serverJourney(kind, serverPort) {
  await available(serverPort);
  const path = join(root, `${kind}.sqlite`); const localOrigin = `http://127.0.0.1:${serverPort}`;
  const publicOrigin = kind === "insecure-http" ? `http://192.0.2.10:${serverPort}` : localOrigin;
  const childEnv = { ...env, SQLITE_PATH: path, STUDIO_E2E_DB: path, API_PUBLIC_ORIGIN: publicOrigin, API_ALLOW_INSECURE_TEST_HTTP: kind === "insecure-http" ? "true" : "false", SERVER_BASE_URL: publicOrigin + "/", STUDIO_E2E_ORIGIN_KIND: kind, STUDIO_BROWSER_PROXY_URL: "" };
  const settings = databaseSettings(childEnv); initializeDatabase(settings); const db = openDatabase(settings);
  try { await migrate(db, join(appRoot, "migrations/sqlite")); } finally { db.close(); }
  const server = start(["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", String(serverPort)], childEnv, appRoot, runtime);
  await waitForHealth(localOrigin + "/api/health", { phase: `ui-${kind}`, expectedStatus: 200, timeoutMs: 15000, assertAlive() { if (server.exited) throw new Error("NEXT_EXITED"); } });
  if (kind === "insecure-http") {
    const proxy = await insecureBrowserProxy(publicOrigin, localOrigin); proxies.push(proxy); childEnv.STUDIO_BROWSER_PROXY_URL = proxy.url;
  }
  console.log(`SERVER browser gate: ${kind}; ${process.env.STUDIO_E2E_RELEASE_ROOT ? "extracted package" : "production build"}; isolated SQLite`);
  if (!process.argv.includes("--capture-only")) await command(["node_modules/@playwright/test/cli.js", "test", "--config=playwright.server.config.ts", `--output=${join(root, `${kind}-results`)}`], childEnv);
  return childEnv;
}
try {
  releaseLocation();
  const secureEnv = await serverJourney("localhost", port);
  if (!process.argv.includes("--capture-only")) await serverJourney("insecure-http", port + 1);
  if (!serverOnly) {
    await available(demoPort);
    start(["scripts/serve-demo.mjs"], { ...env, DEMO_PORT: String(demoPort), NEXT_PUBLIC_BASE_PATH: "/loft-booking" });
    let ready = false;
    for (let i = 0; i < 30; i++) {
      try { ready = await new Promise((resolve, reject) => { const r = get(env.DEMO_BASE_URL, { agent: false }, (response) => { response.resume(); resolve(response.statusCode === 200); }); r.on("error", reject); }); } catch {}
      if (ready) break; await delay(100);
    }
    if (!ready) throw new Error("DEMO_NOT_READY");
    if (!process.argv.includes("--capture-only")) await command(["node_modules/@playwright/test/cli.js", "test", `--output=${join(root, "demo-results")}`], { ...env, PLAYWRIGHT_BASE_URL: env.DEMO_BASE_URL });
    if (process.argv.includes("--capture") || process.argv.includes("--capture-only")) await command(["scripts/capture-v24.mjs"], secureEnv);
  }
  console.log(`${serverOnly ? "SERVER" : "SERVER/DEMO"} browser checks passed; real SQLite, isolated private data`);
} catch (error) { console.error(`SERVER UI check failed: ${error.name}; details are in the test output above`); process.exitCode = 1; }
finally {
  try {
    for (const item of children.reverse()) {
      item.child.kill("SIGTERM");
      if (!await Promise.race([item.done.then(() => true), delay(5000, false, { ref: false })])) item.child.kill("SIGKILL");
      if (!await Promise.race([item.done.then(() => true), delay(3000, false, { ref: false })])) throw new Error("UI_PROCESS_CLEANUP_FAILED");
    }
    for (const proxy of proxies) await proxy.close();
  } finally { rmSync(root, { recursive: true, force: true }); }
}
