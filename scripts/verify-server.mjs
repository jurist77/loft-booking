import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { chmod, mkdtemp, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import { HealthProbeError, waitForHealth } from "./lib/health-probe.mjs";

const args = process.argv.slice(2);
const negativeControl = args.includes("--keep-db-unavailable");
const port = 3011;
const url = `http://127.0.0.1:${port}/api/health`;
console.log(`Health test runtime: Node ${process.version}, Undici ${process.versions.undici ?? "none"}; fresh node:http sockets`);

let root; let directory; let sqlitePath; let testEnv;
async function availability(action) {
  await rename(action === "up" ? directory + "-offline" : directory, action === "up" ? directory : directory + "-offline");
}
async function prepareDatabase(command) {
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--conditions=react-server", "scripts/database.mjs", command], { env: testEnv, stdio: "ignore" });
    child.once("error", () => reject(new HealthProbeError("SQLITE_SETUP_FAILED")));
    child.once("close", (code) => code === 0 ? resolve() : reject(new HealthProbeError("SQLITE_SETUP_FAILED")));
  });
}

let server; let serverExit; let exitInfo; let stopped = false; let phase = "startup";
function assertAlive() {
  if (exitInfo) throw new HealthProbeError(`SERVER_EXITED code=${exitInfo.code ?? "none"} signal=${exitInfo.signal ?? "none"}`);
}
async function terminateServer() {
  if (!server || !serverExit) return;
  server.kill("SIGTERM");
  let ended = await Promise.race([serverExit.then(() => true), delay(5000, false, { ref: false })]);
  if (!ended) {
    server.kill("SIGKILL");
    ended = await Promise.race([serverExit.then(() => true), delay(3000, false, { ref: false })]);
  }
  if (!ended) throw new HealthProbeError("SERVER_CLEANUP_TIMEOUT");
  console.log("Health test Next.js process stopped");
}

async function main() {
  if (args.some((arg) => arg !== "--keep-db-unavailable") || args.length > 1) throw new HealthProbeError("INVALID_TEST_ARGUMENTS");
  await new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", () => reject(new HealthProbeError("HTTP_TEST_PORT_IN_USE")));
    probe.listen(port, "127.0.0.1", () => probe.close(resolve));
  });
  root = await mkdtemp(join(tmpdir(), "studio-sqlite-http-"));
  directory = join(root, "data"); sqlitePath = join(directory, "test.sqlite");
  testEnv = { ...process.env, APP_MODE: "server", DEPLOY_TARGET: "node", SQLITE_PATH: sqlitePath, SQLITE_BUSY_TIMEOUT_MS: "100", NEXT_PUBLIC_APP_MODE: "server", NEXT_PUBLIC_BASE_PATH: "", NEXT_PUBLIC_API_BASE_URL: "", NEXT_TELEMETRY_DISABLED: "1" };
  try {
    await prepareDatabase("init"); await prepareDatabase("migrate");
    // Preserve PR #6: monitor Next directly and keep fresh HTTP connections.
    server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", String(port)], { stdio: "ignore", env: testEnv });
    serverExit = new Promise((resolve) => {
      server.once("error", () => { exitInfo = { code: "LAUNCH_FAILED" }; resolve(); });
      server.once("exit", (code, signal) => { exitInfo = { code, signal }; resolve(); });
    });
    await waitForHealth(url, { phase, expectedStatus: 200, timeoutMs: 15000, assertAlive });
    // A separate fresh connection also verifies SERVER does not offer demo bookings.
    const { get } = await import("node:http");
    const page = await new Promise((resolve, reject) => {
      const request = get(`http://127.0.0.1:${port}/`, { agent: false, signal: AbortSignal.timeout(3000) }, (response) => {
        let body = ""; response.setEncoding("utf8");
        response.on("data", (chunk) => { body += chunk; });
        response.on("end", () => resolve(response.statusCode === 200 ? body : ""));
        response.on("error", () => reject(new HealthProbeError("SERVER_PAGE_FAILED")));
      });
      request.on("error", () => reject(new HealthProbeError("SERVER_PAGE_FAILED")));
    });
    if (!page.includes("Серверный режим") || !page.includes("Онлайн-запись пока недоступна") || page.includes('class="slots"')) throw new HealthProbeError("INVALID_SERVER_PAGE");
    for (let cycle = 1; cycle <= (negativeControl ? 1 : 3); cycle++) {
      phase = `stopped-${cycle}`;
      stopped = true; await availability("down");
      await waitForHealth(url, { phase, expectedStatus: 503, timeoutMs: 5000, assertAlive });
      phase = `recovery-${cycle}`;
      if (!negativeControl) { await availability("up"); stopped = false; }
      await waitForHealth(url, { phase, expectedStatus: 200, timeoutMs: negativeControl ? 3000 : 15000, assertAlive });
      console.log(`Recovery cycle ${cycle}: 200 -> 503 -> 200; same Next.js process alive`);
    }
    if (!negativeControl) {
      await chmod(sqlitePath, 0o400);
      try { await waitForHealth(url, { phase: "write-denied", expectedStatus: 503, timeoutMs: 5000, assertAlive }); }
      finally { await chmod(sqlitePath, 0o600); }
      await waitForHealth(url, { phase: "write-restored", expectedStatus: 200, timeoutMs: 15000, assertAlive });
    }
  } catch (error) {
    // Only our own safe codes are printed; no raw exceptions, SQL, paths, URL or response data.
    console.error(`Health test failed: ${error instanceof HealthProbeError ? error.code : "UNEXPECTED_TEST_FAILURE"}; phase=${phase}; Next=${exitInfo ? `exited(${exitInfo.code ?? exitInfo.signal})` : "running"}`);
    throw new HealthProbeError("SERVER_HTTP_TEST_FAILED");
  } finally {
    try { if (stopped) { await availability("up"); stopped = false;
      if (server && !exitInfo) await waitForHealth(url, { phase: "cleanup-recovery", expectedStatus: 200, timeoutMs: 15000, assertAlive });
      console.log("Health test SQLite restored"); } }
    finally { try { await terminateServer(); } finally { if (root) await rm(root, { recursive: true, force: true }); } }
  }
}

await main().catch((error) => {
  console.error(`Health command failed: ${error instanceof HealthProbeError ? error.code : "UNEXPECTED_TEST_FAILURE"}`);
  process.exitCode = 1;
});
