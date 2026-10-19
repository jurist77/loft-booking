import { randomBytes } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { get, request } from "node:http";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

const secret = `private_demo_audit_${randomBytes(16).toString("hex")}`;
const env = {
  ...process.env, APP_MODE: "server",
  SQLITE_PATH: `/unavailable/${secret}/studio.sqlite`, SQLITE_BUSY_TIMEOUT_MS: "invalid",
  API_PUBLIC_ORIGIN: `https://${secret}.invalid/path`, API_TRUST_PROXY: "invalid",
};
function command(args) {
  const result = spawnSync("npm", args, { env, stdio: "inherit" });
  if (result.error || result.status !== 0) process.exit(result.status ?? 1);
}
command(["run", "build"]);
// Prove runtime isolation in Node DEMO too, before replacing .next with static output.
const port = 3013;
await new Promise((resolve, reject) => { const probe = createServer(); probe.once("error", reject); probe.listen(port, "127.0.0.1", () => probe.close(resolve)); });
const server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", String(port)], { env: { ...env, APP_MODE: "demo", DEPLOY_TARGET: "node", NEXT_PUBLIC_APP_MODE: "demo", NEXT_PUBLIC_BASE_PATH: "" }, stdio: "ignore" });
let exited = false;
const done = new Promise((resolve) => { server.once("error", () => { exited = true; resolve(); }); server.once("exit", () => { exited = true; resolve(); }); });
async function probe(path, post = false) {
  return new Promise((resolve, reject) => {
    const url = `http://127.0.0.1:${port}${path}`;
    const handler = (res) => { let body = ""; res.setEncoding("utf8"); res.on("data", (chunk) => { body += chunk; }); res.on("error", reject); res.on("end", () => resolve({ status: res.statusCode, body })); };
    const req = post ? request(url, { method: "POST", agent: false, signal: AbortSignal.timeout(3000) }, handler) : get(url, { agent: false, signal: AbortSignal.timeout(3000) }, handler);
    req.on("error", reject); if (post) req.end("{}");
  });
}
try {
  let ready = false;
  for (let i = 0; i < 60 && !exited; i++) {
    try { const page = await probe("/"); if (page.status !== 200 || !page.body.includes("Демонстрационная версия")) throw new Error("INVALID_DEMO"); ready = true; break; }
    catch (error) { if (error.code !== "ECONNREFUSED") throw new Error("INVALID_NODE_DEMO"); await delay(200); }
  }
  if (!ready || exited) throw new Error("NODE_DEMO_START_FAILED");
  for (const [path, post] of [["/api/health", false], ["/api/availability?date=2030-01-15", false], ["/api/bookings", true]]) if ((await probe(path, post)).status !== 404) throw new Error("SERVER_API_IN_NODE_DEMO");
  console.log("Node DEMO isolation: page 200, health/availability/bookings 404 with invalid server configuration");
} finally {
  server.kill("SIGTERM");
  if (!await Promise.race([done.then(() => true), delay(5000, false, { ref: false })])) server.kill("SIGKILL");
  if (!await Promise.race([done.then(() => true), delay(3000, false, { ref: false })])) throw new Error("NODE_DEMO_CLEANUP_FAILED");
}
command(["run", "build:demo"]); command(["run", "audit:demo"]);
console.log("DEMO isolation: Node/static forced DEMO, invalid SQLite/API configuration ignored, canary values absent");
