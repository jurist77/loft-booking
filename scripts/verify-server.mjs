import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { createServer } from "node:net";

const port = 3011;
// Refuse to test a pre-existing process or stop its database accidentally.
await new Promise((resolve, reject) => {
  const probe = createServer();
  probe.once("error", () => reject(new Error("HTTP test port 3011 is already in use")));
  probe.listen(port, "127.0.0.1", () => probe.close(resolve));
});
const server = spawn(process.execPath, ["--env-file=.env.test.local", "scripts/next-mode.mjs", "server", "start", "--port", String(port)], { stdio: "ignore" });
const exited = new Promise((resolve) => { server.once("exit", resolve); server.once("error", resolve); });
let stopped = false;
function postgres(action) {
  const result = spawnSync(process.execPath, ["scripts/database-compose.mjs", "test", action], { stdio: "inherit" });
  assert.equal(result.status, 0, "Test PostgreSQL lifecycle failed");
}
async function health(status) {
  const response = await fetch(`http://127.0.0.1:${port}/api/health`, { signal: AbortSignal.timeout(6000) });
  assert.equal(response.status, status);
  assert.deepEqual(await response.json(), { status: status === 200 ? "ok" : "unavailable" });
  assert.equal(response.headers.get("cache-control"), "no-store");
}
try {
  let ready = false;
  for (let i = 0; i < 60; i++) {
    try { await health(200); ready = true; break; } catch { await new Promise((resolve) => setTimeout(resolve, 250)); }
  }
  assert.ok(ready, "SERVER did not become healthy");
  console.log("Real HTTP /api/health with PostgreSQL: 200, minimal safe JSON");
  const page = await (await fetch(`http://127.0.0.1:${port}/`)).text();
  assert.ok(page.includes("Серверный режим") && page.includes("Онлайн-запись пока недоступна"));
  assert.ok(!page.includes('class="slots"'));
  stopped = true; postgres("stop");
  await health(503);
  console.log("Real HTTP /api/health after PostgreSQL stopped: 503, no diagnostics leaked");
  postgres("up"); stopped = false;
  await health(200);
  console.log("Real HTTP /api/health after PostgreSQL restarted: 200");
} finally {
  if (stopped) postgres("up");
  server.kill("SIGTERM");
  await exited;
}
