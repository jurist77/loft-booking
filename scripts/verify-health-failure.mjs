import { spawn } from "node:child_process";

// An independent CLI must actually fail while PostgreSQL remains stopped.
// Its finally block must still restore PostgreSQL and terminate Next.js.
const child = spawn(process.execPath, ["scripts/verify-server.mjs", "--keep-db-stopped"], { stdio: ["ignore", "pipe", "pipe"] });
let output = "";
for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { output += chunk; process.stdout.write(chunk); });
const code = await new Promise((resolve) => { child.once("error", () => resolve(-1)); child.once("close", resolve); });
if (code !== 1 || !/HEALTH_TIMEOUT phase=recovery-1 expected=200 attempts=\d+ last=HTTP_503/.test(output) || !output.includes("Next=running") || !output.includes("Health test Next.js process stopped") || !output.includes("Health test PostgreSQL restored")) {
  console.error("Negative control failed: expected exit=1 for persistent HTTP 503 with cleanup");
  process.exitCode = 1;
} else console.log("Negative control passed: real health CLI exited 1 for persistent HTTP 503; database restored and Next.js stopped");
