import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";

const secret = `private_demo_audit_${randomBytes(16).toString("hex")}`;
const env = {
  ...process.env, APP_MODE: "server",
  SQLITE_PATH: `/unavailable/${secret}/studio.sqlite`, SQLITE_BUSY_TIMEOUT_MS: "invalid",
};
for (const args of [["run", "build:demo"], ["run", "audit:demo"]]) {
  const result = spawnSync("npm", args, { env, stdio: "inherit" });
  if (result.error || result.status !== 0) process.exit(result.status ?? 1);
}
console.log("DEMO isolation: build forced DEMO, unavailable SQLite ignored, canary secrets absent");
