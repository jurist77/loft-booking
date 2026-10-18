import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";

const secret = `private_demo_audit_${randomBytes(16).toString("hex")}`;
const env = {
  ...process.env, APP_MODE: "server",
  DATABASE_URL: `postgresql://audit_app:${secret}@127.0.0.1:1/unreachable_test`,
  MIGRATION_DATABASE_URL: `postgresql://audit_migrator:${secret}@127.0.0.1:1/unreachable_test`,
  POSTGRES_PASSWORD: secret, POSTGRES_APP_PASSWORD: secret, POSTGRES_MIGRATION_PASSWORD: secret,
};
for (const args of [["run", "build:demo"], ["run", "audit:demo"]]) {
  const result = spawnSync("npm", args, { env, stdio: "inherit" });
  if (result.error || result.status !== 0) process.exit(result.status ?? 1);
}
console.log("DEMO isolation: build forced DEMO, unreachable database ignored, canary secrets absent");
