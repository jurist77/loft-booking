import { spawnSync } from "node:child_process";

const [kind, action] = process.argv.slice(2);
if (!["dev", "test"].includes(kind) || !["up", "stop", "status"].includes(action)) throw new Error("Invalid local PostgreSQL command");
const args = ["compose", "--project-name", `studio1925-${kind}`, "--env-file", kind === "test" ? ".env.test.local" : ".env.local", "-f", "compose.yaml"];
args.push(...(action === "up" ? ["up", "-d", "--wait", "--wait-timeout", "90", "postgres"] : action === "stop" ? ["stop", "postgres"] : ["ps", "postgres"]));
const result = spawnSync("docker", args, { stdio: "inherit" });
if (result.error) { console.error("Docker Compose is unavailable"); process.exitCode = 1; }
else process.exitCode = result.status ?? 1;
