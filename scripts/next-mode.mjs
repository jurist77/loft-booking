import { spawn } from "node:child_process";

const [mode, command, ...args] = process.argv.slice(2);
if (!["demo", "server"].includes(mode) || !["dev", "build", "start"].includes(command)) throw new Error("Invalid Next target");
const child = spawn(process.execPath, ["node_modules/next/dist/bin/next", command, ...(command === "build" ? [] : ["--hostname", "127.0.0.1"]), ...args], {
  stdio: "inherit",
  env: { ...process.env, APP_MODE: mode, DEPLOY_TARGET: "node", NEXT_PUBLIC_APP_MODE: mode, NEXT_PUBLIC_BASE_PATH: "", NEXT_PUBLIC_API_BASE_URL: "", NEXT_TELEMETRY_DISABLED: "1" },
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
child.on("error", () => { console.error("Could not start Next.js"); process.exitCode = 1; });
child.on("exit", (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0); });
