import { spawnSync } from "node:child_process";
import { writeFile } from "node:fs/promises";

const result = spawnSync(process.execPath, ["node_modules/next/dist/bin/next", "build"], {
  stdio: "inherit",
  env: {
    ...process.env,
    DEPLOY_TARGET: "pages",
    NEXT_PUBLIC_APP_MODE: "demo",
    NEXT_PUBLIC_BASE_PATH: process.env.NEXT_PUBLIC_BASE_PATH ?? "/loft-booking",
    NEXT_PUBLIC_API_BASE_URL: "",
    NEXT_TELEMETRY_DISABLED: "1",
  },
});
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
await writeFile("out/.nojekyll", "");
