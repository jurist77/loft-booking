import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: { "server-only": new URL("./tests/server-only.ts", import.meta.url).pathname } },
  test: { include: ["tests/integration/**/*.test.ts"], environment: "node", fileParallelism: false, maxWorkers: 1, testTimeout: 15000, hookTimeout: 15000 },
});
