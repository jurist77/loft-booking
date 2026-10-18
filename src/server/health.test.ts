import { afterEach, expect, it, vi } from "vitest";
import { databaseHealth } from "./health";
import { closeDatabasePool } from "./database";

afterEach(async () => { await closeDatabasePool(); vi.unstubAllEnvs(); });
it("does not access PostgreSQL in DEMO even when a URL exists", async () => {
  vi.stubEnv("APP_MODE", "demo"); vi.stubEnv("DATABASE_URL", "private-canary-not-a-url");
  const response = await databaseHealth();
  expect(response.status).toBe(404); expect(await response.json()).toEqual({ status: "not_found" });
});
it("returns a safe 503 for missing SERVER configuration", async () => {
  vi.stubEnv("APP_MODE", "server"); vi.stubEnv("DATABASE_URL", "private-canary-not-a-url");
  const response = await databaseHealth();
  expect(response.status).toBe(503); expect(await response.text()).toBe('{"status":"unavailable"}');
  expect(response.headers.get("cache-control")).toBe("no-store");
});
