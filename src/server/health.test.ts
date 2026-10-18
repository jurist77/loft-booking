import { afterEach, expect, it, vi } from "vitest";
import { databaseHealth } from "./health";
import { closeDatabase } from "./database";

afterEach(async () => { await closeDatabase(); vi.unstubAllEnvs(); });
it("does not access SQLite in DEMO even when a URL exists", async () => {
  vi.stubEnv("APP_MODE", "demo"); vi.stubEnv("SQLITE_PATH", "private-canary-not-a-url");
  const response = await databaseHealth();
  expect(response.status).toBe(404); expect(await response.json()).toEqual({ status: "not_found" });
});
it("returns a safe 503 for missing SERVER configuration", async () => {
  vi.stubEnv("APP_MODE", "server"); vi.stubEnv("SQLITE_PATH", "private-canary-not-a-url");
  const response = await databaseHealth();
  expect(response.status).toBe(503); expect(await response.text()).toBe('{"status":"unavailable"}');
  expect(response.headers.get("cache-control")).toBe("no-store");
});
