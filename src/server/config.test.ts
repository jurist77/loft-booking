import { describe, expect, it } from "vitest";
import { appMode } from "../lib/app-mode";
import { databaseSettings } from "./config";

const url = "postgresql://test_app:fictional_password@127.0.0.1:54330/studio_config_test";
describe("Explicit application mode and private server settings", () => {
  it("defaults to DEMO and does not activate SERVER because a URL happens to exist", () => {
    expect(appMode(undefined)).toBe("demo");
    expect(() => databaseSettings({ DATABASE_URL: url })).toThrow("Invalid server database configuration");
    expect(() => databaseSettings({ APP_MODE: "demo", DATABASE_URL: url })).toThrow();
  });
  it("requires valid SERVER credentials and bounds pool/timeouts", () => {
    expect(databaseSettings({ APP_MODE: "server", DATABASE_URL: url })).toEqual({ connectionString: url, max: 5, connectTimeout: 2000, queryTimeout: 2000 });
    expect(() => databaseSettings({ APP_MODE: "server" })).toThrow();
    for (const value of ["0", "-1", "100", "bad", "1.5"]) expect(() => databaseSettings({ APP_MODE: "server", DATABASE_URL: url, DB_POOL_MAX: value })).toThrow();
    expect(() => databaseSettings({ APP_MODE: "server", DATABASE_URL: url, DB_QUERY_TIMEOUT_MS: "999999" })).toThrow();
  });
  it("uses separate migration credentials and refuses URLs with weakened TLS verification", () => {
    expect(() => databaseSettings({ APP_MODE: "server", DATABASE_URL: url }, true)).toThrow();
    expect(databaseSettings({ APP_MODE: "server", MIGRATION_DATABASE_URL: url }, true).queryTimeout).toBe(30000);
    expect(() => databaseSettings({ APP_MODE: "server", DATABASE_URL: `${url}?sslmode=no-verify` })).toThrow();
  });
  it("does not include connection values in errors", () => {
    expect(() => databaseSettings({ APP_MODE: "server", DATABASE_URL: "not-a-url-private-canary" })).toThrow(/^Invalid server database configuration$/);
    expect(() => appMode("unexpected-private-value")).toThrow(/^APP_MODE must be demo or server$/);
  });
});
