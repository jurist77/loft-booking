import { describe, expect, it } from "vitest";
import { resolve } from "node:path";
import { appMode } from "../lib/app-mode";
import { databaseSettings } from "./config";

const path = "/tmp/studio-test/studio.sqlite";
describe("Explicit mode and private SQLite configuration", () => {
  it("does not activate SERVER because a database path exists", () => {
    expect(appMode(undefined)).toBe("demo");
    expect(() => databaseSettings({ SQLITE_PATH: path })).toThrow();
    expect(() => databaseSettings({ APP_MODE: "demo", SQLITE_PATH: path })).toThrow();
  });
  it("requires an absolute path outside the application and bounds busy timeout", () => {
    expect(databaseSettings({ APP_MODE: "server", SQLITE_PATH: path })).toEqual({ path, busyTimeout: 1000 });
    for (const candidate of [undefined, ":memory:", "relative.sqlite", resolve("public/private.sqlite"), resolve("..fake/db.sqlite")]) expect(() => databaseSettings({ APP_MODE: "server", SQLITE_PATH: candidate })).toThrow();
    for (const value of ["0", "-1", "bad", "1.5", "999999"]) expect(() => databaseSettings({ APP_MODE: "server", SQLITE_PATH: path, SQLITE_BUSY_TIMEOUT_MS: value })).toThrow();
  });
  it("never uses a legacy PostgreSQL URL as a mode or SQLite fallback", () => {
    expect(() => databaseSettings({ APP_MODE: "server", DATABASE_URL: "private-canary" })).toThrow();
    expect(databaseSettings({ APP_MODE: "server", SQLITE_PATH: path, DATABASE_URL: "private-canary" }).path).toBe(path);
  });
  it("does not expose paths or private input in configuration errors", () => {
    expect(() => databaseSettings({ APP_MODE: "server", SQLITE_PATH: "private-canary" })).toThrow(/^Invalid server database configuration$/);
    expect(() => appMode("private-canary")).toThrow(/^APP_MODE must be demo or server$/);
  });
});
