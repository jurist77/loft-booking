import { describe, expect, it } from "vitest";
import { assetPath, deploymentConfig } from "./deployment";

describe("Deployment configuration", () => {
  it("defaults to the non-persistent demo with no API", () => {
    expect(deploymentConfig({})).toEqual({ mode: "demo", basePath: "", apiBaseUrl: "" });
  });
  it("supports a subdirectory without hard-coded host names", () => {
    expect(assetPath("/images/studio-1.svg", "/loft-booking")).toBe("/loft-booking/images/studio-1.svg");
    expect(assetPath("/images/studio-1.svg", "")).toBe("/images/studio-1.svg");
    expect(assetPath("/images/studio-1.svg", "/another/demo")).toBe("/another/demo/images/studio-1.svg");
  });
  it("prepares independent VPS/API configuration without implementing an API", () => {
    expect(deploymentConfig({ mode: "server", apiBaseUrl: "/api" })).toEqual({ mode: "server", basePath: "", apiBaseUrl: "/api" });
    expect(deploymentConfig({ apiBaseUrl: "https://api.example.test/v1" }).apiBaseUrl).toBe("https://api.example.test/v1");
  });
  it.each(["/demo/", "demo", "//host", "/../demo", "/demo?secret=yes"])("rejects unsafe base path %s", (basePath) => {
    expect(() => deploymentConfig({ basePath })).toThrow();
  });
  it("rejects unknown modes and nonlocal assets", () => {
    expect(() => deploymentConfig({ mode: "unknown" })).toThrow();
    expect(() => assetPath("//external.example.test/photo.svg")).toThrow();
    expect(() => assetPath("https://external.example.test/photo.svg")).toThrow();
    expect(() => deploymentConfig({ apiBaseUrl: "javascript:alert(1)" })).toThrow();
  });
});
