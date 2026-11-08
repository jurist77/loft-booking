import { test, expect } from "@playwright/test";
import Database from "better-sqlite3";
import { execFileSync } from "node:child_process";
import { contacts } from "../e2e-server/flows";

const path = process.env.STUDIO_E2E_DB ?? "";
if (process.env.GITHUB_ACTIONS !== "true" || process.env.STUDIO_INSTALLER_CI !== "1" ||
    !path.startsWith("/tmp/studio-server-ui-") || !path.endsWith("/studio.sqlite")) throw new Error("Isolated CI SQLite required");
const db = new Database(path); db.pragma("foreign_keys=ON");
const submit = (page: import("@playwright/test").Page) => page.getByRole("button", { name: "Подтвердить выбор", exact: true });
test.beforeEach(async ({ page }) => {
  db.transaction(() => db.exec("DELETE FROM booking_events; DELETE FROM bookings;"))();
  // Independent disposable CI cases restart rapidly to reset the API budget.
  // Clear the fixture's start counter, retaining production unit limits.
  execFileSync("systemctl", ["reset-failed", "studio1925.service"], { stdio: "ignore", timeout: 15000 });
  execFileSync("systemctl", ["restart", "studio1925.service"], { stdio: "ignore", timeout: 45000 });
  await expect.poll(async () => {
    try { return (await page.request.get("/api/health")).status(); } catch { return 0; }
  }).toBe(200);
  await page.goto("/");
  expect(await page.evaluate(() => isSecureContext)).toBe(true);
});
test.afterAll(() => db.close());

test("trusted HTTPS five-screen flow commits to isolated SQLite and survives reload", async ({ page }) => {
  await contacts(page); await submit(page).click();
  await expect(page.getByTestId("booking-id")).toBeVisible();
  const stored = db.prepare("SELECT id,status FROM bookings").get() as { id: string; status: string };
  expect(stored.status).toBe("confirmed"); expect(stored.id).toMatch(/^[a-f0-9-]{36}$/);
  await expect(page.locator(".confirmation")).not.toContainText("Демонстрационный режим");
  await page.reload(); await expect(page.locator('[data-screen="welcome"]')).toBeVisible();
  expect((await page.request.get("/api/health")).status()).toBe(200);
});

test("lost TLS response after COMMIT safely reuses one ID and one event", async ({ page }) => {
  const ids: string[] = [];
  page.on("request", r => { if (r.method() === "POST" && new URL(r.url()).pathname === "/api/bookings") ids.push(r.postDataJSON().requestId); });
  await contacts(page);
  await page.route("**/api/bookings", async route => {
    expect((await route.fetch()).status()).toBe(201);
    expect((db.prepare("SELECT count(*) AS n FROM bookings").get() as { n: number }).n).toBe(1);
    await route.abort("failed");
  }, { times: 1 });
  await submit(page).click(); await expect(page.locator(".form-error")).toContainText("Заявка могла сохраниться");
  await page.getByRole("button", { name: "Безопасно повторить отправку", exact: true }).click();
  await expect(page.getByTestId("booking-id")).toBeVisible();
  expect(ids).toHaveLength(2); expect(ids[0]).toBe(ids[1]);
  expect((db.prepare("SELECT count(*) AS n FROM booking_events").get() as { n: number }).n).toBe(1);
});

test("TLS proxy enforces Origin and overwrites spoofed client identity", async ({ page }) => {
  expect((await page.request.post("/api/bookings", { data: {}, headers: { Origin: "https://untrusted.example" } })).status()).toBe(403);
  const statuses: number[] = [];
  for (let i = 0; i < 12; i++) {
    const response = await page.request.post("/api/bookings", { data: {}, headers: {
      Origin: "https://fixture.duckdns.org", "X-Studio-Client-IP": `198.51.100.${i + 1}`, "X-Forwarded-For": `203.0.113.${i + 1}`,
    } });
    statuses.push(response.status());
  }
  expect(statuses).toContain(400); expect(statuses).toContain(429);
  expect((db.prepare("SELECT count(*) AS n FROM bookings").get() as { n: number }).n).toBe(0);
});

test("HTTPS headers, HTTP POST rejection and mobile width remain correct", async ({ page }) => {
  const response = await page.request.get("/");
  expect(response.headers()["strict-transport-security"]).toBe("max-age=300");
  expect(response.headers()["x-content-type-options"]).toBe("nosniff");
  expect((await page.request.post("http://fixture.duckdns.org/api/bookings", { data: {}, maxRedirects: 0 })).status()).toBe(405);
  for (const width of [320, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
});
