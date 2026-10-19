import { chromium, expect } from "@playwright/test";
import Database from "better-sqlite3";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { selectFutureDay, slotButton, fillContact } from "../e2e-server/flows.ts";

const path = process.env.STUDIO_E2E_DB ?? "";
if (!path.startsWith(`${tmpdir()}/studio-server-ui-`)) throw new Error("Private test database required");
const db = new Database(path); db.pragma("foreign_keys=ON");
const directory = new URL("../docs/acceptance/v2.4/", import.meta.url); await mkdir(directory, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium" });
const results = { version: "2.4", capturedAt: new Date().toISOString(), screenshots: [], serverPersisted: 0, demoApiRequests: 0 };
try {
  for (const mode of ["server", "demo"]) for (const [device, width, height] of [["desktop", 1440, 900], ["mobile", 390, 844]]) {
    db.transaction(() => db.exec("DELETE FROM booking_events; DELETE FROM bookings;"))();
    const page = await browser.newPage({ viewport: { width, height }, isMobile: device === "mobile", hasTouch: device === "mobile", reducedMotion: "reduce", extraHTTPHeaders: mode === "server" ? { "x-studio-client-ip": `2001:db8:abcd::${device === "mobile" ? 1 : 2}` } : {} });
    let apiCalls = 0; const browserErrors = [];
    page.on("request", (r) => { if (new URL(r.url()).pathname.includes("/api/")) apiCalls++; });
    page.on("pageerror", () => browserErrors.push("PAGE_ERROR"));
    const capture = async (screen, index, masks = []) => {
      await expect(page.locator(`[data-screen="${screen}"]`)).toBeVisible(); await expect(page.locator("[data-screen]")).toHaveCount(1);
      await page.locator(".studio-brand img").evaluate((image) => image.decode());
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      const filename = `${mode}-${device}-${index}-${screen}.png`;
      await page.screenshot({ path: new URL(filename, directory).pathname, fullPage: true, animations: "disabled", mask: masks, maskColor: "#eaeade" });
      results.screenshots.push(filename);
    };
    await page.goto(mode === "server" ? process.env.SERVER_BASE_URL : process.env.DEMO_BASE_URL);
    await expect(page.getByRole("button", { name: "Забронировать", exact: true })).toBeEnabled();
    await page.locator(".hero-image img").evaluate((image) => image.decode()); await capture("welcome", "01");
    await page.getByRole("button", { name: "Забронировать", exact: true }).click(); await capture("calendar", "02");
    await selectFutureDay(page, 6); await expect(page.locator(".slots button")).toHaveCount(28);
    await slotButton(page, "10:00").click(); await slotButton(page, "12:00").click(); await capture("time", "03");
    await page.getByRole("button", { name: "Продолжить", exact: true }).click(); await fillContact(page); await capture("contacts", "04", [page.locator("#phone")]);
    await page.getByRole("button", { name: "Подтвердить выбор", exact: true }).click();
    await expect(page.locator('[data-screen="confirmation"]')).toBeVisible();
    if (mode === "server") { await expect(page.getByTestId("booking-id")).toBeVisible(); await expect(page.getByTestId("confirmation-phone")).toHaveCount(0); }
    await capture("confirmation", "05", mode === "demo" ? [page.getByTestId("confirmation-phone")] : []);
    const records = db.prepare("SELECT count(*) AS n FROM bookings").get().n;
    expect(records).toBe(mode === "server" ? 1 : 0); expect(browserErrors).toEqual([]);
    if (mode === "demo") { expect(apiCalls).toBe(0); results.demoApiRequests += apiCalls; } else results.serverPersisted += records;
    await page.close();
  }
  await writeFile(new URL("checks.json", directory), JSON.stringify(results, null, 2) + "\n");
  console.log("Captured 20 SERVER/DEMO screenshots; only fictional contacts, phones masked, actual SQLite writes verified");
} finally { db.close(); await browser.close(); }
