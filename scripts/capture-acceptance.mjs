import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { chromium, expect } from "@playwright/test";
import { fillDemoContact, selectFutureDay, slotButton } from "../e2e/flows.ts";

const baseURL = process.env.ACCEPTANCE_BASE_URL || "http://127.0.0.1:3000";
const output = new URL("../docs/acceptance/v1.3/", import.meta.url);
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium" });
const errors = [];
const results = { version: "1.3", testedURL: baseURL, capturedAt: new Date().toISOString(), browser: browser.version(), screenshots: [], checks: {} };
try {
  for (const [device, width, height] of [["desktop", 1440, 900], ["mobile", 390, 844]]) {
    const page = await browser.newPage({ viewport: { width, height }, isMobile: device === "mobile", hasTouch: device === "mobile", reducedMotion: "reduce" });
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
    async function capture(screen, filename, mask = []) {
      await expect(page.locator(`[data-screen="${screen}"]`)).toBeVisible();
      await expect(page.locator("[data-screen]")).toHaveCount(1);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      await page.evaluate(() => scrollTo(0, 0));
      await page.screenshot({ path: new URL(`${filename}-${device}.png`, output).pathname, fullPage: true, animations: "disabled", mask, maskColor: "#eaeade" });
      results.screenshots.push(`${filename}-${device}.png`);
    }
    await page.goto(baseURL);
    await expect(page.getByRole("button", { name: "Забронировать", exact: true })).toBeEnabled();
    await page.locator(".hero-image img").evaluate((image) => image.decode());
    assert.equal(await page.evaluate(() => document.documentElement.scrollHeight > innerHeight + 1), false);
    await capture("welcome", "01-welcome");
    await page.getByRole("button", { name: "Забронировать", exact: true }).click();
    await capture("calendar", "02-calendar");
    await selectFutureDay(page, 6);
    await expect(page.locator(".slots button")).toHaveCount(32);
    await slotButton(page, "10:00").click();
    await expect(page.locator(".selection-summary")).toHaveText("10:00–11:00 · 1 ч");
    await slotButton(page, "12:00").click();
    await expect(page.locator(".selection-summary")).toHaveText("10:00–12:30 · 2 ч 30 мин");
    await capture("time", "03-time");
    await page.getByRole("button", { name: "Продолжить", exact: true }).click();
    await fillDemoContact(page);
    await capture("contacts", "04-contacts", [page.locator("#phone")]);
    await page.getByRole("button", { name: "Подтвердить выбор" }).click();
    await expect(page.locator(".confirmation-details")).toContainText("10:00–12:30");
    await expect(page.getByTestId("confirmation-phone")).toHaveText("+79261234567");
    await capture("confirmation", "05-confirmation", [page.getByTestId("confirmation-phone")]);
    await page.close();
  }
  assert.deepEqual(errors, []);
  results.checks = { exclusiveScreens: 5, welcomeFitsViewport: true, slots: 32, interval: "10:00–12:30", phoneNormalized: true, clientErrors: errors };
  await writeFile(new URL("checks.json", output), JSON.stringify(results, null, 2) + "\n");
  console.log(JSON.stringify(results, null, 2));
} finally { await browser.close(); }
