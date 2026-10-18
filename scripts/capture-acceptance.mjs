import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { chromium, expect } from "@playwright/test";
import { fillDemoContact, triggerAvailabilityConflict } from "../e2e/flows.ts";

const baseURL = process.env.ACCEPTANCE_BASE_URL || "http://127.0.0.1:3000";
const output = new URL("../docs/acceptance/", import.meta.url);
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium" });
const clientErrors = [];
const results = { capturedAt: new Date().toISOString(), browser: browser.version(), screenshots: [], checks: {} };

async function capture(locator, name, options = {}) {
  await locator.screenshot({ ...options, path: new URL(name, output).pathname, animations: "disabled" });
  results.screenshots.push(name);
}

async function pageFor(viewport, mobile = false) {
  const page = await browser.newPage({ viewport, isMobile: mobile, hasTouch: mobile, reducedMotion: "reduce" });
  page.on("pageerror", (error) => clientErrors.push(error.message));
  page.on("console", (message) => { if (message.type() === "error") clientErrors.push(message.text()); });
  await page.goto(baseURL);
  await page.getByRole("button", { name: "Открыть изображение: Общее пространство", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("button", { name: "Закрыть изображение" }).click();
  await page.locator(".gallery-grid").scrollIntoViewIfNeeded();
  await page.locator(".gallery-grid img").evaluateAll(async (images) => { await Promise.all(images.map((image) => image.decode())); });
  await page.evaluate(() => scrollTo(0, 0));
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  return page;
}

try {
  const desktop = await pageFor({ width: 1440, height: 1000 });
  await capture(desktop, "01-home-desktop.png", { fullPage: true });
  const mobile = await pageFor({ width: 390, height: 844 }, true);
  await capture(mobile, "02-home-mobile.png", { fullPage: true });
  results.checks.mobileOverflow = false;
  await mobile.close();

  await desktop.getByText("Тестовые сценарии доступности", { exact: true }).click();
  await desktop.getByRole("button", { name: /^Частично занят/ }).click();
  const slots = desktop.getByRole("group", { name: "Все получасовые слоты" }).getByRole("button");
  await expect(slots).toHaveCount(32);
  const busySlots = desktop.locator(".slot.busy-slot");
  await expect(busySlots).toHaveCount(8);
  for (const slot of await busySlots.all()) {
    await expect(slot).toBeDisabled();
    assert.match(await slot.evaluate((element) => getComputedStyle(element).textDecorationLine), /line-through/);
  }
  results.checks.slots = 32;
  results.checks.busySlotsStruckThroughAndDisabled = 8;
  await capture(desktop.locator(".date-time-panel"), "03-calendar-busy.png");

  const start = desktop.getByRole("combobox", { name: "Начало", exact: true });
  for (const value of [690, 720, 750, 780, 810, 1050, 1080, 1110, 1140, 1170, 1350]) {
    await expect(start.locator(`option[value="${value}"]`)).toHaveCount(0);
  }
  await start.selectOption("990");
  const end = desktop.getByRole("combobox", { name: "Окончание", exact: true });
  await expect(end).toHaveValue("1050");
  await expect(end.locator("option:not([disabled])")).toHaveText(["17:30", "18:00"]);
  results.checks.automaticEnd = "16:30 → 17:30";
  results.checks.allowedEnds = ["17:30", "18:00"];
  await capture(desktop.locator(".date-time-panel"), "04-time-selection.png");
  await end.selectOption("1080");
  await fillDemoContact(desktop);
  // The screenshot keeps the phone field masked; the actual input remains valid.
  await capture(desktop.locator(".contact-panel"), "05-booking-form.png", { mask: [desktop.locator("#phone")], maskColor: "#eaeade" });
  await desktop.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(desktop.locator(".confirmation-details")).toContainText("16:30–18:00");
  await expect(desktop.locator(".confirmation-details")).toContainText("1 ч 30 мин");
  await expect(desktop.locator(".demo-notice")).toContainText("Бронирование фактически не сохранено");
  await capture(desktop.locator(".confirmation"), "06-demo-confirmation.png");
  await desktop.close();

  const conflict = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: "reduce" });
  conflict.on("pageerror", (error) => clientErrors.push(error.message));
  await triggerAvailabilityConflict(conflict, baseURL);
  await capture(conflict.locator(".booking-card"), "07-time-conflict.png", { mask: [conflict.locator("#phone")], maskColor: "#eaeade" });
  results.checks.conflictMessage = await conflict.locator(".form-error").innerText();
  await conflict.close();
  assert.deepEqual(clientErrors, []);
  results.checks.clientErrors = clientErrors;
  await writeFile(new URL("checks.json", output), JSON.stringify(results, null, 2) + "\n");
  console.log(JSON.stringify(results, null, 2));
} finally {
  await browser.close();
}
