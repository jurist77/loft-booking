import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { chromium, expect } from "@playwright/test";
import { fillDemoContact, selectFutureDay, slotButton } from "../e2e/flows.ts";

const baseURL = process.env.ACCEPTANCE_BASE_URL || "http://127.0.0.1:3000";
const output = new URL("../docs/acceptance/v1.2/", import.meta.url);
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium" });
const clientErrors = [];
const results = { version: "1.2", testedURL: baseURL, capturedAt: new Date().toISOString(), browser: browser.version(), screenshots: [], checks: {} };

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

  await selectFutureDay(desktop, 1);
  await expect(desktop.locator(".slots button")).toHaveCount(32);
  const busySlots = desktop.locator(".busy-slot");
  await expect(busySlots).toHaveCount(8);
  for (const slot of await busySlots.all()) {
    await expect(slot).toBeDisabled();
    await expect(slot).toHaveCSS("text-decoration-line", "line-through");
  }
  await expect(desktop.locator("#start, #end, .booking-picker select, .demo-scenarios, .timezone-badge")).toHaveCount(0);
  await expect(desktop.locator(".slot-legend")).toHaveText("СвободноЗанятоВыбрано");
  results.checks.slots = 32; results.checks.busyStruckThroughAndDisabled = 8;
  results.checks.noTimeDropdownsOrDemoControls = true;
  await capture(desktop.locator(".booking-picker"), "03-busy-grid.png");

  await selectFutureDay(desktop, 6);
  await slotButton(desktop, "10:00").click();
  await expect(desktop.locator(".selection-summary")).toHaveText("10:00–11:00 · 1 ч");
  await expect(desktop.locator('.slot[aria-pressed="true"]')).toHaveCount(2);
  results.checks.firstSelection = "10:00–11:00 · 1 ч";
  await capture(desktop.locator(".booking-picker"), "04-one-hour.png");
  await slotButton(desktop, "12:00").click();
  await expect(desktop.locator(".selection-summary")).toHaveText("10:00–12:30 · 2 ч 30 мин");
  await expect(desktop.locator('.slot[aria-pressed="true"]')).toHaveCount(5);
  results.checks.extendedSelection = "10:00–12:30 · 2 ч 30 мин";
  await capture(desktop.locator(".booking-picker"), "05-two-and-half-hours.png");

  await desktop.getByRole("button", { name: "Продолжить", exact: true }).click();
  await fillDemoContact(desktop);
  await expect(desktop.locator('input[type="checkbox"], input[type="radio"]')).toHaveCount(0);
  await expect(desktop.locator(".contact-step .admin-contact")).toContainText("Контакт администратора появится здесь.");
  await capture(desktop.locator(".contact-step"), "06-contact-form.png", { mask: [desktop.locator("#phone")], maskColor: "#eaeade" });
  await desktop.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(desktop.getByRole("heading", { name: "Ваше бронирование", exact: true })).toBeVisible();
  await expect(desktop.locator(".confirmation-details")).toContainText("10:00–12:30");
  await expect(desktop.locator(".confirmation-details")).toContainText("2 ч 30 мин");
  await expect(desktop.locator(".confirmation-details")).toContainText("Тест Пример");
  await expect(desktop.getByTestId("confirmation-phone")).toHaveText("+79261234567");
  await expect(desktop.locator(".demo-notice")).toContainText("Это демонстрация. Бронирование не создаётся, данные не сохраняются и уведомления не отправляются");
  await capture(desktop.locator(".confirmation"), "07-your-booking.png", { mask: [desktop.getByTestId("confirmation-phone")], maskColor: "#eaeade" });
  results.checks.phoneNormalized = true; results.checks.noCheckboxOrNotificationChoice = true;
  results.checks.adminPlaceholder = true;
  assert.deepEqual(clientErrors, []); results.checks.clientErrors = clientErrors;
  await writeFile(new URL("checks.json", output), JSON.stringify(results, null, 2) + "\n");
  console.log(JSON.stringify(results, null, 2));
} finally { await browser.close(); }
