import { expect, test } from "@playwright/test";
import { selectFutureDay, slotButton } from "./flows";

test("grid expands, shortens and resets with mouse and keyboard", async ({ page }) => {
  await page.goto("./");
  await selectFutureDay(page, 6);
  const summary = page.locator(".selection-summary");
  await slotButton(page, "10:00").focus();
  await page.keyboard.press("Enter");
  await expect(summary).toHaveText("10:00–11:00 · 1 ч");
  await expect(page.locator('.slot[aria-pressed="true"]')).toHaveCount(2);
  await slotButton(page, "11:00").click();
  await expect(summary).toHaveText("10:00–11:30 · 1 ч 30 мин");
  await slotButton(page, "12:00").focus(); await page.keyboard.press("Space");
  await expect(summary).toHaveText("10:00–12:30 · 2 ч 30 мин");
  await expect(page.locator('.slot[aria-pressed="true"]')).toHaveCount(5);
  await slotButton(page, "09:30").click();
  await expect(summary).toHaveText("09:30–12:30 · 3 ч");
  await slotButton(page, "10:30").click();
  await expect(summary).toHaveText("09:30–11:00 · 1 ч 30 мин");
  await slotButton(page, "10:00").click(); await slotButton(page, "10:00").click();
  await expect(summary).toHaveText("09:30–10:30 · 1 ч");
  await slotButton(page, "09:30").click();
  await expect(summary).toHaveText("Время пока не выбрано");
  await slotButton(page, "10:00").click();
  await page.getByRole("button", { name: "Сбросить выбор" }).focus(); await page.keyboard.press("Enter");
  await expect(page.locator('.slot[aria-pressed="true"]')).toHaveCount(0);
  await slotButton(page, "10:00").click();
  await selectFutureDay(page, 1);
  await expect(summary).toHaveText("Время пока не выбрано");
  await expect(page.getByRole("button", { name: "Продолжить", exact: true })).toBeDisabled();
});

test("grid cannot cross busy time and preserves adjacent intervals", async ({ page }) => {
  await page.goto("./"); await selectFutureDay(page, 1);
  await expect(slotButton(page, "11:30")).toBeDisabled();
  await slotButton(page, "10:00").click(); await slotButton(page, "11:30").click();
  await expect(page.locator(".selection-summary")).toHaveText("10:00–12:00 · 2 ч");
  await expect(slotButton(page, "12:00")).toBeDisabled();
  await expect(slotButton(page, "14:00")).toBeDisabled();
  for (const slot of await page.locator(".busy-slot").all()) {
    await expect(slot).toBeDisabled();
    await expect(slot).toHaveCSS("text-decoration-line", "line-through");
  }
  await page.getByRole("button", { name: "Сбросить выбор" }).click();
  await slotButton(page, "14:00").click();
  await expect(slotButton(page, "11:00")).toBeDisabled();
  await expect(page.locator(".selection-summary")).toHaveText("14:00–15:00 · 1 ч");
});

test("closing boundary, legend, removed controls and administrator placeholder", async ({ page }) => {
  await page.goto("./"); await selectFutureDay(page, 6);
  await expect(page.locator(".slots button")).toHaveCount(32);
  await expect(page.locator("#start, #end, .booking-picker select, .demo-scenarios, .timezone-badge")).toHaveCount(0);
  await expect(page.getByText("Тестовые сценарии доступности", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("group", { name: "Состояния времени" })).toHaveText("СвободноЗанятоВыбрано");
  await expect(page.locator(".slot-legend s")).toHaveText("Занято");
  await expect(slotButton(page, "22:30")).toBeDisabled();
  await slotButton(page, "21:00").click(); await slotButton(page, "22:30").click();
  await expect(page.locator(".selection-summary")).toHaveText("21:00–23:00 · 2 ч");
  await expect(page.locator(".slots").getByRole("button", { name: /^23:00/ })).toHaveCount(0);
  await expect(page.locator(".booking-picker .admin-contact")).toContainText("Контакт администратора появится здесь.");
  await expect(page.locator('a[href^="tel:"]')).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
