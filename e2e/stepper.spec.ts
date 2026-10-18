import { expect, test } from "@playwright/test";
import { fillDemoContact, openCalendar, selectFutureDay, slotButton } from "./flows";

test("five exclusive screens preserve time and contacts on Back and reset on a new booking", async ({ page }) => {
  await page.goto("./");
  await expect(page.locator("[data-screen]")).toHaveCount(1);
  await expect(page.locator('[data-screen="welcome"]')).toBeVisible();
  await expect(page.locator(".calendar, .slots, .contact-fields, .confirmation")).toHaveCount(0);
  await openCalendar(page);
  await expect(page.locator(".slots, .contact-fields")).toHaveCount(0);
  const date = await selectFutureDay(page, 6);
  await expect(page.locator('[data-screen="time"]')).toBeVisible();
  await expect(page.locator(".calendar, .contact-fields")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Продолжить", exact: true })).toBeDisabled();
  await slotButton(page, "10:00").click(); await slotButton(page, "12:00").click();
  await page.getByRole("button", { name: "← Назад", exact: true }).click();
  await expect(page.getByRole("button", { name: date, exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: date, exact: true }).click();
  await expect(page.locator(".selection-summary")).toHaveText("10:00–12:30 · 2 ч 30 мин");
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await fillDemoContact(page);
  await expect(page.locator(".calendar, .slots")).toHaveCount(0);
  await page.getByRole("button", { name: "← Назад", exact: true }).click();
  await expect(page.locator(".selection-summary")).toHaveText("10:00–12:30 · 2 ч 30 мин");
  await page.getByRole("button", { name: "← Назад", exact: true }).click();
  await page.getByRole("button", { name: "← Назад", exact: true }).click();
  await expect(page.locator('[data-screen="welcome"]')).toBeVisible();
  await openCalendar(page);
  await page.getByRole("button", { name: date, exact: true }).click();
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await expect(page.locator("#firstName")).toHaveValue("Тест");
  await expect(page.locator("#lastName")).toHaveValue("Пример");
  await expect(page.locator("#phone")).toHaveValue("9261234567");
  await expect(page.locator("#eventType")).toHaveValue("Другое");
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.locator('[data-screen="confirmation"]')).toBeVisible();
  await expect(page.locator("[data-screen]")).toHaveCount(1);
  await expect(page.locator(".calendar, .slots, .contact-fields")).toHaveCount(0);
  await page.getByRole("button", { name: "Новое бронирование" }).click();
  await selectFutureDay(page, 6);
  await expect(page.locator(".selection-summary")).toHaveText("Время пока не выбрано");
  await slotButton(page, "10:00").click();
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await expect(page.locator("#phone")).toHaveValue("");
  await page.reload();
  await expect(page.locator('[data-screen="welcome"]')).toBeVisible();
});

test("Welcome fits standard viewports and tiny screens keep controls reachable", async ({ page }) => {
  for (const [width, height] of [[320, 568], [375, 667], [390, 844], [1440, 900]]) {
    await page.setViewportSize({ width, height }); await page.goto("./");
    await expect(page.getByRole("button", { name: "Забронировать", exact: true })).toBeEnabled();
    const size = await page.evaluate(() => ({ x: document.documentElement.scrollWidth, y: document.documentElement.scrollHeight, w: innerWidth, h: innerHeight }));
    expect(size.x).toBeLessThanOrEqual(size.w); expect(size.y).toBeLessThanOrEqual(size.h + 1);
    await expect(page.locator(".calendar, .slots, .contact-fields")).toHaveCount(0);
    await page.getByRole("button", { name: "О пространстве", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "О пространстве", exact: true })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("button", { name: "О пространстве", exact: true })).toBeFocused();
  }
  await page.setViewportSize({ width: 320, height: 300 });
  await page.getByRole("button", { name: "Забронировать", exact: true }).click();
  await expect(page.locator('[data-screen="calendar"]')).toBeVisible();
  await selectFutureDay(page, 6);
  await slotButton(page, "22:00").scrollIntoViewIfNeeded();
  await expect(slotButton(page, "22:00")).toBeInViewport();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
