import { expect, test } from "@playwright/test";
import { fillDemoContact, selectFutureDay, slotButton } from "./flows";

test("complete demo booking, gallery, time restrictions and reset", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
  await page.goto("./");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Место для");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole("button", { name: "Открыть изображение: Общее пространство", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("button", { name: "Следующее изображение" }).click();
  await expect(page.getByRole("dialog")).toContainText("2/4");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await page.getByRole("link", { name: "Забронировать", exact: true }).click();
  const date = await selectFutureDay(page, 1);
  await expect(page.getByRole("group", { name: "Все получасовые слоты" }).getByRole("button")).toHaveCount(32);
  await expect(slotButton(page, "18:00")).toBeDisabled();
  await slotButton(page, "16:30").click();
  await expect(page.locator(".selection-summary")).toHaveText("16:30–17:30 · 1 ч");
  await expect(page.locator('.slot[aria-pressed="true"]')).toHaveCount(2);
  await slotButton(page, "17:30").click();
  await expect(page.locator(".selection-summary")).toHaveText("16:30–18:00 · 1 ч 30 мин");
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Контактные данные", exact: true })).toBeFocused();
  await expect(page.locator(".chosen-details")).toContainText(date);
  await expect(page.locator('input[type="checkbox"], input[type="radio"]')).toHaveCount(0);
  await fillDemoContact(page);
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.getByRole("heading", { name: "Ваше бронирование", exact: true })).toBeVisible();
  await expect(page.locator(".confirmation-details")).toContainText("16:30–18:00");
  await expect(page.locator(".confirmation-details")).toContainText("1 ч 30 мин");
  await expect(page.locator(".confirmation-details")).toContainText("Тест Пример");
  await expect(page.locator(".confirmation-details")).toContainText("Другое");
  await expect(page.getByTestId("confirmation-phone")).toHaveText("+79261234567");
  await expect(page.locator(".demo-notice")).toContainText("Это демонстрация. Бронирование не создаётся, данные не сохраняются и уведомления не отправляются");
  await expect(page.locator(".confirmation .admin-contact")).toContainText("Контакт администратора появится здесь.");
  await page.getByRole("button", { name: "Новое бронирование" }).click();
  await expect(page.locator(".selection-summary")).toHaveText("Время пока не выбрано");
  await selectFutureDay(page, 1);
  await slotButton(page, "16:00").click();
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await expect(page.locator("#phone")).toHaveValue("");
  expect(errors).toEqual([]);
});

test("required form fields and unavailable day", async ({ page }) => {
  await page.goto("./");
  await selectFutureDay(page, 5);
  await expect(page.locator(".empty-state")).toContainText("Этот день полностью занят");
  await expect(page.getByRole("button", { name: "Продолжить", exact: true })).toBeDisabled();
  await expect(page.getByRole("group", { name: "Все получасовые слоты" }).getByRole("button", { disabled: true })).toHaveCount(32);
  await selectFutureDay(page, 1);
  await slotButton(page, "16:00").click();
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.getByText("Укажите имя.", { exact: true })).toBeVisible();
  await expect(page.getByText("Укажите фамилию.", { exact: true })).toBeVisible();
  await expect(page.getByText("Выберите вид мероприятия.", { exact: true })).toBeVisible();
  await expect(page.locator("#firstName")).toBeFocused();
  await page.locator("#phone").fill("123");
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.getByText("Введите российский мобильный номер", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Изменить дату или время", exact: false }).click();
  await expect(page.locator(".selection-summary")).toContainText("16:00–17:00");
});

test("calendar navigation respects the booking horizon", async ({ page }) => {
  await page.goto("./");
  await expect(page.getByRole("button", { name: "Предыдущий месяц" })).toBeDisabled();
  for (let i = 0; i < 3; i++) await page.getByRole("button", { name: "Следующий месяц" }).click();
  await expect(page.getByRole("button", { name: "Следующий месяц" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Предыдущий месяц" })).toBeEnabled();
  const lastDay = Number((await page.locator(".calendar-footnote").innerText()).match(/до (\d+)/)![1]);
  for (const day of await page.locator(".calendar-day").all()) {
    if (Number(await day.innerText()) > lastDay) await expect(day).toBeDisabled();
    else await expect(day).toBeEnabled();
  }
});
