import { expect, test } from "@playwright/test";

test("complete demo booking, gallery, time restrictions and reset", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Место для");
  await expect(page.locator("body")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole("button", { name: "Открыть изображение: Общее пространство", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("button", { name: "Следующее изображение" }).click();
  await expect(page.getByRole("dialog")).toContainText("2/4");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();

  await page.getByRole("link", { name: "Забронировать", exact: true }).click();
  await page.getByText("Тестовые сценарии доступности", { exact: true }).click();
  await page.getByRole("button", { name: /^Частично занят/ }).click();
  await expect(page.getByRole("group", { name: "Все получасовые слоты" }).getByRole("button")).toHaveCount(32);
  await expect(page.getByRole("button", { name: "18:00 — занято", exact: true })).toBeDisabled();
  const start = page.getByRole("combobox", { name: "Начало", exact: true });
  await expect(start.locator('option[value="1080"]')).toHaveCount(0);
  await expect(start.locator('option[value="1050"]')).toHaveCount(0);
  await start.selectOption("990");
  await expect(page.getByRole("combobox", { name: "Окончание", exact: true })).toHaveValue("1050");
  await expect(page.getByRole("combobox", { name: "Окончание", exact: true }).locator("option:not([disabled])")).toHaveText(["17:30", "18:00"]);
  await page.getByRole("combobox", { name: "Окончание", exact: true }).selectOption("1080");
  await page.getByLabel("Имя", { exact: false }).first().fill("Анна");
  await page.getByLabel("Фамилия", { exact: false }).fill("Иванова");
  await page.getByLabel("Телефон", { exact: false }).fill("8 (926) 123-45-67");
  await page.getByLabel("Что планируете?", { exact: false }).selectOption("День рождения");
  await page.getByRole("radio", { name: "Telegram" }).check();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.getByRole("heading", { name: "Всё готово для встречи." })).toBeVisible();
  await expect(page.locator(".confirmation-details")).toContainText("16:30–18:00");
  await expect(page.locator(".confirmation-details")).toContainText("1 ч 30 мин");
  await expect(page.locator(".confirmation-details")).toContainText("Telegram");
  await expect(page.getByText("Бронирование фактически не сохранено.", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Вернуться к календарю" }).click();
  await expect(page.getByLabel("Телефон", { exact: false })).toHaveValue("");
  expect(errors).toEqual([]);
});

test("required form fields and unavailable day", async ({ page }) => {
  await page.goto("/");
  await page.getByText("Тестовые сценарии доступности", { exact: true }).click();
  await page.getByRole("button", { name: /^Полностью занят/ }).click();
  await expect(page.getByRole("status")).toContainText("Этот день полностью занят");
  await expect(page.getByRole("combobox", { name: "Начало", exact: true })).toBeDisabled();
  await expect(page.getByRole("group", { name: "Все получасовые слоты" }).getByRole("button", { disabled: true })).toHaveCount(32);
  await page.getByRole("button", { name: /^Частично занят/ }).click();
  await page.getByRole("combobox", { name: "Начало", exact: true }).selectOption("960");
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.getByText("Укажите имя.", { exact: true })).toBeVisible();
  await expect(page.getByText("Укажите фамилию.", { exact: true })).toBeVisible();
  await expect(page.getByText("Для продолжения необходимо согласие.")).toBeVisible();
  await page.getByLabel("Телефон", { exact: false }).fill("123");
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.getByText("Введите российский мобильный номер", { exact: false })).toBeVisible();
});

test("calendar navigation respects the booking horizon", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Предыдущий месяц" })).toBeDisabled();
  for (let i = 0; i < 3; i++) await page.getByRole("button", { name: "Следующий месяц" }).click();
  await expect(page.getByRole("button", { name: "Следующий месяц" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Предыдущий месяц" })).toBeEnabled();
  const lastDay = Number((await page.locator(".calendar-footnote").innerText()).match(/до (\d+)/)![1]);
  for (const day of await page.locator(".calendar-day").all()) {
    const number = Number(await day.innerText());
    if (number > lastDay) await expect(day).toBeDisabled();
    else await expect(day).toBeEnabled();
  }
});
