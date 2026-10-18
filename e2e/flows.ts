import { expect, type Page } from "@playwright/test";

export function slotButton(page: Page, time: string) {
  return page.getByRole("group", { name: "Все получасовые слоты" }).getByRole("button", { name: new RegExp(`^${time} —`) });
}

/** Reach a fixture through the real calendar, never through client-facing demo controls. */
export async function selectFutureDay(page: Page, offset = 1) {
  const iso = await page.evaluate(() => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Moscow", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date()));
  const target = new Date(`${iso}T12:00:00Z`);
  target.setUTCDate(target.getUTCDate() + offset);
  const label = new Intl.DateTimeFormat("ru-RU", { timeZone: "UTC", day: "numeric", month: "long", year: "numeric" }).format(target);
  const previous = page.getByRole("button", { name: "Предыдущий месяц" });
  for (let i = 0; i < 3 && await previous.isEnabled(); i++) await previous.click();
  const day = page.getByRole("button", { name: label, exact: true });
  for (let i = 0; i < 3 && await day.count() === 0; i++) await page.getByRole("button", { name: "Следующий месяц" }).click();
  await day.click();
  return label;
}

/** Fictional contact values from the specification; never real customer data. */
export async function fillDemoContact(page: Page) {
  await page.getByLabel("Имя", { exact: false }).first().fill("Тест");
  await page.getByLabel("Фамилия", { exact: false }).fill("Пример");
  await page.getByLabel("Мобильный телефон", { exact: false }).fill("9261234567");
  await page.getByLabel("Тип мероприятия", { exact: false }).selectOption("Другое");
}

export async function triggerAvailabilityConflict(page: Page, baseURL: string) {
  const baseline = new Date();
  await page.clock.setFixedTime(baseline);
  await page.goto(baseURL);
  await selectFutureDay(page, 6);
  await slotButton(page, "16:00").click();
  await expect(page.locator(".selection-summary")).toContainText("16:00–17:00");
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await fillDemoContact(page);
  // Shift the fixture's date anchor after selection. confirm() reads fresh bookings.
  await page.clock.setFixedTime(new Date(baseline.getTime() + 86_400_000));
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.locator(".form-error")).toHaveText("Это время уже занято. Выберите другой свободный интервал.");
  await expect(page.locator(".confirmation")).toHaveCount(0);
}
