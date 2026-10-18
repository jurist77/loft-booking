import { expect, type Page } from "@playwright/test";

/** Fictional contact values from the specification; no real customer data. */
export async function fillDemoContact(page: Page) {
  await page.getByLabel("Имя", { exact: false }).first().fill("Тест");
  await page.getByLabel("Фамилия", { exact: false }).fill("Пример");
  await page.getByLabel("Телефон", { exact: false }).fill("9261234567");
  await page.getByLabel("Что планируете?", { exact: false }).selectOption("Другое");
  await page.getByRole("radio", { name: "SMS" }).check();
  await page.getByRole("checkbox").check();
}

/** Change the demo fixture's day anchor after selection to exercise a real conflict. */
export async function triggerAvailabilityConflict(page: Page, baseURL: string) {
  const baseline = new Date();
  await page.clock.setFixedTime(baseline);
  await page.goto(baseURL);

  // Wait for hydration before selecting a future free day (today + six days).
  await page.getByText("Тестовые сценарии доступности", { exact: true }).click();
  await page.getByRole("button", { name: /^Свободный день/ }).click();
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Moscow", year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(baseline);
  const get = (type: string) => parts.find((part) => part.type === type)!.value;
  const target = new Date(`${get("year")}-${get("month")}-${get("day")}T12:00:00Z`);
  target.setUTCDate(target.getUTCDate() + 6);
  const targetLabel = new Intl.DateTimeFormat("ru-RU", {
    timeZone: "UTC", day: "numeric", month: "long", year: "numeric",
  }).format(target);
  if (target.getUTCMonth() !== Number(get("month")) - 1) {
    await page.getByRole("button", { name: "Следующий месяц" }).click();
  }
  await page.getByRole("button", { name: targetLabel, exact: true }).click();
  await page.getByRole("combobox", { name: "Начало", exact: true }).selectOption("960");
  await expect(page.getByRole("combobox", { name: "Окончание", exact: true })).toHaveValue("1020");
  await fillDemoContact(page);

  // Date changes, timers do not advance: the selected snapshot is still free,
  // but confirm() re-reads the fixture and sees a fully occupied day.
  await page.clock.setFixedTime(new Date(baseline.getTime() + 86_400_000));
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.locator(".form-error")).toHaveText("Это время уже занято. Выберите другой свободный интервал.");
  await expect(page.locator(".confirmation")).toHaveCount(0);
}
