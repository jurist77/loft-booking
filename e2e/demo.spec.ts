import { expect, test } from "@playwright/test";
import { fillDemoContact, selectFutureDay, slotButton } from "./flows";

test("demo is labelled and never transmits or persists entered contacts", async ({ page, context, baseURL }) => {
  const requests: { method: string; url: string; body: string }[] = [];
  const failures: string[] = [];
  page.on("request", (request) => requests.push({ method: request.method(), url: request.url(), body: request.postData() || "" }));
  page.on("response", (response) => { if (response.status() >= 400) failures.push(`${response.status()} ${response.url()}`); });
  await page.goto("./");
  await expect(page.getByText("Демонстрационная версия", { exact: true })).toBeVisible();
  await selectFutureDay(page, 6); await slotButton(page, "10:00").click(); await slotButton(page, "12:00").click();
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  const warning = "Это демонстрация. Бронирование не создаётся, данные не сохраняются и уведомления не отправляются";
  await expect(page.locator(".demo-warning")).toHaveText(warning);
  await fillDemoContact(page);
  await page.locator("#firstName").fill("Демопроверка");
  const afterInput = requests.length;
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.getByRole("heading", { name: "Ваше бронирование", exact: true })).toBeVisible();
  await expect(page.locator(".demo-notice")).toContainText(warning);
  const contactRequests = requests.slice(afterInput);
  expect(contactRequests.filter((request) => !["GET", "HEAD"].includes(request.method))).toEqual([]);
  for (const request of requests) {
    expect(new URL(request.url).origin).toBe(new URL(baseURL!).origin);
    expect(decodeURIComponent(request.url) + request.body).not.toMatch(/Демопроверка|79261234567|9261234567/);
  }
  const storage = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage }, cookie: document.cookie, url: location.href }));
  expect(storage.local).toEqual({}); expect(storage.session).toEqual({});
  expect(JSON.stringify(storage)).not.toMatch(/Демопроверка|79261234567|9261234567/);
  expect(JSON.stringify(await context.cookies())).not.toMatch(/Демопроверка|79261234567|9261234567/);
  expect(failures).toEqual([]);
  await page.reload();
  await expect(page.locator(".selection-summary")).toHaveText("Время пока не выбрано");
  await expect(page.locator(".confirmation")).toHaveCount(0);
});

test("dates are initialized at opening time rather than static build time", async ({ page }) => {
  await page.clock.setFixedTime(new Date("2026-11-02T21:05:00Z")); // November 3 in Moscow.
  await page.goto("./");
  await expect(page.locator('.calendar-day[aria-current="date"]')).toHaveAttribute("aria-label", "3 ноября 2026 г.");
  await expect(page.locator(".calendar-footnote")).toContainText("3 февраля");
  await selectFutureDay(page, 1);
  await expect(slotButton(page, "12:00")).toBeDisabled();
  await expect(slotButton(page, "18:00")).toBeDisabled();
});

test("hash navigation, reload and all local images work in a repository subdirectory", async ({ page }) => {
  await page.goto("./");
  await page.getByRole("link", { name: "Забронировать", exact: true }).click();
  await expect(page).toHaveURL(/#booking$/);
  await page.getByRole("link", { name: "Loft Studio — главная", exact: true }).click();
  await expect(page).toHaveURL(/#$/);
  await page.goBack(); await expect(page).toHaveURL(/#booking$/);
  await page.goForward(); await expect(page).toHaveURL(/#$/);
  await page.reload();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Место для");
  await page.locator(".gallery-grid").scrollIntoViewIfNeeded();
  await page.locator(".gallery-grid img").evaluateAll(async (images) => { await Promise.all(images.map((image) => (image as HTMLImageElement).decode())); });
  const images = await page.locator(".gallery-grid img").evaluateAll((items) => items.map((image) => ({ ok: (image as HTMLImageElement).complete && (image as HTMLImageElement).naturalWidth > 0, path: new URL((image as HTMLImageElement).src).pathname })));
  expect(images).toHaveLength(4); expect(images.every((image) => image.ok)).toBe(true);
  const pathname = new URL(page.url()).pathname;
  for (const image of images) expect(image.path.startsWith(pathname)).toBe(true);
});
