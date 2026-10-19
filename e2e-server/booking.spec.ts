import { expect, test, type Page } from "@playwright/test";
import Database from "better-sqlite3";
import { chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { contacts, fillContact, selectFutureDay, slotButton } from "./flows";

const path = process.env.STUDIO_E2E_DB ?? "";
if (!path.startsWith(`${tmpdir()}/studio-server-ui-`)) throw new Error("Private test database required; never use the working DB");
const db = new Database(path); db.pragma("foreign_keys=ON");
const count = () => (db.prepare("SELECT count(*) AS n FROM bookings").get() as { n: number }).n;
const submit = (page: Page) => page.getByRole("button", { name: "Подтвердить выбор", exact: true });
function requests(page: Page) {
  const values: Record<string, string>[] = [];
  page.on("request", (r) => { if (r.method() === "POST" && new URL(r.url()).pathname === "/api/bookings") values.push(r.postDataJSON()); });
  return values;
}
function fixture(date: string) {
  const start = Date.parse(`${date}T10:00:00+03:00`);
  db.prepare(`INSERT INTO bookings(id,resource_id,starts_at,ends_at,first_name,last_name,phone,created_at,updated_at)
    VALUES ('fixture','studio-19-25',?,?,'Тест','Пример','+79000000000',0,0)`).run(start, start + 3600000);
}
const logs: string[] = [];
function observe(page: Page) { page.on("console", (m) => logs.push(m.text())); page.on("pageerror", () => logs.push("UNHANDLED_PAGE_ERROR")); }
test.beforeEach(async ({ page, context }, info) => {
  db.transaction(() => { db.exec("DELETE FROM booking_events; DELETE FROM bookings;"); })(); logs.length = 0;
  const hash = createHash("sha256").update(info.testId + info.project.name).digest("hex");
  await context.setExtraHTTPHeaders({ "x-studio-client-ip": `2001:db8:${hash.slice(0, 4)}:${hash.slice(4, 8)}::1` });
  observe(page); await page.goto("./");
});
test.afterEach(() => {
  for (const value of ["Тест", "Пример", "79000000000", "9000000000", "UNHANDLED_PAGE_ERROR"]) expect(logs.some((text) => text.includes(value))).toBe(false);
});
test.afterAll(() => db.close());

test("complete real booking, double click guard, persisted availability after reload", async ({ page }) => {
  const sent = requests(page); await contacts(page);
  let release!: () => void; const hold = new Promise<void>((resolve) => { release = resolve; });
  let arrived!: () => void; const seen = new Promise<void>((resolve) => { arrived = resolve; });
  await page.route("**/api/bookings", async (route) => { const response = await route.fetch(); arrived(); await hold; await route.fulfill({ response }); });
  await page.evaluate(() => { const b = document.querySelector<HTMLButtonElement>('button[type="submit"]')!; b.click(); b.click(); });
  await seen; await expect(page.locator('[data-screen="confirmation"]')).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Отправляем заявку…" })).toBeDisabled(); await expect(page.locator("#phone")).toBeDisabled();
  release(); await expect(page.getByTestId("booking-id")).toBeVisible();
  expect(sent).toHaveLength(1); expect(count()).toBe(1);
  await expect(page.locator(".confirmation")).toContainText("Бронирование подтверждено и сохранено");
  await expect(page.locator(".confirmation")).not.toContainText("Тест"); await expect(page.getByTestId("confirmation-phone")).toHaveCount(0);
  await page.reload(); await expect(page.locator('[data-screen="welcome"]')).toBeVisible();
  await selectFutureDay(page); await expect(slotButton(page, "10:00")).toBeDisabled(); await expect(slotButton(page, "10:30")).toHaveClass(/busy-slot/);
});
test("two actual clients compete for one interval and loser keeps contacts", async ({ page, browser }, info) => {
  const context = await browser.newContext({ viewport: page.viewportSize()!, isMobile: info.project.name === "mobile", hasTouch: info.project.name === "mobile", extraHTTPHeaders: { "x-studio-client-ip": "2001:db8:ffff:1234::1" } });
  try {
    const second = await context.newPage(); observe(second); await second.goto(process.env.SERVER_BASE_URL!);
    await contacts(page); await contacts(second);
    await Promise.all([submit(page).click(), submit(second).click()]);
    await expect.poll(async () => (await page.locator('[data-screen="confirmation"]').count()) + (await second.locator('[data-screen="confirmation"]').count())).toBe(1);
    const loser = await page.locator('[data-screen="confirmation"]').count() ? second : page;
    await expect(loser.locator('[data-screen="time"]')).toBeVisible(); await expect(loser.locator(".form-error")).toContainText("уже занят");
    await expect(slotButton(loser, "10:00")).toBeDisabled(); await slotButton(loser, "11:00").click();
    await loser.getByRole("button", { name: "Продолжить", exact: true }).click(); await expect(loser.locator("#firstName")).toHaveValue("Тест"); expect(count()).toBe(1);
  } finally { await context.close(); }
});
test("Back refreshes changed availability, resets stale interval and preserves contacts", async ({ page }) => {
  await contacts(page); const iso = await page.evaluate(() => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Moscow" }).format(new Date(Date.now() + 86400000)));
  fixture(iso); await page.getByRole("button", { name: "← Назад", exact: true }).click();
  await expect(page.locator(".form-error")).toContainText("больше недоступно"); await expect(page.locator(".selection-summary")).toHaveText("Время пока не выбрано");
  await slotButton(page, "11:00").click(); await page.getByRole("button", { name: "Продолжить", exact: true }).click(); await expect(page.locator("#phone")).toHaveValue("8 (900) 000-00-00");
  await page.getByRole("button", { name: "← Назад", exact: true }).click(); await selectFutureDay(page, 2);
  await expect(page.locator(".selection-summary")).toHaveText("Время пока не выбрано");
});
test("availability failure never renders a free grid and can be retried", async ({ page }) => {
  await page.route("**/api/availability?**", (route) => route.fulfill({ status: 503, json: { error: { code: "STORAGE_UNAVAILABLE" } } }));
  await selectFutureDay(page); await expect(page.locator(".form-error")).toContainText("Свободное время пока не подтверждено");
  await expect(page.locator('[data-screen="calendar"]')).toBeVisible(); await expect(page.locator(".slots")).toHaveCount(0);
  await page.unroute("**/api/availability?**"); await page.getByRole("button", { name: "Повторить загрузку", exact: true }).click();
  await expect(page.locator(".slots button")).toHaveCount(28);
});
test("HTTP 400 permits correction with a consciously changed payload and new ID", async ({ page }) => {
  const sent = requests(page); await contacts(page);
  await page.route("**/api/bookings", (route) => route.fulfill({ status: 400, json: { error: { code: "INVALID_CONTACT", message: "private" } } }), { times: 1 });
  await submit(page).click(); await expect(page.locator(".form-error")).toContainText("Сервер отклонил данные"); await expect(page.locator("#firstName")).toBeEnabled();
  await page.locator("#firstName").fill("Тестовое"); await submit(page).click(); await expect(page.getByTestId("booking-id")).toBeVisible();
  expect(sent).toHaveLength(2); expect(sent[0].requestId).not.toBe(sent[1].requestId); expect(count()).toBe(1);
});
test("lost HTTP response after COMMIT is safely retried with the same ID", async ({ page }) => {
  const sent = requests(page); await contacts(page);
  await page.route("**/api/bookings", async (route) => { await route.fetch(); await route.abort("failed"); }, { times: 1 });
  await submit(page).click(); await expect(page.locator(".form-error")).toContainText("Заявка могла сохраниться"); expect(count()).toBe(1);
  await expect(page.locator("#phone")).toBeDisabled(); await expect(page.getByRole("button", { name: "← Назад", exact: true })).toBeDisabled();
  await expect(page.locator('[data-screen="confirmation"]')).toHaveCount(0);
  await page.getByRole("button", { name: "Безопасно повторить отправку", exact: true }).click(); await expect(page.getByTestId("booking-id")).toBeVisible();
  expect(sent).toHaveLength(2); expect(sent[0].requestId).toBe(sent[1].requestId); expect(count()).toBe(1);
  expect((db.prepare("SELECT count(*) AS n FROM booking_events").get() as { n: number }).n).toBe(1);
});
test("actual readonly SQLite 503 preserves the attempt and succeeds after recovery", async ({ page }) => {
  const sent = requests(page); await contacts(page); chmodSync(path, 0o400);
  try { await submit(page).click(); await expect(page.locator(".form-error")).toContainText("не удалось подтвердить"); await expect(page.locator('[data-screen="confirmation"]')).toHaveCount(0); expect(count()).toBe(0); }
  finally { chmodSync(path, 0o600); }
  const retry = page.getByRole("button", { name: "Безопасно повторить отправку", exact: true }); await expect(retry).toBeEnabled(); await retry.click();
  await expect(page.getByTestId("booking-id")).toBeVisible(); expect(sent[0].requestId).toBe(sent[1].requestId); expect(count()).toBe(1);
});
test("429 respects Retry-After without automatic POST retries or ID changes", async ({ page }) => {
  const sent = requests(page); await contacts(page);
  await page.route("**/api/bookings", (route) => route.fulfill({ status: 429, headers: { "Retry-After": "2" }, json: { error: { code: "RATE_LIMITED" } } }), { times: 1 });
  await submit(page).click(); await expect(page.locator(".form-error")).toContainText("Слишком много запросов");
  await expect(page.locator('button[type="submit"]')).toBeDisabled(); expect(sent).toHaveLength(1); expect(count()).toBe(0);
  await expect(submit(page)).toBeEnabled(); expect(sent).toHaveLength(1); await submit(page).click();
  await expect(page.getByTestId("booking-id")).toBeVisible(); expect(sent[0].requestId).toBe(sent[1].requestId);
});
test("changing an uncertain attempt requires an explicit warning", async ({ page }) => {
  const sent = requests(page); await contacts(page);
  await page.route("**/api/bookings", (route) => route.abort("failed"), { times: 1 });
  await submit(page).click(); await expect(page.locator("#firstName")).toBeDisabled();
  page.once("dialog", (dialog) => dialog.accept()); await page.getByRole("button", { name: "Изменить заявку после предупреждения" }).click();
  await page.locator("#firstName").fill("Тестовое"); await submit(page).click(); await expect(page.getByTestId("booking-id")).toBeVisible();
  expect(sent[0].requestId).not.toBe(sent[1].requestId); expect(count()).toBe(1);
});
test("all five screens fit widths 320–1440 without hiding controls", async ({ page }) => {
  let offset = 10;
  for (const width of [320, 360, 375, 390, 430, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: width < 768 ? 844 : 1000 }); await page.goto("./");
    const checkWidth = async () => expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await checkWidth(); await page.getByRole("button", { name: "Забронировать", exact: true }).click(); await checkWidth();
    await selectFutureDay(page, offset++); await expect(page.locator(".slots button")).toHaveCount(28); await slotButton(page, "10:00").click(); await slotButton(page, "12:00").click();
    await expect(page.locator(".selection-summary")).toContainText("2 ч 30 мин"); await checkWidth();
    await page.getByRole("button", { name: "Продолжить", exact: true }).click(); await fillContact(page); await checkWidth();
    await submit(page).click(); await expect(page.getByTestId("booking-id")).toBeVisible(); await checkWidth();
    await page.getByRole("button", { name: "Новое бронирование" }).click(); await expect(page.locator('[data-screen="welcome"]')).toBeVisible();
  }
});
