import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { chromium, expect } from "@playwright/test";
import { fillDemoContact, selectFutureDay, slotButton } from "../e2e/flows.ts";

const baseURL = process.env.ACCEPTANCE_BASE_URL || "http://127.0.0.1:4173/loft-booking/";
const target = new URL(baseURL);
const local = ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname);
assert.ok(local || target.protocol === "https:", "A public DEMO must use HTTPS");
const output = new URL("../docs/acceptance/v1.4/", import.meta.url);
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium" });
const results = { testedURL: baseURL, publicHTTPS: !local && target.protocol === "https:", checkedAt: new Date().toISOString(), browser: browser.version(), widths: [] };
try {
  for (const width of [320, 360, 375, 390, 430, 768, 1024, 1440]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 }, isMobile: width < 768, hasTouch: width < 768, reducedMotion: "reduce" });
    const errors = []; const requests = []; const failedResponses = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
    page.on("response", (response) => { if (response.status() >= 400) failedResponses.push(response.status()); });
    page.on("request", (request) => requests.push({ method: request.method(), url: request.url(), body: request.postData() || "" }));
    const stages = [];
    async function checkStage(name) {
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `Horizontal overflow: ${width}px ${name}`);
      assert.equal(await page.locator("[data-screen]").count(), 1);
      stages.push(name);
    }
    const response = await page.goto(baseURL);
    assert.equal(response.status(), 200);
    await expect(page).toHaveTitle("studio 19.25 — Творческое пространство");
    await page.locator(".studio-brand img").evaluate((image) => image.decode());
    await expect(page.getByText("Демонстрационная версия", { exact: true })).toBeVisible();
    await expect(page.locator('[data-screen="welcome"]')).toBeVisible();
    await expect(page.locator(".calendar, .slots, .contact-fields")).toHaveCount(0);
    assert.equal(await page.evaluate(() => document.documentElement.scrollHeight > innerHeight + 1), false);
    await checkStage("welcome");
    await page.getByRole("button", { name: "О пространстве", exact: true }).click();
    await page.locator(".gallery-grid").scrollIntoViewIfNeeded();
    assert.equal(await page.locator(".gallery-grid img").evaluateAll(async (images) => {
      await Promise.all(images.map((image) => image.decode()));
      return images.length === 4 && images.every((image) => image.complete && image.naturalWidth > 0);
    }), true);
    await page.getByRole("button", { name: "Закрыть описание", exact: true }).click();
    await page.getByRole("button", { name: "Забронировать", exact: true }).click();
    await checkStage("calendar");
    await selectFutureDay(page, 1);
    await expect(page.locator(".slots button")).toHaveCount(28);
    await expect(page.locator(".busy-slot")).toHaveCount(8);
    await checkStage("busy-grid");
    await selectFutureDay(page, 6);
    await slotButton(page, "10:00").click();
    await slotButton(page, "12:00").click();
    await expect(page.locator(".selection-summary")).toHaveText("10:00–12:30 · 2 ч 30 мин");
    await checkStage("selection");
    await page.getByRole("button", { name: "Продолжить", exact: true }).click();
    await expect(page.locator(".demo-warning")).toBeVisible();
    await fillDemoContact(page);
    await checkStage("form");
    await page.getByRole("button", { name: "Подтвердить выбор" }).click();
    await expect(page.getByRole("heading", { name: "Ваше бронирование", exact: true })).toBeVisible();
    await expect(page.locator(".demo-notice")).toContainText("Это демонстрация. Бронирование не создаётся, данные не сохраняются и уведомления не отправляются");
    await checkStage("confirmation");
    await page.reload();
    await expect(page.locator('[data-screen="welcome"]')).toBeVisible();
    await expect(page.locator(".calendar, .slots, .contact-fields")).toHaveCount(0);
    const storage = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage }, cookie: document.cookie, url: location.href }));
    assert.deepEqual(storage.local, {}); assert.deepEqual(storage.session, {});
    assert.doesNotMatch(JSON.stringify(storage), /79261234567|9261234567|Тест|Пример/);
    assert.doesNotMatch(JSON.stringify(await page.context().cookies()), /79261234567|9261234567|Тест|Пример/);
    for (const request of requests) {
      assert.ok(["GET", "HEAD"].includes(request.method), "Unexpected data submission");
      assert.equal(new URL(request.url).origin, target.origin, "Unexpected third-party request");
      assert.doesNotMatch(decodeURIComponent(request.url) + request.body, /79261234567|9261234567|Тест|Пример/);
    }
    assert.deepEqual(errors, []); assert.deepEqual(failedResponses, []);
    results.widths.push({ width, stages, noOverflow: true, noClientErrors: true, noFailedAssets: true, noContactTransmissionOrPersistence: true, reloadClearsState: true });
    await page.close();
  }
  await mkdir(output, { recursive: true });
  await writeFile(new URL("runtime-checks.json", output), JSON.stringify(results, null, 2) + "\n");
  console.log(JSON.stringify(results, null, 2));
} finally { await browser.close(); }
