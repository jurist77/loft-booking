import { expect, test, type Page } from "@playwright/test";
import { fillDemoContact, openCalendar, selectFutureDay, slotButton } from "./flows";

async function expectOriginalBrand(page: Page) {
  const image = page.getByRole("banner").getByRole("img", { name: "studio 19.25 — Творческое пространство", exact: true });
  await expect(image).toBeVisible();
  await image.evaluate(async (element) => { await (element as HTMLImageElement).decode(); });
  await expect(image).toHaveAttribute("src", /\/images\/studio-19-25-logo\.jpg$/);
  const geometry = await image.evaluate((element) => {
    const image = element as HTMLImageElement;
    const box = image.getBoundingClientRect();
    return { naturalWidth: image.naturalWidth, naturalHeight: image.naturalHeight, ratio: box.width / box.height };
  });
  expect(geometry.naturalWidth).toBe(1280); expect(geometry.naturalHeight).toBe(775);
  expect(geometry.ratio).toBeCloseTo(1280 / 775, 2);
  await expect(page.getByRole("banner")).toContainText("Творческое пространство");
  await expect(page.locator("body")).not.toContainText(/loft\s*studio/i);
}

test("original studio 19.25 brand is present on all five screens and the last hour needs only three contacts", async ({ page }) => {
  await page.goto("./");
  await expect(page).toHaveTitle("studio 19.25 — Творческое пространство");
  await expect(page.locator('meta[name="description"]')).toHaveAttribute("content", /studio 19\.25/);
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute("href", /\/images\/studio-19-25-logo\.jpg$/);
  await expectOriginalBrand(page);
  await openCalendar(page); await expectOriginalBrand(page);
  await selectFutureDay(page, 6); await expectOriginalBrand(page);
  await expect(page.locator(".slots button")).toHaveCount(28);
  await expect(page.locator(".time-heading")).toContainText("09:00–23:00");
  await expect(slotButton(page, "08:30")).toHaveCount(0);
  await expect(slotButton(page, "09:00")).toBeEnabled();
  await expect(slotButton(page, "22:30")).toBeDisabled();
  await slotButton(page, "22:00").click();
  await expect(page.locator(".selection-summary")).toHaveText("22:00–23:00 · 1 ч");
  await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await expectOriginalBrand(page);
  await expect(page.locator(".contact-fields input")).toHaveCount(3);
  await expect(page.locator(".contact-fields select, #eventType")).toHaveCount(0);
  await fillDemoContact(page);
  await page.getByRole("button", { name: "Подтвердить выбор" }).click();
  await expect(page.locator('[data-screen="confirmation"]')).toBeVisible();
  await expectOriginalBrand(page);
  await expect(page.locator(".confirmation-details")).toContainText("22:00–23:00");
  await expect(page.locator(".confirmation-details")).not.toContainText("мероприятия");
  await expect(page.locator(".form-error")).toHaveCount(0);
});
