import { expect, type Page } from "@playwright/test";
import { selectFutureDay, slotButton } from "../e2e/flows.ts";
export { selectFutureDay, slotButton };
export async function contacts(page: Page, offset = 1) {
  await selectFutureDay(page, offset); await expect(page.locator(".slots button")).toHaveCount(28);
  await slotButton(page, "10:00").click(); await page.getByRole("button", { name: "Продолжить", exact: true }).click();
  await fillContact(page);
}
export async function fillContact(page: Page) {
  await page.locator("#firstName").fill("Тест"); await page.locator("#lastName").fill("Пример"); await page.locator("#phone").fill("8 (900) 000-00-00");
}
