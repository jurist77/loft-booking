import { test } from "@playwright/test";
import { triggerAvailabilityConflict } from "./flows";

test("confirmation rejects availability changed after selection", async ({ page, baseURL }) => {
  await triggerAvailabilityConflict(page, baseURL!);
});
