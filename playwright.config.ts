import { defineConfig } from "@playwright/test";

const baseURL = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:3000").replace(/\/?$/, "/");

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  workers: 2,
  use: { baseURL, trace: "retain-on-failure" },
  projects: [
    { name: "desktop", use: { viewport: { width: 1440, height: 1000 }, launchOptions: { executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium" } } },
    { name: "mobile", use: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, launchOptions: { executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium" } } },
  ],
  webServer: process.env.PLAYWRIGHT_BASE_URL ? undefined : { command: "npm run dev", url: "http://127.0.0.1:3000", reuseExistingServer: !process.env.CI, timeout: 120000 },
});
