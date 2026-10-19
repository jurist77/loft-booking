import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e-server", workers: 1, fullyParallel: false, timeout: 40000,
  use: { baseURL: process.env.SERVER_BASE_URL, trace: "retain-on-failure" },
  projects: [
    { name: "desktop", use: { viewport: { width: 1440, height: 1000 }, launchOptions: { executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium" } } },
    { name: "mobile", use: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, launchOptions: { executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium" } } },
  ],
});
