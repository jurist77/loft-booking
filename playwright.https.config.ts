import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e-https", workers: 1, fullyParallel: false, timeout: 40000,
  use: { baseURL: "https://fixture.dynv6.net", ignoreHTTPSErrors: false, trace: "retain-on-failure" },
  projects: [
    { name: "desktop", use: { viewport: { width: 1440, height: 1000 }, launchOptions: { executablePath: process.env.CHROMIUM_PATH } } },
    { name: "mobile", use: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, launchOptions: { executablePath: process.env.CHROMIUM_PATH } } },
  ],
});
