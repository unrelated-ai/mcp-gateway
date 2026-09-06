import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  globalSetup: "./e2e/setup.ts",
  outputDir: "../output/playwright/e2e-results",
  reporter: [
    ["list"],
    ["html", { outputFolder: "../output/playwright/e2e-report", open: "never" }],
  ],
  use: {
    browserName: "chromium",
    viewport: { width: 1440, height: 1000 },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    permissions: ["clipboard-read", "clipboard-write"],
  },
});
