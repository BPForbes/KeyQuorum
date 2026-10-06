import { randomBytes } from "node:crypto";
import { defineConfig, devices } from "@playwright/test";

// Runs against the production build served by tests/mock-relay.mjs, a
// stand-in relay that serves dist/ at /console/ the way the real host does
// and answers the console's routes with fixtures. Build first:
// `npm run build`.
//
// The bearers the mock accepts are drawn at random here, once per run
// (`??=` keeps the first value when Playwright re-evaluates this file in a
// worker), handed to the mock through its environment and read by the tests
// from theirs. No test key is written down.
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined;
process.env.CONSOLE_TEST_ADMIN_KEY ??= `kq_${randomBytes(24).toString("hex")}`;
process.env.CONSOLE_TEST_PULL_KEY ??= `kq_${randomBytes(24).toString("hex")}`;

export default defineConfig({
  testDir: "tests",
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: "http://127.0.0.1:4175/console/",
    launchOptions: executablePath ? { executablePath } : {},
  },
  projects: [
    {
      name: "desktop",
      use: { ...devices["Desktop Chrome"], launchOptions: executablePath ? { executablePath } : {} },
      testIgnore: /mobile\.spec\.ts/,
    },
    {
      name: "mobile",
      use: { ...devices["Pixel 7"], launchOptions: executablePath ? { executablePath } : {} },
      testMatch: /mobile\.spec\.ts/,
    },
  ],
  webServer: {
    command: "node tests/mock-relay.mjs",
    url: "http://127.0.0.1:4175/health",
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      CONSOLE_TEST_ADMIN_KEY: process.env.CONSOLE_TEST_ADMIN_KEY,
      CONSOLE_TEST_PULL_KEY: process.env.CONSOLE_TEST_PULL_KEY,
    },
  },
});
