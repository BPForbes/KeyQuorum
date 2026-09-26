import { defineConfig, devices } from "@playwright/test";

// Runs against the production build served by `vite preview` under the same
// /KeyQuorum/ base path GitHub Pages uses. Build first: `npm run build`.
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined;

export default defineConfig({
  testDir: "tests",
  timeout: 60_000,
  fullyParallel: false,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: "http://127.0.0.1:4173/KeyQuorum/",
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
  webServer: [
    {
      command: "npm run preview",
      url: "http://127.0.0.1:4173/KeyQuorum/",
      reuseExistingServer: !process.env.CI,
    },
    {
      // A second origin standing in for bailey-forbes.com (tests/embed.spec.ts).
      command: "node tests/parent-server.mjs",
      url: "http://127.0.0.1:4174/?src=http://127.0.0.1:4173/",
      reuseExistingServer: !process.env.CI,
    },
  ],
});
