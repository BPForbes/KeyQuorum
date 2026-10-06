import { expect, test } from "@playwright/test";

const ADMIN_KEY = process.env.CONSOLE_TEST_ADMIN_KEY ?? "";

test.beforeEach(async ({ request }) => {
  await request.post("http://127.0.0.1:4175/__test/reset");
});

test("on a phone the tab row shows one section at a time", async ({ page }) => {
  await page.goto("./");
  await expect(page.locator("[data-console-state=ready]")).toBeVisible({ timeout: 30_000 });
  const tabs = page.getByRole("navigation", { name: "Console sections" });
  await expect(tabs).toBeVisible();
  await expect(page.locator("[data-panel=relay]")).toBeVisible();
  await expect(page.locator("[data-panel=keys]")).toBeHidden();

  await page.getByTestId("signin-key").fill(ADMIN_KEY);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByTestId("session-scope")).toHaveText("admin");

  await tabs.getByRole("button", { name: "API keys" }).click();
  await expect(page.locator("[data-panel=keys]")).toBeVisible();
  await expect(page.locator("[data-panel=relay]")).toBeHidden();
  await expect(page.getByTestId("api-key-1")).toBeVisible();
});
