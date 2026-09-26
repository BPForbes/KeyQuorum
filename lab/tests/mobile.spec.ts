import { expect, test } from "@playwright/test";

test("phone layout shows one section at a time", async ({ page }) => {
  await page.goto("./");
  await expect(page.locator("[data-lab-state=ready]")).toBeVisible({ timeout: 30_000 });
  const tabs = page.getByRole("navigation", { name: "Lab sections" });
  await expect(tabs).toBeVisible();
  await expect(page.getByRole("heading", { name: "File Explorer" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Mock USB devices" })).toBeHidden();

  await tabs.getByRole("button", { name: "USB devices" }).click();
  await expect(page.getByRole("heading", { name: "Mock USB devices" })).toBeVisible();
  await page.getByRole("button", { name: "Insert David's USB" }).click();
  await expect(page.getByTestId("drive-david")).toContainText("Connected");

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});
