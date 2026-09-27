import { expect, test, type Page } from "@playwright/test";

async function loadLab(page: Page) {
  await page.goto("./");
  await expect(page.locator("[data-lab-state=ready]")).toBeVisible({ timeout: 30_000 });
}

test.describe("guided tutorials", () => {
  test.skip(({ isMobile }) => isMobile, "desktop layout");

  test("a gated step only advances once the real action happens", async ({ page }) => {
    await loadLab(page);

    await page.getByRole("button", { name: "Tutorials" }).click();
    await expect(page.getByRole("heading", { name: "Guided tutorials" })).toBeVisible();
    await page.getByRole("listitem").filter({ hasText: "Identities & drives" }).getByRole("button", { name: "Start" }).click();

    // Step 1 is informational; advance with Next.
    await expect(page.getByRole("heading", { name: "This is you" })).toBeVisible();
    await page.getByRole("button", { name: "Next" }).click();

    // Step 2 is gated on David's USB actually being connected.
    await expect(page.getByRole("heading", { name: "Try it: insert David's USB" })).toBeVisible();
    await expect(page.getByText("Waiting for you to try it…")).toBeVisible();
    await expect(page.getByTestId("drive-david")).toContainText("Not inserted");

    await page.getByRole("button", { name: "Insert David's USB" }).click();
    await expect(page.getByTestId("drive-david")).toContainText("Connected");

    // The gate should flip and auto-advance to the next step on its own.
    await expect(page.getByText("✓ Nice — that's it.")).toBeVisible();
    await expect(page.getByRole("heading", { name: "The organization key tree" })).toBeVisible({ timeout: 3_000 });

    await page.getByRole("button", { name: "Exit tutorial" }).click();
    await expect(page.getByRole("heading", { name: "The organization key tree" })).toBeHidden();
  });

  test("switching users satisfies a gate driven by the active user chip", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Tutorials" }).click();
    await page.getByRole("listitem").filter({ hasText: "Identities & drives" }).getByRole("button", { name: "Start" }).click();
    await page.getByRole("button", { name: "Next" }).click(); // step 1 -> 2
    await page.getByRole("button", { name: "Skip this step" }).click(); // step 2 -> 3 (insert)
    await page.getByRole("button", { name: "Next" }).click(); // step 3 -> 4 (org tree info)

    await expect(page.getByRole("heading", { name: "Try it: switch to David" })).toBeVisible();
    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /David/ }).click();
    await expect(page.getByTestId("active-user-name")).toHaveText("David");
    await expect(page.getByRole("heading", { name: "That's the basics" })).toBeVisible({ timeout: 3_000 });

    await page.getByRole("button", { name: "Finish" }).click();
    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible();
  });
});
