import { expect, test, type Page } from "@playwright/test";

async function loadLab(page: Page) {
  await page.goto("./");
  await expect(page.locator("[data-lab-state=ready]")).toBeVisible({ timeout: 30_000 });
}

test("both PDF manuals are linked from Tutorials & Documentation and actually served", async ({ page }) => {
  await loadLab(page);
  await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
  await expect(page.getByRole("heading", { name: "Tutorials & Documentation" })).toBeVisible();
  const cli = page.getByRole("link", { name: "KeyQuorum (CLI)" });
  const labManual = page.getByRole("link", { name: "KeyQuorum Lab (this GUI)" });
  await expect(cli).toBeVisible();
  await expect(labManual).toBeVisible();

  const cliHref = await cli.getAttribute("href");
  const labHref = await labManual.getAttribute("href");
  expect(cliHref).toMatch(/docs\/KeyQuorum_Manual\.pdf$/);
  expect(labHref).toMatch(/docs\/KeyQuorum_Lab_Manual\.pdf$/);

  for (const href of [cliHref, labHref]) {
    const response = await page.request.get(new URL(href!, page.url()).toString());
    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("pdf");
  }
});
