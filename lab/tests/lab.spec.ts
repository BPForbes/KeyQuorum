import { expect, test, type Page } from "@playwright/test";

async function loadLab(page: Page) {
  await page.goto("./");
  await expect(page.locator("[data-lab-state=ready]")).toBeVisible({ timeout: 30_000 });
}

const status = (page: Page) => page.locator(".lab-status");
const trace = (page: Page) => page.getByTestId("access-trace");

test.describe("desktop lab", () => {
  test.skip(({ isMobile }) => isMobile, "desktop layout");

  test("cross-department quorum follows the inserted drives", async ({ page }) => {
    await loadLab(page);
    await expect(page.getByTestId("active-user-name")).toHaveText("Alice");
    await expect(page.getByTestId("active-user-label")).toHaveText("M.S.1");
    await expect(page.getByTestId("drive-engineering")).toContainText("Connected");
    await expect(page.getByTestId("drive-accounting")).toContainText("Not inserted");

    await page.getByRole("button", { name: /acquisition-plan\.txt/ }).click();
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(status(page)).toHaveText("Access denied: acquisition-plan.txt");
    await expect(trace(page)).toContainText("Accounting USB not inserted");
    await expect(trace(page)).toContainText("Quorum not satisfied");

    await page.getByRole("button", { name: "Insert Accounting USB" }).click();
    await expect(page.getByTestId("drive-accounting")).toContainText("Connected");
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(status(page)).toHaveText("Access granted: acquisition-plan.txt");
    await expect(trace(page)).toContainText("Physical devices: 2 (minimum 2)");
    await expect(page.getByTestId("opened-file")).toContainText("Acquisition plan (synthetic)");
  });

  test("send, receive, and acknowledge a file", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: /architecture\.md/ }).click();
    await page.getByRole("button", { name: "Send…" }).click();
    await page.getByLabel("Recipient").selectOption("david");
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(status(page)).toHaveText("Transfer delivered to the relay for David");

    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /David/ }).click();
    await expect(page.getByTestId("active-user-name")).toHaveText("David");
    await page.getByRole("button", { name: /^Inbox \(1\)/ }).click();
    const letter = page.locator("[data-testid^=inbox-]").first();
    await expect(letter).toContainText("New · sealed");
    await expect(letter).toContainText("sender sealed");

    await letter.getByRole("button", { name: /^Receive/ }).click();
    await expect(status(page)).toHaveText("Insert your USB to open the letter");

    await page.getByRole("button", { name: "Insert Accounting USB" }).click();
    await letter.getByRole("button", { name: /^Receive/ }).click();
    await expect(status(page)).toHaveText("Transfer received: architecture.md");
    await expect(letter).toContainText("from Alice (M.S.1)");
    await expect(letter).toContainText("Received · acknowledged");

    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /Alice/ }).click();
    await page.getByRole("button", { name: /^Sent \(1\)/ }).click();
    await expect(page.locator("[data-testid^=sent-]")).toContainText("awaiting acknowledgement");
    await page.getByRole("button", { name: "Check relay for acknowledgements" }).click();
    await expect(page.locator("[data-testid^=sent-]")).toContainText("Acknowledged by recipient");
  });

  test("parent approval is requested, signed by the manager, then honoured", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: /prod-credentials\.txt/ }).click();
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(trace(page)).toContainText("Parent approval from Sarah (M.S) missing");

    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /Sarah/ }).click();
    await page.getByRole("button", { name: /^Approvals/ }).click();
    await page.getByRole("button", { name: "Approve and sign" }).click();
    await expect(status(page)).toContainText("Approved unlock of prod-credentials.txt");

    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /Alice/ }).click();
    await page.getByRole("button", { name: /prod-credentials\.txt/ }).click();
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(status(page)).toHaveText("Access granted: prod-credentials.txt");
  });

  test("terminal and buttons share one state, and reset restores the seed", async ({ page }) => {
    await loadLab(page);
    const input = page.getByLabel("Terminal command");
    await input.fill("usb insert accounting");
    await input.press("Enter");
    await expect(page.getByTestId("drive-accounting")).toContainText("Connected");
    await input.fill("su emma");
    await input.press("Enter");
    await expect(page.getByTestId("active-user-name")).toHaveText("Emma");
    await expect(page.getByTestId("terminal-output")).toContainText("Switched to Emma (M.A.1)");

    await page.getByRole("button", { name: "Reset Lab" }).click();
    await expect(page.getByTestId("active-user-name")).toHaveText("Alice");
    await expect(page.getByTestId("drive-accounting")).toContainText("Not inserted");
  });
});
