import { expect, test, type Page } from "@playwright/test";

async function loadLab(page: Page) {
  await page.goto("./");
  await expect(page.locator("[data-lab-state=ready]")).toBeVisible({ timeout: 30_000 });
}

async function openFolder(page: Page, folder: string) {
  await page.getByRole("button", { name: new RegExp(`^${folder}\\b`) }).click();
}

async function switchUser(page: Page, name: string) {
  await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: new RegExp(name) }).click();
}

const status = (page: Page) => page.locator(".lab-status");
const modalTrace = (page: Page) => page.locator(".modal .trace");

test.describe("desktop lab", () => {
  test.skip(({ isMobile }) => isMobile, "desktop layout");

  test("each person has their own drive, and cross-department quorum follows what's inserted", async ({ page }) => {
    await loadLab(page);
    await expect(page.getByTestId("active-user-name")).toHaveText("Alice");
    await expect(page.getByTestId("active-user-label")).toHaveText("M.S.1");
    await expect(page.getByTestId("drive-alice")).toContainText("Connected");
    await expect(page.getByTestId("drive-david")).toContainText("Not inserted");

    await openFolder(page, "executive");
    await page.locator('[data-testid="file-row-acquisition-plan"]').dblclick();
    await expect(status(page)).toHaveText("Access denied: acquisition-plan.txt");
    await expect(modalTrace(page)).toContainText("Quorum not satisfied");
    await page.getByRole("button", { name: "Close" }).click();

    await page.getByRole("button", { name: "Insert David's USB" }).click();
    await expect(page.getByTestId("drive-david")).toContainText("Connected");
    await page.locator('[data-testid="file-row-acquisition-plan"]').dblclick();
    await expect(status(page)).toHaveText("Access granted: acquisition-plan.txt");
    await page.getByRole("button", { name: "Show the access trace" }).click();
    await expect(modalTrace(page)).toContainText("Physical devices: 2 (minimum 2)");
    await expect(page.getByTestId("opened-file")).toContainText("Acquisition plan (synthetic)");
  });

  test("Explorer shows dates and an already-expired file, and Properties explains it", async ({ page }) => {
    await loadLab(page);
    await openFolder(page, "engineering");
    const row = page.locator('[data-testid="file-row-api-keys-rotation"]');
    await expect(row).toContainText("Expired");
    await expect(row).toContainText("UTC");

    await row.click();
    await page.getByRole("button", { name: "Properties" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("Expires");
    await expect(dialog).toContainText("(expired)");
    await expect(dialog).toContainText("Already expired when the lab loaded");
    await page.getByRole("button", { name: "Close" }).click();

    await row.dblclick();
    await expect(status(page)).toHaveText("Access denied: api-keys-rotation.log");
    await expect(page.getByRole("dialog")).toContainText("expired");
  });

  test("a ghost's share is excluded, and Properties names it", async ({ page }) => {
    await loadLab(page);
    await openFolder(page, "engineering");
    const row = page.locator('[data-testid="file-row-legacy-migration-notes"]');
    await row.click();
    await page.getByRole("button", { name: "Properties" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("Priya");
    await expect(dialog).toContainText("ghost");
    await page.getByRole("button", { name: "Close" }).click();

    await row.dblclick();
    await expect(status(page)).toHaveText("Access denied: legacy-migration-notes.txt");
    await page.getByRole("button", { name: "Close" }).click();

    await page.getByRole("button", { name: "Insert Bob's USB" }).click();
    await row.dblclick();
    await expect(status(page)).toHaveText("Access granted: legacy-migration-notes.txt");
  });

  test("moving a slot onto another drive changes device counting live", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Insert Bob's USB" }).click();
    const bobDrive = page.getByTestId("drive-bob");
    await bobDrive.locator("select").selectOption("alice");
    await bobDrive.getByRole("button", { name: "Move" }).click();
    await expect(bobDrive).toContainText("No slots on this drive.");
    const aliceDrive = page.getByTestId("drive-alice");
    await expect(aliceDrive).toContainText("M.S.1");
    await expect(aliceDrive).toContainText("M.S.2");

    await openFolder(page, "engineering");
    await page.locator('[data-testid="file-row-architecture"]').dblclick();
    await expect(status(page)).toHaveText("Access granted: architecture.md");
  });

  test("send, receive, and acknowledge a file through the mailbox", async ({ page }) => {
    await loadLab(page);
    await openFolder(page, "engineering");
    await page.locator('[data-testid="file-row-architecture"]').click();
    await page.getByRole("button", { name: "Send…" }).click();
    await page.getByLabel("Recipient").selectOption("david");
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(status(page)).toHaveText("Transfer delivered to the relay for David");

    await switchUser(page, "David");
    await expect(page.getByTestId("active-user-name")).toHaveText("David");
    await page.getByRole("button", { name: /^Inbox \(1\)/ }).click();
    const letter = page.locator("[data-testid^=inbox-]").first();
    await expect(letter).toContainText("New · sealed");
    await expect(letter).toContainText("sender sealed");

    await letter.getByRole("button", { name: /^Receive/ }).click();
    await expect(status(page)).toHaveText("Insert your USB to open the letter");

    await page.getByRole("button", { name: "Insert David's USB" }).click();
    await letter.getByRole("button", { name: /^Receive/ }).click();
    await expect(status(page)).toHaveText("Transfer received: architecture.md");
    await expect(letter).toContainText("from Alice (M.S.1)");
    await expect(letter).toContainText("Received · acknowledged");

    await switchUser(page, "Alice");
    await page.getByRole("button", { name: /^Sent \(1\)/ }).click();
    await expect(page.locator("[data-testid^=sent-]")).toContainText("awaiting acknowledgement");
    await page.getByRole("button", { name: "Check relay for acknowledgements" }).click();
    await expect(page.locator("[data-testid^=sent-]")).toContainText("Acknowledged by recipient");
  });

  test("parent approval is requested, signed by the manager, then honoured", async ({ page }) => {
    await loadLab(page);
    await openFolder(page, "engineering");
    await page.locator('[data-testid="file-row-prod-credentials"]').dblclick();
    await expect(modalTrace(page)).toContainText("Parent approval from Sarah (M.S) missing");
    await page.getByRole("button", { name: "Close" }).click();

    await switchUser(page, "Sarah");
    await page.getByRole("button", { name: /^Approvals/ }).click();
    await page.getByRole("button", { name: "Approve and sign" }).click();
    await expect(status(page)).toContainText("Approved unlock of prod-credentials.txt");

    await switchUser(page, "Alice");
    // Already inside /engineering/ from earlier in this test; the Explorer
    // keeps its place across a user switch, same as a real file manager.
    await page.locator('[data-testid="file-row-prod-credentials"]').dblclick();
    await expect(status(page)).toHaveText("Access granted: prod-credentials.txt");
  });

  test("right-click opens a context menu with Open, Send, and Properties", async ({ page }) => {
    await loadLab(page);
    await openFolder(page, "public");
    await page.locator('[data-testid="file-row-company-handbook"]').click({ button: "right" });
    const menu = page.getByRole("menu");
    await expect(menu).toBeVisible();
    await expect(menu.getByRole("menuitem", { name: "Open" })).toBeVisible();
    await expect(menu.getByRole("menuitem", { name: "Send…" })).toBeVisible();
    await menu.getByRole("menuitem", { name: "Properties" }).click();
    await expect(page.getByRole("dialog")).toContainText("company-handbook.txt Properties");
  });

  test("an open dialog keeps keyboard focus across the periodic snapshot refresh", async ({ page }) => {
    await loadLab(page);
    await openFolder(page, "engineering");
    await page.locator('[data-testid="file-row-architecture"]').click();
    await page.getByRole("button", { name: "Send…" }).click();
    const recipient = page.getByLabel("Recipient");
    await recipient.focus();
    await page.waitForTimeout(3_500);
    await expect(recipient).toBeFocused();
  });

  test("terminal and buttons share one state, and reset restores the seed", async ({ page }) => {
    await loadLab(page);
    const input = page.getByLabel("Terminal command");
    await input.fill("usb insert david");
    await input.press("Enter");
    await expect(page.getByTestId("drive-david")).toContainText("Connected");
    await input.fill("su emma");
    await input.press("Enter");
    await expect(page.getByTestId("active-user-name")).toHaveText("Emma");
    await expect(page.getByTestId("terminal-output")).toContainText("Switched to Emma (M.A.1)");

    await page.getByRole("button", { name: "Reset Lab" }).click();
    await expect(page.getByTestId("active-user-name")).toHaveText("Alice");
    await expect(page.getByTestId("drive-david")).toContainText("Not inserted");
  });
});
