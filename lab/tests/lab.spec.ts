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
    await expect(modalTrace(page)).toContainText("not enough valid shares to reconstruct this key");
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
    await bobDrive.getByLabel(/^Move/).selectOption("alice");
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

    // With Alice's drive out, the acknowledgement waits, sealed to her key.
    await page.getByRole("button", { name: "Eject Alice's USB" }).click();
    await switchUser(page, "Alice");
    await page.getByRole("button", { name: /^Sent \(1\)/ }).click();
    await expect(page.locator("[data-testid^=sent-]")).toContainText("awaiting acknowledgement");
    // Plugging her drive in opens the answer by itself; there is no refresh to click.
    await page.getByRole("button", { name: "Insert Alice's USB" }).click();
    await expect(page.locator("[data-testid^=sent-]")).toContainText("Acknowledged by recipient");
  });

  test("parent approval needs the manager's drive to sign the unlock", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Eject Sarah's USB" }).click();
    await openFolder(page, "engineering");
    await page.locator('[data-testid="file-row-prod-credentials"]').dblclick();
    await expect(status(page)).toHaveText("Access denied: prod-credentials.txt");
    await expect(modalTrace(page)).toContainText("this unlock needs the parent label's signature");
    await page.getByRole("button", { name: "Close" }).click();

    await page.getByRole("button", { name: "Insert Sarah's USB" }).click();
    await page.locator('[data-testid="file-row-prod-credentials"]').dblclick();
    await expect(status(page)).toHaveText("Access granted: prod-credentials.txt");
    await page.getByRole("button", { name: "Show the access trace" }).click();
    await expect(modalTrace(page)).toContainText("Parent approval: M.S signed for M.S.1");
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
    await input.fill("keyquorum-device list /media/alice-usb");
    await input.press("Enter");
    await expect(page.getByTestId("terminal-output")).toContainText("M.S.1");
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
  test("bridge buttons and the terminal run the real keyquorum bridge command", async ({ page }) => {
    await loadLab(page);
    const bridges = page.getByTestId("bridges");
    await expect(bridges.getByTestId("bridge-M.S-M.A")).toBeVisible();

    // Alice (M.S.1) → Emma (M.A.1): refused until a whitelist entry exists.
    await bridges.getByLabel("Node").selectOption("M.S.1");
    await bridges.getByLabel("Peer").selectOption("M.A.1");
    await bridges.getByRole("button", { name: "Establish bridge" }).click();
    await expect(status(page)).toHaveText("error: cross-branch link is not whitelisted by either node");

    await bridges.getByRole("button", { name: "Allow node → peer" }).click();
    await expect(bridges.getByTestId("allowed-M.S.1-M.A.1")).toBeVisible();
    await bridges.getByRole("button", { name: "Establish bridge" }).click();
    await expect(status(page)).toHaveText("Established bridge M.S.1 <-> M.A.1");
    await expect(bridges.getByTestId("bridge-M.S.1-M.A.1")).toBeVisible();

    // Removing the seeded manager link hides David from Alice's slice.
    await bridges.getByRole("button", { name: "Remove bridge M.S to M.A" }).click();
    await expect(bridges.getByTestId("bridge-M.S-M.A")).toHaveCount(0);
    await expect(bridges.getByTestId("allowed-M.S-M.A")).toBeVisible();

    const input = page.getByLabel("Terminal command");
    await input.fill("bridge list 1");
    await input.press("Enter");
    await expect(page.getByTestId("terminal-output")).toContainText("M.S.1 <-> M.A.1");
  });

  test("the activity log shows three tracked-file stories, filterable and expandable", async ({ page }) => {
    await loadLab(page);
    await page.locator('[data-panel="activity"] details.log > summary').click();
    const panel = page.locator('[data-panel="activity"]');
    const entries = panel.getByTestId("history-entry");
    await expect(entries.first()).toBeVisible();

    // Filters narrow the log to their own events.
    const filter = (name: string) => panel.getByRole("group", { name: "Filter activity" }).getByRole("button", { name });
    await filter("Conflict").click();
    await expect(entries.first()).toBeVisible();
    for (const event of await entries.evaluateAll((nodes) => nodes.map((n) => n.getAttribute("data-event")))) {
      expect(["AutoMergeRequiresHuman", "HistoryForkDetected", "ContentConflictDetected", "ConflictReviewAssigned", "ConflictUnresolved", "AutoMergeBlocked", "ConflictReviewEscalated", "BridgeUsed"]).toContain(event);
    }
    await expect(panel.locator('[data-event="ConflictReviewAssigned"]')).toHaveCount(1);
    await filter("Sharing").click();
    await expect(panel.locator('[data-event="ShareAttempted"]')).toHaveCount(1);
    await expect(panel.locator('[data-event="AutoMergeClean"]')).toHaveCount(0);
    await filter("Security").click();
    await expect(panel.getByText("Nothing under Security yet.")).toBeVisible();

    // An entry expands to its revision, label, parents and trust; the graph
    // lists the revisions with what they descend from.
    await filter("Revision").click();
    const merge = panel.locator('[data-event="AutoMergeClean"]');
    await merge.locator("summary").click();
    await expect(merge).toContainText("Generated label");
    await expect(merge).toContainText("Parents");
    await expect(merge).toContainText("pending");
    await expect(panel.getByTestId("revision-graph")).toContainText("forecast.txt");
    await filter("All").click();
    await expect(panel.getByTestId("revision-graph")).toContainText("budget.txt");

    // A file or a revision narrows the log and the graph to itself.
    const graph = panel.getByTestId("revision-graph");
    const sections = graph.locator("section");
    expect(await sections.count()).toBeGreaterThan(1);
    const budgetId = await panel.locator("#history-file-filter option", { hasText: "budget.txt" }).getAttribute("value");
    await panel.getByLabel("File", { exact: true }).selectOption(budgetId!);
    await expect(sections).toHaveCount(1);
    await expect(graph).toContainText("budget.txt");
    await expect(graph).not.toContainText("forecast.txt");
    await panel.getByLabel("File", { exact: true }).selectOption("");
    await panel.getByLabel("Revision", { exact: true }).fill("no such revision");
    await expect(panel.getByText("Nothing matches these filters yet.")).toBeVisible();
  });

  test("tracked files can be made, edited, signed, verified and handed over from the Activity page", async ({ page }) => {
    await loadLab(page);
    await switchUser(page, "Sarah");
    const panel = page.getByTestId("tracked-files");
    await panel.getByLabel("New tracked file").fill("plan.txt");
    await panel.getByLabel("First revision").fill("a\nb");
    await panel.getByRole("button", { name: "Track and sign" }).click();
    const card = panel.locator('[data-testid="tracked-file"][data-path="/home/sarah/tracked/plan.txt.kqtf"]');
    await expect(card.locator('li[data-trust="trusted"]')).toHaveCount(1);

    // An unsigned edit is pending, and the timeline shows it at once.
    await card.getByLabel("Edit the current revision").fill("a\nB");
    await card.getByLabel("Sign this edit with my slot").uncheck();
    await card.getByRole("button", { name: "Check in" }).click();
    await expect(card.locator('li[data-trust="pending"]')).toHaveCount(1);
    await page.locator('[data-panel="activity"] details.log > summary').click();
    await expect(page.locator('[data-panel="activity"] [data-event="EditCheckedIn"]').first()).toBeVisible();

    // Verify opens the CLI's own report.
    await card.getByRole("button", { name: "Verify history" }).click();
    await expect(page.getByTestId("opened-file")).toContainText("History and revision graph verify");
    await page.getByRole("button", { name: "Close" }).click();

    await card.locator('li[data-trust="pending"]').getByRole("button", { name: "Sign revision" }).click();
    await expect(card.locator('li[data-trust="pending"]')).toHaveCount(0);

    // Hand the file to Alice; she accepts it into her own copy.
    await card.getByLabel("Share with").selectOption("alice");
    await card.getByRole("button", { name: "Share file" }).click();
    await expect(panel.getByTestId("tracked-letters")).toContainText("waiting");
    await switchUser(page, "Alice");
    await panel.getByTestId("tracked-letters").getByRole("button", { name: "Accept plan.txt" }).click();
    await expect(panel.getByTestId("tracked-letters")).toContainText("accepted");
    await expect(panel.getByTestId("tracked-select")).toContainText("/home/alice/tracked/plan.txt.kqtf");

    // Back as Sarah (her drive is in), Alice's answer is recorded as she signs in.
    await switchUser(page, "Sarah");
    await expect(panel.getByTestId("tracked-letters")).toContainText("answer recorded");
    await expect(panel.getByTestId("tracked-letters").getByRole("button", { name: "Record the answer" })).toHaveCount(0);

    // Ask Alice for a change; a request only asks, and her answer only says yes or no.
    await card.getByLabel("Ask").selectOption("alice");
    await card.getByLabel("for", { exact: true }).selectOption("change");
    await card.getByLabel("Request message").fill("Please tighten the second paragraph");
    await card.getByRole("button", { name: "Send request" }).click();
    await expect(panel.getByTestId("tracked-requests")).toContainText("waiting");
    await switchUser(page, "Alice");
    await expect(panel.getByTestId("tracked-requests")).toContainText("Please tighten the second paragraph");
    await panel.getByTestId("tracked-requests").getByRole("button", { name: "Accept request for plan.txt" }).click();
    await expect(panel.getByTestId("tracked-requests")).toContainText("accepted");
    await switchUser(page, "Sarah");
    await expect(panel.getByTestId("tracked-requests")).toContainText("answer recorded");
    await expect(page.locator('[data-panel="activity"] [data-event="ChangeRequested"]').first()).toBeVisible();
    await expect(page.locator('[data-panel="activity"] [data-event="RequestAnswered"]').first()).toBeVisible();
  });

  test("the seeded memo conflict is settled from the Resolve form, and only its reviewer can", async ({ page }) => {
    await loadLab(page);
    const panel = page.getByTestId("tracked-files");
    await panel.getByTestId("tracked-select").selectOption({ label: "memo.txt — /srv/keyquorum/tracked/memo.txt.kqtf" });
    const card = panel.locator('[data-testid="tracked-file"][data-path="/srv/keyquorum/tracked/memo.txt.kqtf"]');
    await expect(card.getByTestId("tracked-heads")).toContainText("two heads");

    // Alice wrote one side of the conflict: the command refuses her.
    await card.getByTestId("history-resolve").getByRole("button", { name: "Resolve", exact: true }).click();
    await expect(status(page)).toContainText("memo.txt");
    await expect(card.getByTestId("tracked-heads")).toContainText("two heads");

    // Sarah is the assigned reviewer; her edited result settles it.
    await switchUser(page, "Sarah");
    const form = card.getByTestId("history-resolve");
    await form.getByLabel("Resolve as the active reviewer").selectOption("edited");
    await form.getByLabel("Result text").fill("Owner: TBD\nBudget: 100\n");
    await form.getByRole("button", { name: "Resolve", exact: true }).click();
    await expect(card.getByTestId("tracked-heads")).toContainText("Current revision");
    await expect(card.getByTestId("history-resolve")).toHaveCount(0);
  });

  test("a tracked file can be renamed without changing what it is", async ({ page }) => {
    await loadLab(page);
    await switchUser(page, "Sarah");
    const panel = page.getByTestId("tracked-files");
    await panel.getByLabel("New tracked file").fill("draft.txt");
    await panel.getByLabel("First revision").fill("v1");
    await panel.getByRole("button", { name: "Track and sign" }).click();
    const card = panel.locator('[data-testid="tracked-file"][data-path="/home/sarah/tracked/draft.txt.kqtf"]');
    await expect(card.getByTestId("tracked-heads")).toContainText("latest trusted");
    const idBefore = await card.getAttribute("data-file-id");
    await card.getByLabel("New name").fill("final.txt");
    await card.getByRole("button", { name: "Rename file" }).click();
    await expect(card).toContainText("final.txt");
    await page.locator('[data-panel="activity"] details.log > summary').click();
    await expect(page.locator('[data-panel="activity"] [data-event="FileRenamed"]').first()).toBeVisible();
    if (idBefore) await expect(card).toHaveAttribute("data-file-id", idBefore);
  });

  test("a tracked file can be expired from the Activity page, leaving a tombstone", async ({ page }) => {
    await loadLab(page);
    await switchUser(page, "Sarah");
    const panel = page.getByTestId("tracked-files");
    await panel.getByLabel("New tracked file").fill("brief.txt");
    await panel.getByLabel("First revision").fill("short-lived");
    await panel.getByRole("button", { name: "Track and sign" }).click();
    const card = panel.locator('[data-testid="tracked-file"][data-path="/home/sarah/tracked/brief.txt.kqtf"]');
    await card.getByLabel("Expires (UTC)").fill("2099-01-01T00:00");
    await card.getByRole("button", { name: "Schedule expiry" }).click();
    await expect(card).toContainText("Content is destroyed after 2099-01-01T00:00:00Z");
    await card.getByRole("button", { name: "Destroy content now" }).click();
    await expect(card.getByTestId("tracked-tombstone")).toBeVisible();
    await expect(card.getByLabel("Edit the current revision")).toHaveCount(0);
    await page.locator('[data-panel="activity"] details.log > summary').click();
    await page.getByRole("group", { name: "Filter activity" }).getByRole("button", { name: "Security" }).click();
    await expect(page.locator('[data-panel="activity"] [data-event="ContentDestroyed"]').first()).toBeVisible();
    // The tombstone still verifies.
    await card.getByRole("button", { name: "Verify history" }).click();
    await expect(page.getByTestId("opened-file")).toContainText("Tombstone");
  });

  test("revision view, diff, snapshots and gate links all work from the tracked-files panel", async ({ page }) => {
    await loadLab(page);
    const panel = page.getByTestId("tracked-files");
    await panel.getByLabel("New tracked file").fill("log.txt");
    await panel.getByLabel("First revision").fill("one");
    await panel.getByRole("button", { name: "Track and sign" }).click();
    const card = panel.locator('[data-testid="tracked-file"][data-path="/home/alice/tracked/log.txt.kqtf"]');
    await card.getByLabel("Edit the current revision").fill("two");
    await card.getByRole("button", { name: "Check in" }).click();
    await expect(card.locator("li[data-trust]")).toHaveCount(2);

    // View an older revision and the changes in the newer one.
    await card.locator("li[data-trust]").first().getByRole("button", { name: /^View revision/ }).click();
    await expect(page.getByTestId("opened-file")).toHaveText("one");
    await page.getByRole("button", { name: "Close" }).click();
    await card.locator("li[data-trust]").last().getByRole("button", { name: /^Diff revision/ }).click();
    await expect(page.getByTestId("opened-file")).toContainText("two");
    await page.getByRole("button", { name: "Close" }).click();

    // Export a snapshot, then check it against the file.
    await card.getByRole("button", { name: "Export history snapshot" }).click();
    await card.getByRole("button", { name: "Check log.txt-1.kqhs" }).click();
    await expect(page.getByTestId("opened-file")).toContainText("It is a point in the history of log.txt");
    await page.getByRole("button", { name: "Close" }).click();

    // Link a quorum file's gate; opening that file lands in this timeline.
    await card.getByLabel("Record unlocks of").selectOption({ label: "architecture.md (quorum)" });
    await card.getByRole("button", { name: "Link gate" }).click();
    await expect(card.getByTestId("tracked-links")).toContainText("architecture.md (quorum)");
    await openFolder(page, "engineering");
    await page.locator('[data-testid^="file-row-"]', { hasText: "architecture.md" }).first().dblclick();
    await expect(status(page)).toHaveText("Access granted: architecture.md");
    await page.getByRole("button", { name: "Close" }).click();
    await page.locator('[data-panel="activity"] details.log > summary').click();
    await expect(page.locator('[data-panel="activity"] [data-event="QuorumUnlockAttempted"]').first()).toBeVisible();
  });
});
