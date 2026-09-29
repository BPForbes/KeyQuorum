import { expect, test, type Page } from "@playwright/test";

async function loadLab(page: Page) {
  await page.goto("./");
  await expect(page.locator("[data-lab-state=ready]")).toBeVisible({ timeout: 30_000 });
}

test.describe("guided tutorials", () => {
  test.skip(({ isMobile }) => isMobile, "desktop layout");

  test("the picker groups multiple workflows under each major category", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();

    for (const [heading, workflowCount] of [
      ["Identities & drives", 5],
      ["Files & unlocking", 5],
      ["Mailbox: sending & receiving", 3],
      ["File history", 4],
    ] as const) {
      const category = page.getByRole("region", { name: heading });
      await expect(category).toBeVisible();
      await expect(category.getByRole("button", { name: "Start" })).toHaveCount(workflowCount);
    }
  });

  test("a gated step only advances once the real action happens", async ({ page }) => {
    await loadLab(page);

    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await expect(page.getByRole("heading", { name: "Tutorials & Documentation" })).toBeVisible();
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
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page.getByRole("listitem").filter({ hasText: "Identities & drives" }).getByRole("button", { name: "Start" }).click();
    await page.getByRole("button", { name: "Next" }).click(); // step 1 -> 2
    await page.getByRole("button", { name: "Skip this step" }).click(); // step 2 -> 3 (insert)
    await page.getByRole("button", { name: "Next" }).click(); // step 3 -> 4 (org tree info)

    await expect(page.getByRole("heading", { name: "Try it: switch to David" })).toBeVisible();
    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /David/ }).click();
    await expect(page.getByTestId("active-user-name")).toHaveText("David");
    await expect(page.getByRole("heading", { name: "Try it: eject David's USB" })).toBeVisible({ timeout: 3_000 });
    await page.getByRole("button", { name: "Eject David's USB" }).click();

    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible();
  });

  test("the mailbox module's receive gate ignores a denied attempt and an unrelated refresh", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Mailbox: sending & receiving" })
      .getByRole("button", { name: "Start" })
      .click();

    // Step 1 is gated on a delivery actually addressed to David.
    await expect(page.getByRole("heading", { name: "Try it: send a file" })).toBeVisible();
    await page.getByRole("button", { name: "public" }).click();
    await page.getByTestId("file-row-company-handbook").click();
    await page.getByRole("button", { name: "Send…" }).click();
    await page.getByLabel("Recipient").selectOption("david");
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Try it: become the recipient" })).toBeVisible({ timeout: 3_000 });

    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /David/ }).click();
    await expect(page.getByRole("heading", { name: "Try it: receive the letter" })).toBeVisible({ timeout: 3_000 });

    // David's own drive is not inserted here, so Receive is denied — this
    // must NOT satisfy the gate (the bug Codex flagged: kind === "receive"
    // alone also matches a denied attempt and the inbox-refresh button).
    const letter = page.locator("[data-testid^=inbox-]").first();
    await letter.getByRole("button", { name: /^Receive/ }).click();
    await expect(page.locator(".lab-status")).toHaveText("Insert your USB to open the letter");
    await expect(page.getByRole("heading", { name: "Try it: receive the letter" })).toBeVisible();
    await expect(page.getByText("Waiting for you to try it…")).toBeVisible();

    // A real, successful receive does satisfy it.
    await page.getByRole("button", { name: "Insert David's USB" }).click();
    await letter.getByRole("button", { name: /^Receive/ }).click();
    await expect(page.getByRole("heading", { name: "Sent and acknowledged" })).toBeVisible({ timeout: 3_000 });

    await page.getByRole("button", { name: "Finish" }).click();
    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible();
  });

  test("a send made before the module starts does not satisfy its send gate", async ({ page }) => {
    await loadLab(page);

    // A send to David happens first, entirely outside the tutorial.
    await page.getByRole("button", { name: "public" }).click();
    await page.getByTestId("file-row-company-handbook").click();
    await page.getByRole("button", { name: "Send…" }).click();
    await page.getByLabel("Recipient").selectOption("david");
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.locator(".lab-status")).toHaveText("Transfer delivered to the relay for David");

    // Only now does the visitor open the mailbox module. Its first step
    // must still be gated: the send above is stale, from before the step
    // (and the module) ever started.
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Mailbox: sending & receiving" })
      .getByRole("button", { name: "Start" })
      .click();
    await expect(page.getByRole("heading", { name: "Try it: send a file" })).toBeVisible();
    await expect(page.getByText("Waiting for you to try it…")).toBeVisible();
    await page.waitForTimeout(1_500);
    await expect(page.getByRole("heading", { name: "Try it: send a file" })).toBeVisible();

    // A genuinely new send does satisfy it.
    await page.getByTestId("file-row-project-roadmap").click();
    await page.getByRole("button", { name: "Send…" }).click();
    await page.getByLabel("Recipient").selectOption("david");
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Try it: become the recipient" })).toBeVisible({
      timeout: 3_000,
    });
  });

  test("an unrelated action while a state-gated step is open does not satisfy it", async ({ page }) => {
    await loadLab(page);

    // Pre-existing state: David's USB is already connected, as if from
    // before this tutorial run started.
    await page.getByRole("button", { name: "Insert David's USB" }).click();
    await expect(page.getByTestId("drive-david")).toContainText("Connected");

    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Identities & drives" })
      .getByRole("button", { name: "Start" })
      .click();
    await page.getByRole("button", { name: "Next" }).click(); // step 1 -> 2

    // Entering the step corrects the precondition instead of treating it
    // as already satisfied: the drive is ejected again so the action is
    // genuinely there to demonstrate.
    await expect(page.getByRole("heading", { name: "Try it: insert David's USB" })).toBeVisible();
    await expect(page.getByTestId("drive-david")).toContainText("Not inserted");
    await expect(page.getByText("Waiting for you to try it…")).toBeVisible();

    // An unrelated action creates a new activity-log entry, but not of the
    // kind this step requires -- it must not satisfy the gate.
    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /Morgan/ }).click();
    await page.waitForTimeout(800);
    await expect(page.getByRole("heading", { name: "Try it: insert David's USB" })).toBeVisible();
    await expect(page.getByText("Waiting for you to try it…")).toBeVisible();

    // The real action does satisfy it.
    await page.getByRole("button", { name: "Insert David's USB" }).click();
    await expect(page.getByRole("heading", { name: "The organization key tree" })).toBeVisible({ timeout: 3_000 });
  });

  test("the mailbox module's send step stays usable even if David is already active", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /David/ }).click();
    await expect(page.getByTestId("active-user-name")).toHaveText("David");

    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Mailbox: sending & receiving" })
      .getByRole("button", { name: "Start" })
      .click();

    // Entering the step switches away from David first: SendDialog
    // excludes the active user from their own recipient list, so this
    // step would otherwise be unrunnable, not just already-satisfied.
    await expect(page.getByTestId("active-user-name")).not.toHaveText("David", { timeout: 3_000 });

    await page.getByRole("button", { name: "public" }).click();
    await page.getByTestId("file-row-company-handbook").click();
    await page.getByRole("button", { name: "Send…" }).click();
    await expect(page.getByLabel("Recipient")).toContainText("David");
    await page.getByLabel("Recipient").selectOption("david");
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Try it: become the recipient" })).toBeVisible({
      timeout: 3_000,
    });
  });

  test("the bridges module's whitelist gate needs a bridge allow command, not any terminal action", async ({
    page,
  }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Bridges & remote devices" })
      .getByRole("button", { name: "Start" })
      .click();

    await expect(page.getByRole("heading", { name: "Whitelist before linking" })).toBeVisible();
    await expect(page.getByText("Waiting for you to try it…")).toBeVisible();

    // A different, successful bridge command (a read-only list, not an
    // "allow") still logs the same generic "terminal" activity kind, but
    // must not satisfy a gate that specifically asks for a whitelist entry.
    const input = page.getByLabel("Terminal command");
    await input.fill("bridge list 1");
    await input.press("Enter");
    await page.waitForTimeout(800);
    await expect(page.getByRole("heading", { name: "Whitelist before linking" })).toBeVisible();
    await expect(page.getByText("Waiting for you to try it…")).toBeVisible();

    // The real action -- Allow node -> peer -- does satisfy it.
    const bridges = page.getByTestId("bridges");
    await bridges.getByLabel("Node").selectOption("M.S.1");
    await bridges.getByLabel("Peer").selectOption("M.A.1");
    await bridges.getByRole("button", { name: "Allow node → peer" }).click();
    await expect(page.getByRole("heading", { name: "Establish, remove, or deny" })).toBeVisible({ timeout: 3_000 });
  });

  test("restructure is a propose step and a separate countersign step", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Key administration" })
      .getByRole("button", { name: "Start" })
      .click();

    // Step 1 either action completes; skip it without touching the tree.
    await expect(page.getByRole("heading", { name: "Revoke versus reissue" })).toBeVisible();
    await page.getByRole("button", { name: "Skip this step" }).click();

    // Step 2 is gated on the authority (David, M.A) actually proposing.
    await expect(page.getByRole("heading", { name: "Try it: propose a restructure" })).toBeVisible({
      timeout: 3_000,
    });
    await expect(page.getByTestId("active-user-name")).toHaveText("David");
    await page.getByRole("button", { name: "Propose restructure as M.A" }).click();

    // Step 3 is a distinct gate: only the parent (Morgan, M) countersigns.
    // Entering it switches to her and connects her drive automatically.
    await expect(page.getByRole("heading", { name: "Try it: countersign as the parent" })).toBeVisible({
      timeout: 3_000,
    });
    await expect(page.getByTestId("active-user-name")).toHaveText("Morgan");
    await expect(page.getByTestId("drive-morgan")).toContainText("Connected");
    await page.getByPlaceholder("Your device passphrase").fill("lab-demo-M");
    await page.getByRole("button", { name: "Countersign" }).click();

    await expect(page.getByRole("heading", { name: "Parent approval is enforced at unlock" })).toBeVisible({
      timeout: 3_000,
    });
  });

  test("the reject-and-acknowledge module forces Alice as sender even when another user is already active", async ({
    page,
  }) => {
    await loadLab(page);

    // Simulate arriving here right after a tutorial that leaves someone
    // else active -- each lab user's Sent list is their own mailbox, so a
    // send recorded under the wrong one would leave the final step unable
    // to find it.
    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /Morgan/ }).click();
    await expect(page.getByTestId("active-user-name")).toHaveText("Morgan");

    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Reject & acknowledge" })
      .getByRole("button", { name: "Start" })
      .click();

    // Entering the step switches to Alice specifically, not just away
    // from David.
    await expect(page.getByTestId("active-user-name")).toHaveText("Alice", { timeout: 3_000 });

    await page.getByRole("button", { name: "public" }).click();
    await page.getByTestId("file-row-company-handbook").click();
    await page.getByRole("button", { name: "Send…" }).click();
    await page.getByLabel("Recipient").selectOption("david");
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Try it: become the recipient" })).toBeVisible({
      timeout: 3_000,
    });

    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /David/ }).click();
    await expect(page.getByRole("heading", { name: "Try it: reject the letter" })).toBeVisible({ timeout: 3_000 });
    await page
      .locator("[data-testid^=inbox-]")
      .first()
      .getByRole("button", { name: /^Reject/ })
      .click();
    await expect(page.getByRole("heading", { name: "Try it: return to the sender" })).toBeVisible({
      timeout: 3_000,
    });

    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /Alice/ }).click();
    await expect(page.getByRole("heading", { name: "Try it: collect the acknowledgement" })).toBeVisible({
      timeout: 3_000,
    });
    await page.getByRole("button", { name: /^Sent/ }).click();
    await page.getByTestId("mailbox-refresh").click();
    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible({ timeout: 3_000 });
  });

  test("the tracked-file module walks track, unsigned edit, fallback, sign and the timeline", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "1 · Track, sign & fall back" })
      .getByRole("button", { name: "Start" })
      .click();

    await expect(page.getByRole("heading", { name: "Tracked files live on the Activity page" })).toBeVisible();
    // The module put the lab where its steps can run: Sarah, with her drive in.
    await expect(page.getByTestId("active-user-name")).toHaveText("Sarah");
    await page.getByRole("button", { name: "Next" }).click();

    const panel = page.getByTestId("tracked-files");
    await expect(page.getByRole("heading", { name: "Try it: track a new file" })).toBeVisible();
    await expect(page.getByText("Waiting for you to try it…")).toBeVisible();
    await panel.getByLabel("New tracked file").fill("notes.txt");
    await panel.getByLabel("First revision").fill("draft 1");
    await panel.getByRole("button", { name: "Track and sign" }).click();

    await expect(page.getByRole("heading", { name: "Try it: check in an unsigned edit" })).toBeVisible({ timeout: 3_000 });
    // A signed check-in does not satisfy the unsigned step.
    await panel.getByLabel("Edit the current revision").fill("draft 2");
    await panel.getByRole("button", { name: "Check in" }).click();
    await expect(page.getByRole("heading", { name: "Try it: check in an unsigned edit" })).toBeVisible();
    await panel.getByLabel("Edit the current revision").fill("draft 3");
    await panel.getByLabel("Sign this edit with my slot").uncheck();
    await panel.getByRole("button", { name: "Check in" }).click();

    await expect(page.getByRole("heading", { name: "Sharing falls back" })).toBeVisible({ timeout: 3_000 });
    await expect(panel.getByTestId("tracked-shareable")).toContainText("the last trusted revision");
    await page.getByRole("button", { name: "Next" }).click();

    await expect(page.getByRole("heading", { name: "Try it: sign the edit" })).toBeVisible();
    await panel.locator('li[data-trust="pending"]').getByRole("button", { name: "Sign revision" }).click();

    await expect(page.getByRole("heading", { name: "Try it: read the timeline" })).toBeVisible({ timeout: 3_000 });
    await expect(panel.locator('li[data-trust="pending"]')).toHaveCount(0);
    await page.locator('[data-panel="activity"] details.log > summary').click();
    await page.getByRole("group", { name: "Filter activity" }).getByRole("button", { name: "Revision" }).click();
    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible({ timeout: 3_000 });
  });

  async function startModule(page: Page, title: string) {
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page.getByRole("listitem").filter({ hasText: title }).getByRole("button", { name: "Start" }).click();
  }

  test("history part 2 hands a file to Alice and records her answer", async ({ page }) => {
    await loadLab(page);
    await startModule(page, "2 · Hand a file over");
    const panel = page.getByTestId("tracked-files");
    await expect(page.getByRole("heading", { name: "Pick the file to hand over" })).toBeVisible();
    await expect(page.getByTestId("active-user-name")).toHaveText("Sarah");
    await panel.getByTestId("tracked-select").selectOption({ label: "budget.txt — /srv/keyquorum/tracked/budget.txt.kqtf" });
    await page.getByRole("button", { name: "Next" }).click();

    await expect(page.getByRole("heading", { name: "Try it: share it with Alice" })).toBeVisible();
    const card = panel.getByTestId("tracked-file");
    // Sharing with someone else does not satisfy this step.
    await card.getByLabel("Share with").selectOption("morgan");
    await card.getByRole("button", { name: "Share file" }).click();
    await expect(page.getByRole("heading", { name: "Try it: share it with Alice" })).toBeVisible();
    await card.getByLabel("Share with").selectOption("alice");
    await card.getByRole("button", { name: "Share file" }).click();

    await expect(page.getByRole("heading", { name: "Try it: become Alice" })).toBeVisible({ timeout: 3_000 });
    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /Alice/ }).click();
    await expect(page.getByRole("heading", { name: "Try it: accept the letter" })).toBeVisible({ timeout: 3_000 });
    await panel.getByTestId("tracked-letters").locator('li[data-status="waiting"]').getByRole("button", { name: "Accept budget.txt" }).click();

    await expect(page.getByRole("heading", { name: "Try it: back to Sarah" })).toBeVisible({ timeout: 3_000 });
    await page.getByRole("group", { name: "Switch user" }).getByRole("button", { name: /Sarah/ }).click();
    await expect(page.getByRole("heading", { name: "Try it: record the answer" })).toBeVisible({ timeout: 3_000 });
    await panel.getByTestId("tracked-letters").getByRole("button", { name: "Record the answer" }).click();

    await expect(page.getByRole("heading", { name: "The hand-off is in the history" })).toBeVisible({ timeout: 3_000 });
    await page.getByRole("button", { name: "Finish" }).click();
    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible();
  });

  test("history part 3 signs a merge and reviews a conflict", async ({ page }) => {
    await loadLab(page);
    await startModule(page, "3 · Merges & conflicts");
    const panel = page.getByTestId("tracked-files");
    await expect(page.getByRole("heading", { name: "A merge that happened on its own" })).toBeVisible();
    await panel.getByTestId("tracked-select").selectOption({ label: "forecast.txt — /srv/keyquorum/tracked/forecast.txt.kqtf" });
    await page.getByRole("button", { name: "Next" }).click();

    await expect(page.getByRole("heading", { name: "Try it: see what the merge changed" })).toBeVisible();
    const card = panel.getByTestId("tracked-file");
    await card.locator("li[data-trust]").last().getByRole("button", { name: /^Diff revision/ }).click();
    await page.getByRole("button", { name: "Close" }).click();

    await expect(page.getByRole("heading", { name: "Try it: sign the merge" })).toBeVisible({ timeout: 3_000 });
    await card.locator('li[data-trust="pending"]').getByRole("button", { name: "Sign revision" }).click();

    await expect(page.getByRole("heading", { name: "Try it: review a conflict" })).toBeVisible({ timeout: 3_000 });
    // Reviewing a file with no fork is not this step: verify forecast.txt instead and stay put.
    await card.getByRole("button", { name: "Verify history" }).click();
    await page.getByRole("button", { name: "Close" }).click();
    await expect(page.getByRole("heading", { name: "Try it: review a conflict" })).toBeVisible();
    await panel.getByTestId("tracked-select").selectOption({ label: "memo.txt — /srv/keyquorum/tracked/memo.txt.kqtf" });
    await panel.getByTestId("tracked-file").getByRole("button", { name: "Review the fork" }).click();
    await expect(page.getByTestId("opened-file")).toContainText("review M.S");
    await page.getByRole("button", { name: "Close" }).click();

    await expect(page.getByRole("heading", { name: "A person decides" })).toBeVisible({ timeout: 3_000 });
    await page.getByRole("button", { name: "Finish" }).click();
    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible();
  });

  test("history part 4 links a gate, records an unlock, and expires the file", async ({ page }) => {
    await loadLab(page);
    await startModule(page, "4 · Gate links & expiry");
    const panel = page.getByTestId("tracked-files");
    await expect(page.getByRole("heading", { name: "Try it: track a file" })).toBeVisible();
    await expect(page.getByTestId("active-user-name")).toHaveText("Alice");
    await panel.getByLabel("New tracked file").fill("gate-notes.txt");
    await panel.getByLabel("First revision").fill("watching the gate");
    await panel.getByRole("button", { name: "Track and sign" }).click();

    await expect(page.getByRole("heading", { name: "Try it: link a gate" })).toBeVisible({ timeout: 3_000 });
    const card = panel.locator('[data-testid="tracked-file"][data-path="/home/alice/tracked/gate-notes.txt.kqtf"]');
    await card.getByLabel("Record unlocks of").selectOption({ label: "architecture.md (quorum)" });
    await card.getByRole("button", { name: "Link gate" }).click();

    await expect(page.getByRole("heading", { name: "Try it: open the linked file" })).toBeVisible({ timeout: 3_000 });
    await page.getByRole("button", { name: /^engineering\b/ }).click();
    await page.locator('[data-testid^="file-row-"]', { hasText: "architecture.md" }).first().dblclick();
    await page.getByRole("button", { name: "Close" }).click();

    await expect(page.getByRole("heading", { name: "Try it: find the unlock in the history" })).toBeVisible({ timeout: 3_000 });
    await page.locator('[data-panel="activity"] details.log > summary').click();
    // A different filter is not this step.
    await page.getByRole("group", { name: "Filter activity" }).getByRole("button", { name: "Sharing" }).click();
    await expect(page.getByRole("heading", { name: "Try it: find the unlock in the history" })).toBeVisible();
    await page.getByRole("group", { name: "Filter activity" }).getByRole("button", { name: "Security" }).click();
    await expect(page.locator('[data-panel="activity"] [data-event="QuorumUnlockAttempted"]').first()).toBeVisible();

    await expect(page.getByRole("heading", { name: "Try it: end the file" })).toBeVisible({ timeout: 3_000 });
    await card.getByRole("button", { name: "Destroy content now" }).click();

    await expect(page.getByRole("heading", { name: "Try it: verify the tombstone" })).toBeVisible({ timeout: 3_000 });
    await card.getByRole("button", { name: "Verify history" }).click();
    await expect(page.getByTestId("opened-file")).toContainText("Tombstone");
    await page.getByRole("button", { name: "Close" }).click();
    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible({ timeout: 3_000 });
  });
});
