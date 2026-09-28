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

  test("the move & copy slots module's copy gate ties to the M.S.1 slot", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Move & copy slots" })
      .getByRole("button", { name: "Start" })
      .click();

    await expect(page.getByRole("heading", { name: "Two similar-looking operations" })).toBeVisible();
    await page.getByRole("button", { name: "Next" }).click();

    await expect(page.getByRole("heading", { name: "Try it: move a slot" })).toBeVisible({ timeout: 3_000 });
    await page.getByTestId("move-slot-M.S.1").getByRole("button", { name: "Move" }).click();

    // Step 3 is gated on copying this same slot (M.S.1), by its testid.
    await expect(page.getByRole("heading", { name: "Try it: copy a slot" })).toBeVisible({ timeout: 3_000 });
    const copyForm = page.getByTestId("copy-slot-M.S.1");
    await copyForm.getByPlaceholder("M.S.1's passphrase").fill("lab-demo-M.S.1");
    await copyForm.getByRole("button", { name: "Copy" }).click();
    await expect(page.getByRole("heading", { name: "Try it: inspect custody in Properties" })).toBeVisible({
      timeout: 3_000,
    });
  });

  test("the share-link steps link redeem and revoke to the file and share created in this module", async ({
    page,
  }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Export bundles & share links" })
      .getByRole("button", { name: "Start" })
      .click();

    await expect(page.getByRole("heading", { name: "Try it: create the file you will share" })).toBeVisible();
    await page.getByLabel("File name").fill("shared-note.txt");
    await page.getByLabel("Contents").fill("Shared via a bearer link.");
    await page.getByLabel("Your own lock password").fill("s3cret-pass");
    await page.getByRole("button", { name: "Lock with my password" }).click();

    await expect(page.getByRole("heading", { name: "Try it: create a recipient-bound export" })).toBeVisible({
      timeout: 3_000,
    });
    const passwordFiles = page.getByTestId("password-files");
    await passwordFiles.getByRole("button", { name: "Export…" }).click();
    await passwordFiles.getByPlaceholder("This file's lock password").fill("s3cret-pass");
    await passwordFiles.getByRole("button", { name: "Seal bundle" }).click();

    await expect(page.getByRole("heading", { name: "Try it: view the export bundle" })).toBeVisible({
      timeout: 3_000,
    });
    await page.getByRole("button", { name: "View sealed bytes" }).click();
    await page.getByLabel("Close").click();

    await expect(page.getByRole("heading", { name: "Try it: create a bearer share link" })).toBeVisible({
      timeout: 3_000,
    });
    await passwordFiles.getByRole("button", { name: "Share…" }).click();
    await passwordFiles.getByRole("button", { name: "Create link" }).click();
    const token = (await page.getByTestId("opened-file").innerText()).match(/Token: (\S+)/)?.[1];
    expect(token).toBeTruthy();
    await page.getByLabel("Close").click();

    // Redeeming ties to the file created earlier in this module.
    await expect(page.getByRole("heading", { name: "Try it: redeem the share link" })).toBeVisible({
      timeout: 3_000,
    });
    const shareLinks = page.getByTestId("share-links");
    await shareLinks.getByPlaceholder("Paste the token you were given").fill(token!);
    await shareLinks.getByRole("button", { name: "Redeem" }).click();

    // Revoking ties to the exact share id this module created, not just
    // any share of the same file.
    await expect(page.getByRole("heading", { name: "Try it: revoke the share" })).toBeVisible({ timeout: 3_000 });
    await shareLinks.getByRole("button", { name: "Revoke" }).click();
    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible({ timeout: 3_000 });
  });

  test("the expiry step requires the exact destructive-purge error, not any expiry mention", async ({ page }) => {
    await loadLab(page);
    await page.getByRole("button", { name: "Tutorials & Documentation" }).click();
    await page
      .getByRole("listitem")
      .filter({ hasText: "Signatures, properties & expiry" })
      .getByRole("button", { name: "Start" })
      .click();

    // Skip the earlier gated steps -- this step's gate is independent of them.
    for (const heading of ["Try it: become the signer", "Try it: sign a file", "Try it: verify the signature"]) {
      await expect(page.getByRole("heading", { name: heading })).toBeVisible({ timeout: 3_000 });
      await page.getByRole("button", { name: "Skip this step" }).click();
    }
    await expect(page.getByRole("heading", { name: "Try it: inspect Properties" })).toBeVisible({ timeout: 3_000 });
    await page.getByRole("button", { name: "Skip this step" }).click();

    // vendor-contract-acme.txt is already expired when the lab seeds; the
    // first unlock attempt runs the real destructive purge.
    await expect(page.getByRole("heading", { name: "Try it: observe expiry and purge" })).toBeVisible({
      timeout: 3_000,
    });
    await page.getByRole("button", { name: "accounting" }).click();
    await page.getByTestId("file-row-vendor-contract-acme").dblclick();
    await expect(page.getByRole("heading", { name: "Module complete" })).toBeVisible({ timeout: 3_000 });
  });
});
