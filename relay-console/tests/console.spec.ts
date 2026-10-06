import { expect, test, type Page } from "@playwright/test";

// The console runs at http://127.0.0.1:4175/console/ on tests/mock-relay.mjs.
// The two bearers come from the environment playwright.config.ts set.
const ADMIN_KEY = process.env.CONSOLE_TEST_ADMIN_KEY ?? "";
const PULL_KEY = process.env.CONSOLE_TEST_PULL_KEY ?? "";

async function loadConsole(page: Page) {
  await page.goto("./");
  await expect(page.locator("[data-console-state=ready]")).toBeVisible({ timeout: 30_000 });
}

async function signIn(page: Page, key: string) {
  await page.getByTestId("signin-key").fill(key);
  await page.getByRole("button", { name: "Sign in" }).click();
}

const status = (page: Page) => page.locator(".console-status");

// Every test starts from the mock's seeded keys and events.
test.beforeEach(async ({ request }) => {
  await request.post("http://127.0.0.1:4175/__test/reset");
});

test.describe("desktop console", () => {
  test.skip(({ isMobile }) => isMobile, "desktop layout");

  test("shows the relay's status without a key, and digests the presented certificate", async ({ page }) => {
    await loadConsole(page);
    await expect(page.getByTestId("status-health")).toContainText("ok");
    await expect(page.getByTestId("status-ready")).toContainText("sqlite");
    await expect(page.getByTestId("status-identity")).toContainText("certificate presented");
    await expect(page.getByTestId("status-identity")).toContainText(/SHA-256 [0-9a-f]{64}/);
    // Nothing is listed before a key is given.
    await expect(page.locator("[data-panel=keys]")).toContainText("Sign in with an admin key");
    await expect(page.locator("[data-panel=audit]")).toContainText("Sign in to read the audit trail");
  });

  test("an unknown key is refused and nothing is kept", async ({ page }) => {
    await loadConsole(page);
    await signIn(page, "kq_not_a_key_the_mock_knows");
    await expect(status(page)).toContainText("does not accept that key");
    await expect(page.getByTestId("signin-key")).toHaveValue("");
    await expect(page.locator("[data-panel=keys]")).toContainText("Sign in with an admin key");
  });

  test("an admin key lists keys, revokes one, and the audit trail records it", async ({ page }) => {
    await loadConsole(page);
    await signIn(page, ADMIN_KEY);
    await expect(page.getByTestId("session-scope")).toHaveText("admin");
    await expect(page.getByTestId("session-id")).toHaveText("key #1");

    const push = page.getByTestId("api-key-3");
    await expect(push).toContainText("inbox.push");
    await expect(push).toHaveAttribute("data-state", "live");
    // Revoked keys are hidden until asked for.
    await expect(page.getByTestId("api-key-4")).toHaveCount(0);
    await page.getByLabel("Show revoked keys").check();
    await expect(page.getByTestId("api-key-4")).toHaveAttribute("data-state", "revoked");

    await page.getByTestId("revoke-3").click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("Revoke key #3?");
    await expect(dialog).toContainText("no undo");
    await page.getByTestId("revoke-confirm").click();
    await expect(status(page)).toHaveText("Key #3 revoked");
    await expect(page.getByTestId("api-key-3")).toHaveAttribute("data-state", "revoked");

    const events = page.locator("[data-panel=audit] [data-testid=audit-event]");
    await page.getByTestId("audit-refresh").click();
    await expect(events.first()).toContainText("revoked");
    await expect(events.first()).toContainText("admin:1");
    await expect(events).toHaveCount(5);

    // The Activity panel records the requests by path and status, never a header.
    const activity = page.locator("[data-testid=activity-entry]");
    await expect(activity.first()).toContainText("GET /audit/api-keys");
    await expect(page.locator("[data-panel=activity]")).not.toContainText(ADMIN_KEY);
    await expect(page.locator("[data-panel=activity]")).toContainText("POST /api-keys/3/revoke");
    await expect(page.locator("[data-panel=activity]")).toContainText("HTTP 204");
  });

  test("the bearer is held in memory only: nothing lands in storage, and sign-out clears it", async ({ page }) => {
    await loadConsole(page);
    await signIn(page, ADMIN_KEY);
    await expect(page.getByTestId("session-scope")).toHaveText("admin");
    const stored = await page.evaluate(() => {
      const values: string[] = [];
      for (let i = 0; i < localStorage.length; i += 1) values.push(localStorage.getItem(localStorage.key(i) ?? "") ?? "");
      for (let i = 0; i < sessionStorage.length; i += 1) values.push(sessionStorage.getItem(sessionStorage.key(i) ?? "") ?? "");
      return { values, cookies: document.cookie, href: window.location.href };
    });
    expect(stored.values.join("\n")).not.toContain(ADMIN_KEY);
    expect(stored.cookies).toBe("");
    expect(stored.href).not.toContain(ADMIN_KEY);

    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.locator("[data-panel=keys]")).toContainText("Sign in with an admin key");
    await expect(status(page)).toContainText("Signed out");
  });

  test("a pull key sees only its own events, its tree slice, and is refused the key list", async ({ page }) => {
    await loadConsole(page);
    await signIn(page, PULL_KEY);
    await expect(page.getByTestId("session-scope")).toHaveText("inbox.pull");
    await expect(page.locator("[data-panel=keys]")).toContainText("needs admin");
    const events = page.locator("[data-panel=audit] [data-testid=audit-event]");
    await expect(events).toHaveCount(1);
    await expect(events.first()).toContainText("#2");

    await page.getByTestId("tree-label").fill("M.S");
    await page.getByRole("button", { name: "Fetch slice" }).click();
    await expect(page.getByTestId("tree-view")).toContainText("generation 3");
    await expect(page.getByTestId("tree-node-M.S")).toContainText("split · 2 of 2");
    await expect(page.getByTestId("tree-node-M.S.1")).toContainText("leaf");

    await page.getByTestId("tree-label").fill("nope");
    await page.getByRole("button", { name: "Fetch slice" }).click();
    await expect(status(page)).toContainText("tree not found");

    // The device directory needs a device key; the relay says 403 and the console shows why.
    await expect(page.locator("[data-panel=devices]")).toContainText("needs device.pull or device.push");
  });

  test("a key hash can be checked without signing in", async ({ page }) => {
    await loadConsole(page);
    await page.getByTestId("check-hash").fill("3".repeat(64));
    await page.getByRole("button", { name: "Check", exact: true }).click();
    await expect(page.getByTestId("check-result")).toContainText("yes");
    await expect(page.getByTestId("check-result")).toContainText("inbox.push");
    await page.getByTestId("check-hash").fill("4".repeat(64));
    await page.getByRole("button", { name: "Check", exact: true }).click();
    await expect(page.getByTestId("check-result")).toContainText("no");
    // A bearer-shaped value is not a hash and is never sent.
    await page.getByTestId("check-hash").fill("kq_this_is_not_a_hash");
    await expect(page.getByRole("button", { name: "Check", exact: true })).toBeDisabled();
  });

  test("a key the relay stops accepting signs the tab out", async ({ page }) => {
    await loadConsole(page);
    await signIn(page, ADMIN_KEY);
    await expect(page.getByTestId("session-scope")).toHaveText("admin");
    // Revoking this tab's own key: the next request is a 401.
    await page.getByTestId("revoke-1").click();
    await expect(page.getByRole("dialog")).toContainText("Revoking it signs you out");
    await page.getByTestId("revoke-confirm").click();
    await expect(status(page)).toContainText("no longer accepts this key");
    await expect(page.locator("[data-panel=keys]")).toContainText("Sign in with an admin key");
  });
});
