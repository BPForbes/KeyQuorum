import { expect, test, type Page } from "@playwright/test";

// The lab runs on http://127.0.0.1:4173; tests/parent-server.mjs serves a
// page on http://127.0.0.1:4174 that embeds it, standing in for
// bailey-forbes.com, and records each message it receives.
const LAB = "http://127.0.0.1:4173/KeyQuorum/";
const PARENT_ORIGIN = "http://127.0.0.1:4174";

async function embed(page: Page, parentOrigin: string) {
  const src = `${LAB}?parentOrigin=${encodeURIComponent(parentOrigin)}`;
  await page.goto(`${PARENT_ORIGIN}/?src=${encodeURIComponent(src)}`);
  await expect(page.frameLocator("iframe").locator("[data-lab-state=ready]")).toBeVisible({ timeout: 30_000 });
}

type Recorded = { origin: string; fromFrame: boolean; data: unknown };
const messages = (page: Page) =>
  page.evaluate(() => (window as unknown as { __messages: Recorded[] }).__messages);

test.skip(({ isMobile }) => isMobile, "handshake is layout independent");

test("posts a strict ready handshake to the named parent origin", async ({ page }) => {
  await embed(page, PARENT_ORIGIN);
  await expect.poll(async () => (await messages(page)).length).toBe(1);
  const [message] = await messages(page);
  expect(message.origin).toBe("http://127.0.0.1:4173");
  expect(message.fromFrame).toBe(true);
  expect(message.data).toEqual({
    source: "keyquorum-guest",
    type: "ready",
    schemaVersion: 1,
    commit: expect.stringMatching(/\S/),
  });
});

test("an unlisted parent origin falls back to bailey-forbes.com, so this parent hears nothing", async ({ page }) => {
  await embed(page, "https://evil.example");
  await page.waitForTimeout(750);
  expect(await messages(page)).toEqual([]);
});
