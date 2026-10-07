// The relay's two Workers refuse other websites' browsers (the Lab and the
// portfolio are other sites) and carry the headers that stop framing and
// embedding. A command-line client sends none of these request headers.
import test from "node:test";
import assert from "node:assert/strict";
import { ISOLATION_HEADERS, crossSiteRefusal } from "../src/browser-isolation.js";

const URL_OF = "https://relay.test/inbox";
const request = (headers = {}, { method = "GET", url = URL_OF } = {}) =>
  new Request(url, { method, headers });

test("a request with no browser headers is served (keyquorum, curl)", () => {
  assert.equal(crossSiteRefusal(request()), null);
  assert.equal(crossSiteRefusal(request({}, { method: "POST" })), null);
});

test("a typed address, a bookmark and the site's own page are served", () => {
  assert.equal(crossSiteRefusal(request({ "sec-fetch-site": "none" })), null);
  assert.equal(crossSiteRefusal(request({ "sec-fetch-site": "same-origin" })), null);
  assert.equal(
    crossSiteRefusal(request({ origin: "https://relay.test", "sec-fetch-site": "same-origin" })),
    null,
  );
});

test("a fetch, frame, script, image or form from another site is refused", () => {
  for (const site of ["cross-site", "same-site"]) {
    for (const [mode, dest] of [
      ["cors", "empty"],
      ["navigate", "iframe"],
      ["no-cors", "script"],
      ["no-cors", "image"],
    ]) {
      const refusal = crossSiteRefusal(
        request({ "sec-fetch-site": site, "sec-fetch-mode": mode, "sec-fetch-dest": dest }),
      );
      assert.ok(refusal, `${site} ${mode} ${dest}`);
    }
    assert.ok(
      crossSiteRefusal(
        request({ "sec-fetch-site": site, "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" }, { method: "POST" }),
      ),
      `${site} form post`,
    );
  }
});

test("a link from another site is refused too unless the caller allows navigation on that path", () => {
  const link = { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" };
  assert.ok(crossSiteRefusal(request(link)));
  assert.equal(crossSiteRefusal(request(link), { allowNavigation: true }), null);
  // Even then a non-GET navigation, or any subresource, is refused.
  assert.ok(crossSiteRefusal(request(link, { method: "POST" }), { allowNavigation: true }));
  assert.ok(
    crossSiteRefusal(request({ ...link, "sec-fetch-dest": "iframe" }), { allowNavigation: true }),
  );
  assert.ok(
    crossSiteRefusal(request({ ...link, "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" }), {
      allowNavigation: true,
    }),
  );
});

test("a foreign or null Origin is refused, even with no Fetch Metadata", () => {
  for (const origin of [
    "https://bailey-forbes.com",
    "https://keyquorum.github.io",
    "http://relay.test",
    "https://relay.test:8443",
    "https://evil.relay.test",
    "null",
  ]) {
    assert.ok(crossSiteRefusal(request({ origin })), origin);
    assert.ok(crossSiteRefusal(request({ origin }), { allowNavigation: true }), `${origin} (admin)`);
  }
});

test("isolation headers forbid embedding, framing and shared browsing contexts", () => {
  assert.equal(ISOLATION_HEADERS["cross-origin-resource-policy"], "same-origin");
  assert.equal(ISOLATION_HEADERS["x-frame-options"], "DENY");
  assert.equal(ISOLATION_HEADERS["cross-origin-opener-policy"], "same-origin");
  assert.ok(!Object.keys(ISOLATION_HEADERS).some((name) => name.startsWith("access-control-")));
});
