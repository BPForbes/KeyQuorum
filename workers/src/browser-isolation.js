// Keeps the relay's sites out of reach of every other website, the Lab and the
// portfolio included. Both relay Workers (the public one and the admin one) use
// it, and neither ever sends a CORS header, so a browser page on another origin
// cannot read what they answer.
//
// Two layers. First, a request a browser marks as coming from another site is
// refused before anything else runs, from Fetch Metadata (`Sec-Fetch-Site`) and
// the `Origin` header. Second, every response carries headers that stop a
// browser from embedding or framing it. A command-line client sends neither
// request header, so `keyquorum` and `curl` are unaffected; so is a person who
// types the address or opens a bookmark (`Sec-Fetch-Site: none`), and so is the
// site's own page (`same-origin`).
//
// This is not authentication. Who may use the relay is decided by a bearer
// (public Worker) or by Cloudflare Access and its signed token (admin Worker).

// Added to every response.
export const ISOLATION_HEADERS = {
  // A browser will not load this response into another origin's page as an
  // image, script or other no-cors subresource.
  "cross-origin-resource-policy": "same-origin",
  // No page may frame this one (the content security policy says the same for
  // browsers that read it; this is for the ones that do not).
  "x-frame-options": "DENY",
  "cross-origin-opener-policy": "same-origin",
};

// Returns null when the request may be served, or the reason it is refused
// (for the log; never shown to the caller).
//
// `allowNavigation` is for the admin console only. After an operator signs in,
// Cloudflare Access sends the browser back through a redirect that began on
// another site, so the landing request is marked cross-site; refusing it would
// lock the operator out. A top-level page load (`navigate` to a `document`) is
// therefore let through to the Worker's own checks, which still require a valid
// Access token. A fetch, a script, an image, a frame or a form post from another
// site is refused either way.
export function crossSiteRefusal(request, { allowNavigation = false } = {}) {
  const origin = request.headers.get("origin");
  if (origin !== null) {
    let own;
    try {
      own = new URL(request.url).origin;
    } catch {
      return "a request URL that does not parse";
    }
    // `Origin: null` is what a sandboxed frame or a data: page sends.
    if (origin !== own) return "an Origin that is not this site";
  }

  const site = request.headers.get("sec-fetch-site");
  if (site === "cross-site" || site === "same-site") {
    const navigation =
      request.headers.get("sec-fetch-mode") === "navigate" &&
      request.headers.get("sec-fetch-dest") === "document" &&
      (request.method === "GET" || request.method === "HEAD");
    if (!(allowNavigation && navigation)) return `a ${site} browser request`;
  }
  return null;
}
