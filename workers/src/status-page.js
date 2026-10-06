// The one page the public Worker serves to a browser: whether the relay is up.
// It holds nothing secret and reads nothing but /health and /ready, which any
// caller can read. No inline script or style, no outside origin, no form: the
// content security policy below allows only this origin's two asset files.

export const STATUS_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

export const STATUS_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>KeyQuorum relay</title>
<link rel="stylesheet" href="/assets/status.css">
<script src="/assets/status.js" defer></script>
</head>
<body>
<main>
<h1>KeyQuorum relay</h1>
<p class="lede">This service carries sealed KeyQuorum letters between users. It cannot read them, and there is nothing to sign in to here.</p>
<dl>
<dt>Service</dt><dd id="health" class="checking">checking</dd>
<dt>Store</dt><dd id="ready" class="checking">checking</dd>
</dl>
<p class="note">To use this relay, load the API key you were given with <code>keyquorum loadkey</code>.</p>
</main>
</body>
</html>
`;

export const STATUS_CSS = `:root {
  color-scheme: light dark;
  --bg: #f7f7f5;
  --fg: #1c1d1f;
  --muted: #5d6066;
  --ok: #17692f;
  --bad: #a1261f;
  --rule: #d9d9d4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #131416;
    --fg: #ececea;
    --muted: #a3a6ab;
    --ok: #62c37d;
    --bad: #ef7d76;
    --rule: #34363a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
}
main {
  max-width: 34rem;
  margin: 0 auto;
  padding: 3rem 16px;
}
h1 { margin: 0 0 0.5rem; font-size: 1.5rem; }
.lede, .note { color: var(--muted); }
dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.5rem 1.5rem;
  margin: 1.5rem 0;
  padding: 1rem 0;
  border-block: 1px solid var(--rule);
}
dt { font-weight: 600; }
dd { margin: 0; }
.checking { color: var(--muted); }
.up { color: var(--ok); }
.down { color: var(--bad); }
code { font: 0.9em ui-monospace, SFMono-Regular, Menlo, monospace; }
`;

export const STATUS_JS = `"use strict";
async function check(path) {
  try {
    const response = await fetch(path, { cache: "no-store", redirect: "manual" });
    return response.ok;
  } catch {
    return false;
  }
}
function show(id, ok, up, down) {
  const element = document.getElementById(id);
  element.textContent = ok ? up : down;
  element.className = ok ? "up" : "down";
}
check("/health").then((ok) => show("health", ok, "running", "not answering"));
check("/ready").then((ok) => show("ready", ok, "ready", "not ready"));
`;
