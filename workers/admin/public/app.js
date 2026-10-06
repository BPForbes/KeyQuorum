// Everything the page shows is set with textContent, never as HTML.
async function getJson(path) {
  const response = await fetch(path, { headers: { accept: "application/json" }, credentials: "same-origin" });
  let body = null;
  try {
    body = await response.json();
  } catch {
    // not JSON: leave body null
  }
  return { status: response.status, body };
}

async function showWho() {
  const who = document.getElementById("who");
  try {
    const { status, body } = await getJson("/api/whoami");
    if (status === 200 && body?.email) {
      who.textContent = `Signed in as ${body.email}. The Access session ends ${body.expiresAt ?? "when it expires"}.`;
    } else {
      who.textContent = "Cloudflare Access did not identify you.";
    }
  } catch {
    who.textContent = "Could not reach the admin Worker.";
  }
}

async function showRelay() {
  const relay = document.getElementById("relay");
  try {
    const { status } = await getJson("/api/status");
    relay.textContent =
      status === 503 ? "The relay is not connected to this page yet." : `The relay answered with status ${status}.`;
  } catch {
    relay.textContent = "Could not reach the admin Worker.";
  }
}

showWho();
showRelay();
