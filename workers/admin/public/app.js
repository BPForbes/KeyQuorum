// The provider's console. Everything shown is built as elements and set with
// textContent. The operator lock is typed into a field for one action and is
// never kept: not in a variable, in storage or in the address.
import { errorText, get } from "./api.js";
import { clear, h, notice } from "./ui.js";

// [route, title, loader, in the menu]
const ROUTES = [
  ["overview", "Overview", () => import("./view-overview.js"), true],
  ["users", "Users", () => import("./view-users.js"), true],
  ["user", "User", () => import("./view-user.js"), false],
  ["issue", "Issue keys", () => import("./view-issue.js"), true],
  ["files", "Files", () => import("./view-files.js"), true],
  ["keys", "Keys", () => import("./view-keys.js"), true],
  ["activity", "Activity", () => import("./view-activity.js"), true],
  ["letters", "Letters and trees", () => import("./view-letters.js"), true],
  ["status", "Status", () => import("./view-status.js"), true],
  ["audit", "Audit", () => import("./view-audit.js"), true],
];

const nav = document.getElementById("nav");
const main = document.getElementById("view");
const who = document.getElementById("who");
const config = { relayUrl: "" };
let generation = 0;

function parseHash() {
  const [name, query = ""] = location.hash.replace(/^#/, "").split("?");
  const known = ROUTES.find(([key]) => key === name);
  return { name: known ? name : "overview", params: new URLSearchParams(query) };
}

function drawNav(current) {
  clear(nav);
  // A user's own page is under Users in the menu.
  const shown = current === "user" ? "users" : current;
  for (const [key, label, , inMenu] of ROUTES) {
    if (!inMenu) continue;
    nav.append(h("a", { href: `#${key}`, text: label, "aria-current": key === shown ? "page" : null }));
  }
}

async function render() {
  const { name, params } = parseHash();
  const mine = ++generation;
  drawNav(name);
  main.setAttribute("aria-busy", "true");
  clear(main);
  main.append(h("p", { class: "empty", text: "Loading…" }));
  const [, label, load] = ROUTES.find(([key]) => key === name);
  const ctx = {
    config,
    params,
    refresh: () => render(),
    navigate: (route, query = {}) => {
      const text = new URLSearchParams(query).toString();
      location.hash = text ? `${route}?${text}` : route;
    },
  };
  let content;
  try {
    const module = await load();
    content = await module.default(ctx);
  } catch (error) {
    content = h(
      "div",
      {},
      notice("bad", errorText(error)),
      h("div", { class: "actions" }, h("button", { type: "button", text: "Try again", on: { click: () => render() } })),
    );
  }
  if (mine !== generation) return;
  clear(main);
  main.append(h("h1", { text: label, tabindex: "-1", id: "page-title" }), content);
  main.setAttribute("aria-busy", "false");
  document.title = `${label} – KeyQuorum relay operator`;
}

async function start() {
  try {
    const body = await get("/api/whoami");
    who.textContent = body?.email ? `Signed in as ${body.email}` : "Cloudflare Access did not identify you.";
  } catch {
    who.textContent = "Could not reach the console.";
  }
  try {
    const body = await get("/api/config");
    if (typeof body?.relayUrl === "string") config.relayUrl = body.relayUrl;
  } catch {
    // the form is simply not pre-filled
  }
  window.addEventListener("hashchange", () => {
    render().then(() => document.getElementById("page-title")?.focus());
  });
  await render();
}

start();
