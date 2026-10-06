// The provider's console. Everything shown is built as elements and set with
// textContent. The operator lock is typed into a field for one action and is
// never kept: not in a variable, in storage or in the address.
import { errorText, getJson } from "./api.js";
import { clear, h, notice } from "./ui.js";

const ROUTES = [
  ["overview", "Overview", () => import("./view-overview.js")],
  ["clients", "Clients and licences", () => import("./view-clients.js")],
  ["issue", "Issue", () => import("./view-issue.js")],
  ["keys", "Keys", () => import("./view-keys.js")],
  ["activity", "Activity", () => import("./view-activity.js")],
  ["letters", "Letters and trees", () => import("./view-letters.js")],
  ["audit", "Audit", () => import("./view-audit.js")],
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
  for (const [key, label] of ROUTES) {
    nav.append(h("a", { href: `#${key}`, text: label, "aria-current": key === current ? "page" : null }));
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
    const { status, body } = await getJson("/api/whoami");
    who.textContent = status === 200 && body?.email ? `Signed in as ${body.email}` : "Cloudflare Access did not identify you.";
  } catch {
    who.textContent = "Could not reach the console.";
  }
  try {
    const { status, body } = await getJson("/api/config");
    if (status === 200 && typeof body?.relayUrl === "string") config.relayUrl = body.relayUrl;
  } catch {
    // the form is simply not pre-filled
  }
  window.addEventListener("hashchange", () => {
    render().then(() => document.getElementById("page-title")?.focus());
  });
  await render();
}

start();
