// Where a Worker is mounted on its host: the path prefix its routes live under.
// One domain carries several things, each under its own path, and the Worker
// strips its own prefix so what it hands on (the relay core, the console's
// routes and assets) sees the paths it has always had. Pure functions, no I/O.
//
// The prefix is a non-secret variable, `MOUNT_PATH`, set by the deploy job from
// the environment's URL, so staging and production can sit on one hostname:
//   the relay, production      /relay
//   the relay, staging         /relay/staging-user
//   the console, production    /relay/admin  (or a hostname of its own: "")
//   the console, staging       /relay/staging-admin
// The value must match exactly or the Worker is unconfigured and serves
// nothing: a typo can never widen what a Worker answers.

const SEGMENT = "[a-z0-9]+(?:-[a-z0-9]+)*";
const RELAY_MOUNT = new RegExp(`^/relay(?:/(${SEGMENT}))?$`);
const ADMIN_MOUNT = new RegExp(`^(?:/relay/(${SEGMENT}))?$`);

// The first segment of every route the production relay answers at `/relay`
// (policy.js), and its own files. A staging or console mount may not take one
// of these names, or `/relay/<name>` would mean two things at once.
const RESERVED = new Set([
  "inbox", "keycheck", "provider-identity", "audit", "trees", "devices", "health", "ready", "assets",
]);

function valid(pattern, value) {
  const match = typeof value === "string" ? pattern.exec(value) : null;
  return match !== null && !(match[1] !== undefined && RESERVED.has(match[1]));
}

// The relay's mount: `/relay`, or `/relay/<name>` (a name that is not a route
// of the relay); unset or empty is `/relay`.
// -> the mount, or null when the variable is not a valid one.
export function relayMount(value) {
  if (value === undefined || value === null || value === "") return "/relay";
  return valid(RELAY_MOUNT, value) ? value : null;
}

// The console's mount: `/relay/<name>`, or "" for a hostname of its own; unset
// or empty is "". The console is never `/relay` itself, which is the relay's.
export function adminMount(value) {
  if (value === undefined || value === null) return "";
  return valid(ADMIN_MOUNT, value) ? value : null;
}

// The path below the mount, matched on the raw path (so `/relayx`, an encoded
// `/%72elay` and another case are not under it):
//   { path }      "/..." below the mount ("/" for the mount followed by a slash)
//   { redirect }  the mount itself, with no slash: the page's relative links
//                 need the slash, so the caller sends the browser to it
//   null          not under the mount
export function stripMount(pathname, mount) {
  if (mount === "") return { path: pathname };
  if (pathname === mount) return { redirect: `${mount}/` };
  return pathname.startsWith(`${mount}/`) ? { path: pathname.slice(mount.length) } : null;
}

// The mount of a URL as the deploy variables give it (`https://host/relay`,
// `https://host/relay/staging-user`), for the deploy job: null when the URL is
// not an https URL whose path is exactly a valid mount.
export function mountOfUrl(value, parse) {
  let url;
  try {
    url = new URL(String(value).trim());
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.search !== "" || url.hash !== "") return null;
  const path = url.pathname.replace(/\/+$/, "");
  return parse(path);
}
