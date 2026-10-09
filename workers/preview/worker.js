// Preview-only composition. Production imports neither this file nor the admin handler.
import { handle as admin } from "../admin/src/index.js";
import { handle as relay } from "../src/worker.js";

export async function handle(request, env, dependencies = {}) {
  // A normal deploy of this configuration is inert. Only previews enable it.
  if (env.CONSOLE_PREVIEW !== "1" || !env.RELAY || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) {
    return new Response("preview not configured", { status: 503 });
  }
  const url = new URL(request.url);
  if (url.pathname === "/") {
    return new Response(null, { status: 307, headers: { location: "/relay/admin/", "cache-control": "no-store" } });
  }
  if (url.pathname === "/relay/admin" || url.pathname.startsWith("/relay/admin/")) {
    return admin(request, {
      ...env,
      MOUNT_PATH: "/relay/admin",
      RELAY_PUBLIC_URL: `${url.origin}/relay`,
      // Same local class/namespace as /relay, never a cross-Worker binding.
      RELAY_ADMIN: env.RELAY,
    }, dependencies);
  }
  return relay(request, { ...env, MOUNT_PATH: "/relay", ALLOWED_HOSTS: url.hostname });
}

export default { fetch: (request, env) => handle(request, env) };
