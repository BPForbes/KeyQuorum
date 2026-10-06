// Health-only stub. It answers GET and HEAD /health and nothing else, so a
// deploy of this Worker exposes no relay behavior, no operator route and no
// mint route. The relay itself arrives with the Durable Object store.

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

function json(status, body, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...extra },
  });
}

export default {
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname === "/health") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json(405, { error: "method not allowed" }, { allow: "GET, HEAD" });
      }
      return json(200, { status: "ok" });
    }
    return json(404, { error: "not found" });
  },
};
