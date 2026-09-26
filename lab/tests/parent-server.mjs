// Stand-in for bailey-forbes.com in the handshake tests: a page on a
// different origin (port 4174) that embeds the lab and records every
// message it receives. `?src=` picks the iframe URL.
import { createServer } from "node:http";

const port = Number(process.env.PARENT_PORT ?? 4174);

createServer((request, response) => {
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  const src = url.searchParams.get("src") ?? "";
  if (!src.startsWith("http://127.0.0.1:4173/")) {
    response.writeHead(400).end("src must point at the lab preview server");
    return;
  }
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end(`<!doctype html><title>parent</title>
<script>
  window.__messages = [];
  window.addEventListener("message", (event) => {
    const frame = document.querySelector("iframe");
    window.__messages.push({ origin: event.origin, fromFrame: event.source === frame.contentWindow, data: event.data });
  });
</script>
<iframe src="${src.replace(/"/g, "&quot;")}" width="1200" height="800"></iframe>`);
}).listen(port, "127.0.0.1", () => console.log(`parent page on http://127.0.0.1:${port}`));
