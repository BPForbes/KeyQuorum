import { execSync } from "node:child_process";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The relay serves the console from its own origin at /console/ (see
// src/relay/console.rs), so every asset URL is rooted there.
const base = "/console/";

function sourceCommit(): string {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try {
    return execSync("git rev-parse HEAD", { encoding: "utf8" }).trim();
  } catch {
    return "local";
  }
}

const commit = sourceCommit();
const shortCommit = /^[0-9a-f]{7,40}$/i.test(commit) ? commit.slice(0, 7) : commit;

export default defineConfig({
  base,
  plugins: [react()],
  define: {
    __BUILD_COMMIT__: JSON.stringify(shortCommit),
  },
  build: {
    target: "es2022",
    // The relay embeds dist/ at build time (build.rs) and serves it under a
    // strict Content-Security-Policy with no inline script or style, so
    // nothing may be inlined into index.html.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
