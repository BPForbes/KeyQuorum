import { execSync } from "node:child_process";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves this repository at /KeyQuorum/.
const base = process.env.LAB_BASE ?? "/KeyQuorum/";

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
  plugins: [
    react(),
    {
      name: "keyquorum-build-info",
      generateBundle() {
        this.emitFile({
          type: "asset",
          fileName: "build-info.json",
          source: `${JSON.stringify(
            { schemaVersion: 1, commit, shortCommit, builtAt: new Date().toISOString() },
            null,
            2,
          )}\n`,
        });
      },
    },
  ],
  define: {
    __BUILD_COMMIT__: JSON.stringify(shortCommit),
  },
  build: {
    target: "es2022",
  },
});
