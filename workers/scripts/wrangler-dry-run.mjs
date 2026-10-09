import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Builds consumes Wrangler's structured deployment output for its GitHub bot.
// Validation must not report a dry-run deployment ahead of the real Preview.
export function runDryRun(args, { env = process.env, cli = fileURLToPath(new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url)) } = {}) {
  const validationEnv = { ...env };
  delete validationEnv.WRANGLER_OUTPUT_FILE_PATH;
  delete validationEnv.WRANGLER_OUTPUT_FILE_DIRECTORY;
  const result = spawnSync(process.execPath, [cli, "deploy", "--dry-run", ...args], {
    env: validationEnv, stdio: "inherit",
  });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(runDryRun(process.argv.slice(2)));
}
