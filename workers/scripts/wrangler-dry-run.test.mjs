import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDryRun } from "./wrangler-dry-run.mjs";

test("validation cannot publish deployment output and leaves the parent preview environment intact", () => {
  const dir = mkdtempSync(join(tmpdir(), "wrangler-check-"));
  try {
    const cli = join(dir, "fixture.cjs");
    const report = join(dir, "report.json");
    const output = join(dir, "deployment.json");
    writeFileSync(cli, `const fs = require('node:fs');
      if (process.env.WRANGLER_OUTPUT_FILE_PATH) fs.writeFileSync(process.env.WRANGLER_OUTPUT_FILE_PATH, 'dry-run');
      fs.writeFileSync(process.env.CHECK_REPORT, JSON.stringify({ args: process.argv.slice(2), directory: process.env.WRANGLER_OUTPUT_FILE_DIRECTORY, branch: process.env.WORKERS_CI_BRANCH }));
      process.exit(Number(process.env.CHECK_EXIT));`);
    const env = { ...process.env, CHECK_REPORT: report, CHECK_EXIT: "7", WORKERS_CI_BRANCH: "test-branch",
      WRANGLER_OUTPUT_FILE_PATH: output, WRANGLER_OUTPUT_FILE_DIRECTORY: dir };
    assert.equal(runDryRun(["--config", "preview/wrangler.json"], { env, cli }), 7);
    assert.deepEqual(JSON.parse(readFileSync(report)), { args: ["deploy", "--dry-run", "--config", "preview/wrangler.json"], branch: "test-branch" });
    assert.equal(existsSync(output), false);
    assert.equal(env.WRANGLER_OUTPUT_FILE_PATH, output);
    assert.equal(env.WRANGLER_OUTPUT_FILE_DIRECTORY, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
