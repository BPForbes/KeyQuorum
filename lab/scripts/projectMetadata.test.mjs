import assert from "node:assert/strict";
import { test } from "node:test";
import { assembleProjectMetadata, languageBreakdown, validateProjectMetadata } from "./projectMetadata.mjs";

const base = () =>
  assembleProjectMetadata({
    repository: { owner: "BPForbes", name: "KeyQuorum", defaultBranch: "main", url: "https://github.com/BPForbes/KeyQuorum" },
    languages: languageBreakdown({ Rust: 900, TypeScript: 90, CSS: 10 }),
    timeline: [
      {
        type: "pull_request",
        number: 2,
        title: "Browser lab",
        mergedAt: "2026-09-26T00:00:00Z",
        url: "https://github.com/BPForbes/KeyQuorum/pull/2",
        author: "BPForbes",
        coAuthors: [],
      },
    ],
    sourceCommit: "2cf8623",
    generatedAt: "2026-09-26T00:00:00Z",
    workflow: "Deploy KeyQuorum Lab",
  });

test("assembles the schemaVersion 1 contract the portfolio consumes", () => {
  const doc = base();
  assert.equal(doc.schemaVersion, 1);
  assert.equal(doc.repository.name, "KeyQuorum");
  assert.deepEqual(
    doc.languages.map((language) => [language.name, language.percentage]),
    [["Rust", 90], ["TypeScript", 9], ["CSS", 1]],
  );
  assert.equal(doc.build.commit, "2cf8623");
});

test("rejects a document with an email address or the wrong schema", () => {
  const doc = base();
  assert.throws(() => validateProjectMetadata({ ...doc, schemaVersion: 2 }));
  const leaked = structuredClone(doc);
  leaked.timeline[0].author = "someone@example.com";
  assert.throws(() => validateProjectMetadata(leaked));
});
