#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateProjectMetadata, validateProjectMetadata } from './projectMetadata.mjs';

const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const defaultOutput = resolve(repositoryRoot, 'public', 'project-metadata.json');

const parseArgs = (argv) => {
  const validateIndex = argv.indexOf('--validate');
  if (validateIndex >= 0) {
    return {
      mode: 'validate',
      path: resolve(argv[validateIndex + 1] || resolve(repositoryRoot, 'dist', 'project-metadata.json')),
    };
  }
  const outputIndex = argv.indexOf('--output');
  return {
    mode: 'generate',
    path: resolve(outputIndex >= 0 ? argv[outputIndex + 1] : (process.env.METADATA_OUTPUT || defaultOutput)),
  };
};

const readJsonFile = (path) => {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to parse ${path} as JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  return parsed;
};

const args = parseArgs(process.argv.slice(2));

if (args.mode === 'validate') {
  const metadata = readJsonFile(args.path);
  validateProjectMetadata(metadata);
  if (process.env.GITHUB_SHA && metadata.sourceCommit !== process.env.GITHUB_SHA) {
    throw new Error(`sourceCommit ${metadata.sourceCommit} does not match GITHUB_SHA ${process.env.GITHUB_SHA}.`);
  }
  console.log(`Validated ${args.path} (schemaVersion ${metadata.schemaVersion}).`);
} else {
  const metadata = await generateProjectMetadata({
    token: process.env.GITHUB_TOKEN,
    repository: process.env.GITHUB_REPOSITORY,
    sourceCommit: process.env.GITHUB_SHA,
    workflow: process.env.GITHUB_WORKFLOW || 'Deploy KeyQuorum Lab',
  });
  mkdirSync(dirname(args.path), { recursive: true });
  writeFileSync(args.path, `${JSON.stringify(metadata, null, 2)}\n`);
  console.log(`Wrote ${args.path} for ${metadata.repository.owner}/${metadata.repository.name}@${metadata.sourceCommit.slice(0, 7)}.`);
}
