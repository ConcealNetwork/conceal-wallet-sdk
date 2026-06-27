#!/usr/bin/env node
/**
 * Insert Conceal copyright into source files (MIT — matches LICENSE).
 * Usage: node scripts/add-copyright-conceal.mjs <file> [file...]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";

const YEAR = new Date().getFullYear();

const SHORT_HEADER = `// Copyright (c) ${YEAR} Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT`;

const SKIP_DIRS = ["dist/", "node_modules/", "coverage/"];

const SKIP_EXT = new Set([
  ".svg",
  ".png",
  ".ico",
  ".jpg",
  ".jpeg",
  ".webp",
  ".woff",
  ".woff2",
  ".lock",
  ".json",
  ".wasm",
  ".map",
]);

function shouldSkip(path) {
  const rel = relative(process.cwd(), path).replaceAll("\\", "/");
  if (SKIP_DIRS.some((dir) => rel.startsWith(dir) || rel.includes(`/${dir}`))) {
    return `vendor or build path (${rel})`;
  }
  const dot = rel.lastIndexOf(".");
  if (dot === -1) {
    return null;
  }
  const ext = rel.slice(dot);
  if (SKIP_EXT.has(ext)) {
    return `unsupported extension (${ext})`;
  }
  return null;
}

function hasCopyright(text) {
  const head = text.split("\n").slice(0, 30).join("\n");
  return /Copyright/i.test(head) || /SPDX-License-Identifier/i.test(head);
}

function insertHeader(text, header) {
  const lines = text.split("\n");
  let index = 0;

  while (index < lines.length) {
    const line = lines[index].trim();
    if (
      line === "" ||
      line === '"use client";' ||
      line === '"use server";' ||
      line.startsWith("#!") ||
      line === "// @ts-nocheck"
    ) {
      index++;
      continue;
    }
    break;
  }

  const before = lines.slice(0, index);
  const after = lines.slice(index);
  const parts = [...before];

  if (parts.length > 0 && parts[parts.length - 1] !== "") {
    parts.push("");
  }
  parts.push(header);
  if (after.length > 0) {
    parts.push("");
  }
  parts.push(...after);

  return `${parts.join("\n").replace(/\n+$/, "\n")}`;
}

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("Usage: node scripts/add-copyright-conceal.mjs <file> [file...]");
  process.exit(1);
}

let changed = 0;
let skipped = 0;

for (const arg of files) {
  const path = resolve(arg);
  const skipReason = shouldSkip(path);
  if (skipReason) {
    console.log(`skip ${arg}: ${skipReason}`);
    skipped++;
    continue;
  }

  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    console.error(`error ${arg}: ${error.message}`);
    process.exitCode = 1;
    continue;
  }

  if (hasCopyright(text)) {
    console.log(`skip ${arg}: already has copyright`);
    skipped++;
    continue;
  }

  writeFileSync(path, insertHeader(text, SHORT_HEADER), "utf8");
  console.log(`ok   ${arg}`);
  changed++;
}

if (changed === 0 && skipped === files.length) {
  process.exitCode = 1;
}
