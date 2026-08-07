# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working in this repository.

## Repository

`conceal-wallet-sdk` — the typed TypeScript wallet engine consumed by `conceal-next-wallet` (and other Conceal surfaces). Plain ES module built with `tsup` → `dist/`; its `conceal-lib-js` WASM crypto is bundled. Released as a tarball pinned by downstream apps in their `package.json`.

## Commands

```bash
npm ci                      # install deps (Node 24+)
npm run build               # tsup → dist/
npm run types               # tsc --noEmit
npm run lint                # Biome lint (lint:fix to autofix)
npm run format              # Biome format (format:fix to write)
npm run check               # biome check . (check:fix to autofix)
npm test                    # vitest run
npm run test:watch          # vitest watch
npm run test:coverage       # vitest with coverage
npm run release             # build + types + npm pack (produces the release tarball)
```

Quality gate before completing changes: `npm run types && npm run lint && npm test`.

## Conventions & gotchas

- **Biome only** (no ESLint/Prettier). CI gates on `npm run lint` / `npm run types` (exit non-zero on errors), so run both before pushing.
- **On every `@biomejs/biome` update — follow this workflow in order:**
  1. **Plan** to update the `$schema` URL in `biome.json` to the new version in the same change. Dependabot only bumps `package.json` — it never touches `biome.json`, so this is always a manual follow-up. A stale `$schema` makes Biome emit an `info` diagnostic ("Expected X, Found Y … run `biome migrate`") on every lint run.
  2. **Before editing, check the web for the new schema:** fetch `https://biomejs.dev/schemas/<NEW_VERSION>/schema.json` and confirm it exists (HTTP 200), is valid JSON, and is a JSON Schema document (`$schema` key, non-trivial `properties`). This catches a missing/typo'd release doc and lets you diff structure for breaking changes.
  3. **Consider breaking changes** between old and new schema (removed/renamed properties, changed enums, new required fields). Patch bumps (x.y.Z) are config-compatible; minor (x.Y.0) and especially major (X.0.0) need a real diff. Read the Biome changelog + the schema diff.
  4. **If breaking changes are introduced:** try a PR with the updated `$schema` **and** adapt `biome.json` config keys to the new schema (rename/migrate/remove deprecated fields — run `biome migrate` if available, then hand-verify). Land both the schema URL and the config adaptation in one change.
  5. **If Biome still emits errors after adaptation** (lint/check/types fail on config the new Biome can't reconcile): consider **downgrading `@biomejs/biome` back** to the prior working version and **stop for admin review** — surface the exact errors, the version pair, and the unresolvable config conflict. Do not force a broken upgrade through.
  6. Always run `npm run lint && npm run check` after the schema edit to confirm the diagnostic clears and nothing regressed.
