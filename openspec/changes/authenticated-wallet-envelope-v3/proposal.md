## Why

Legacy wallet envelopes (1–2) use password-as-key with pad/clamp KDF and do not authenticate outer KDF metadata. Apps need Argon2id (RFC 9106) memory-hard derivation and authenticated envelope parameters while remaining able to open older Conceal JSON backups forever. This SDK release makes Envelope 3 the only write format and migrates device storage non-destructively after verified round-trip.

## What Changes

- Add **Envelope 3** wire format: `{ envelope: 3, kdf, nonce, data }` with Argon2id + secretbox and authenticated inner `{ envelope, kdf, nonce, wallet }`.
- Change dispatch to detect-then-decrypt (fail closed): `envelope` → env 3 only; else `data` → env 2; else `encryptedKeys` → env 1. No password trial across versions.
- **BREAKING for readers of new files:** `saveEncryptedWallet` / `saveStoredWallet` write only Envelope 3 — SDK **0.2.x cannot open** those files. Bump package to **0.3.0**.
- Additive API: `OpenedWallet = { raw, keys, envelope }`; export `Envelope3`, `migrateToEnvelope3`, `parseEncryptedWalletJson` (32 MiB string gate before parse).
- Non-destructive `openStoredWallet` migration: env 1/2 → 3 only after encrypt→decrypt verify; no rewrite when already v3.
- Typed `crypto.argon2id` facade; docs in `docs/wallet-envelope.md` + README.
- Tests covering legacy open, v3 round-trip, tamper, allowlist, UTF-8 passwords, migration, and gated live Argon2id.

## Capabilities

### New Capabilities
- `wallet-envelope`: Encrypted wallet file/storage codec — open (1/2/3), save (3 only), parse size gates, migrate, and fail-closed auth.

### Modified Capabilities
- (none — no prior envelope capability under `openspec/specs/`)

## Impact

- Code: `src/envelope.ts`, `src/crypto.ts`, `src/index.ts`, `tests/envelope.test.ts`, new `docs/wallet-envelope.md`, `README.md`, `package.json` → `0.3.0`.
- Dependency: already on `conceal-lib-js` 0.3.5 (`crypto.argon2id`, `secretbox`).
- Downstream (follow-up, not this PR): bump SDK in `conceal-next-wallet` and `getnowhere` together; prefer `parseEncryptedWalletJson` for file import (today they `JSON.parse` first).
- Additive field on open result is source-compatible; **on-disk format for new writes is not** readable by 0.2.x.
