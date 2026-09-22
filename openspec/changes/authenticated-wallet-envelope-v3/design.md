## Context

See proposal.md — Why. Today `src/envelope.ts` writes Envelope 2 (`{ data, nonce }`) with `normalizeWalletPassword` + UTF-8(base64-16) nonce trick, and opens env 1 (inline) or 2. Inner plaintext is `RawWalletV1` (unrelated to envelope version). `conceal-lib-js` 0.3.5 already exposes sync `crypto.argon2id` and `secretbox`.

## Goals / Non-Goals

**Goals:**
- Envelope 3 as sole write path; fail-closed detect-then-decrypt; authenticated KDF metadata; non-destructive storage migrate; additive public API; docs + tests.

**Non-Goals:**
- Password strength policy; biometric/keystore; Workers; changing secretbox for env 1–2; editing next-wallet/getnowhere sources; cn_gpu/bcrypt.

## Decisions

1. **Approach A** — Keep codec in `envelope.ts`; add typed `argon2id` (+ hex helpers) on `crypto.ts` facade. Alternative rejected: split modules (review surface) / async Worker API (app rewrite).

2. **Dispatch order** — `envelope` field first (even though v3 also has `data`), then env 2 `data`, then env 1 `encryptedKeys`. Load-bearing.

3. **Canonical hex for Argon2id** — Decode salt hex → bytes → lowercase hex before `argon2id`. Compare inner/outer salt and nonce via bytesEqual after decode. Never pass mixed-case wire salt into the primitive.

4. **Size gates** — `parseEncryptedWalletJson(text)` rejects `text.length > 33_554_432` before `JSON.parse`. After open path, reject `data.length > 8_388_608`. `openEncryptedWallet` takes an object only.

5. **Closed kdf** — Exactly `{ alg, v, m, t, p, salt }`. Extra keys inside kdf → null. Root-level extras ignored. `envelope` / `v` / `m` / `t` / `p` MUST be numbers (`3 !== "3"`).

6. **Profile policy** — Structural bounds then allowlist `(19456,2,1)|(32768,3,1)|(65536,3,1)`; write `(32768,3,1)`.

7. **Migration** — `migrateToEnvelope3` encrypt→open verify→return JSON; `openStoredWallet` setItem only after verify; setItem throw keeps legacy disk + returns in-memory opened; v3 open does not rewrite.

8. **Version** — `0.3.0` because new writes are unreadable by 0.2.x (not only because of additive field).

## Risks / Trade-offs

- [Risk] Argon2id `(32768,3,1)` blocks UI thread → Mitigation: document off-thread later; keep sync now; no Worker in this change.
- [Risk] Wrong allowlist rejects a future profile → Mitigation: explicit three-profile list; bump requires SDK change.
- [Risk] Apps still JSON.parse before size gate → Mitigation: export `parseEncryptedWalletJson`; document follow-up.
- [Risk] Migration setItem fails after verify → Mitigation: return opened wallet; legacy blob remains.
- [Risk] Pad-KDF fallback on v3 → Mitigation: tests spy that `normalizeWalletPassword` is not called when `envelope===3`.

## Migration Plan

1. Ship SDK 0.3.0 with env 3 writes + legacy read + storage migrate.
2. Bump both apps together; point file-import at `parseEncryptedWalletJson`.
3. User downloads become v3 automatically; original imported JSON files are never mutated by download.

## Open Questions

None.
