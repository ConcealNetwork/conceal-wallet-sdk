# Wallet envelope

Password-protected Conceal wallet blobs for storage and JSON backups. Cipher is
always `secretbox` (XSalsa20-Poly1305) from `conceal-lib-js`. Envelope **3** is
the only write format (planned minor release after review); envelopes **1** and **2** remain
readable forever.

## Formats

Open dispatch is fail-closed and detect-then-decrypt (no password trial across
versions):

1. If `envelope` is present → must be the number `3` (Envelope 3 only).
2. Else if `data` is a number array → Envelope 2.
3. Else if `encryptedKeys` is a number array → Envelope 1.
4. Otherwise → open returns `null`.

### Envelope 1 (legacy)

Inline ciphertext on a `RawWalletV1`-shaped object: `encryptedKeys` is a number
array of secretbox bytes. Password KDF is legacy pad/clamp
(`normalizeWalletPassword`); nonce is the 24 ASCII bytes of
`base64(16 random bytes)` (the base64 string is stored, not the decoded 16
bytes).

### Envelope 2 (legacy)

Whole-blob ciphertext: `{ data: number[], nonce: string }` with the same legacy
KDF and base64-nonce trick. Inner plaintext is a bare `RawWalletV1`.

### Envelope 3 (current write)

Wire shape:

```json
{
  "envelope": 3,
  "kdf": { "alg": "argon2id", "v": 19, "m": 32768, "t": 3, "p": 1, "salt": "<32 hex>" },
  "nonce": "<48 hex>",
  "data": [/* ciphertext bytes 0–255 */]
}
```

- **KDF:** Argon2id ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html))
  on raw UTF-8 password bytes (no pad/clamp). Salt is 16 random bytes,
  lowercase hex; salt is canonicalized (decode → lowercase hex) before the
  primitive. `kdf` is a **closed** object: exactly
  `{ alg, v, m, t, p, salt }` — extra keys → reject.
- **Nonce:** 24 raw random bytes as lowercase hex (not the legacy base64 trick).
- **Authenticated plaintext:** secretbox decrypts to
  `{ envelope: 3, kdf, nonce, wallet }` where outer/inner `kdf` and `nonce`
  must match (type-strict numeric fields; salt/nonce compared as decoded
  bytes). Root-level extras on the outer envelope may be ignored.
- **Profiles:** structural bounds, then allowlist only
  `(m,t,p) ∈ {(19456,2,1), (32768,3,1), (65536,3,1)}`. Writes use
  `(32768,3,1)`.
- **Performance:** Argon2id at the write profile is memory-hard (~32 MiB) and
  blocks the calling thread. Callers SHOULD run open/save off the UI thread
  (Worker or equivalent). This SDK keeps a sync API; no Worker is shipped here.

## Size limits

| Constant | Value | Applies to |
| --- | ---: | --- |
| `MAX_ENVELOPE_JSON_CHARS` | `33_554_432` | JSON text length before `JSON.parse` |
| `MAX_ENVELOPE_CIPHERTEXT_BYTES` | `8_388_608` | Envelope 3 `data.length` on open |

Use `parseEncryptedWalletJson(text)` for file import and storage reads so the
string gate runs **before** parse. Passing an already-parsed object into
`openEncryptedWallet` skips the JSON-size gate (ciphertext gate still
applies for Envelope 3).

## Migration and storage

- `saveEncryptedWallet` / `saveStoredWallet` emit Envelope 3 only.
- `openStoredWallet` opens via `parseEncryptedWalletJson`; on successful
  envelope 1/2 open it builds Envelope 3, verifies by re-opening, then
  replaces storage. Verify failure leaves disk unchanged and returns the
  legacy opened wallet. `setItem` throw after verify keeps the legacy blob and
  still returns the in-memory opened wallet. Already-v3 storage is not
  rewritten on open.
- Envelope 3 rejects passwords whose UTF-8 length exceeds 1024 bytes. Legacy
  pad/clamp still opens with a longer string (only 32 characters feed the key).
  `saveEncryptedWallet` throws `RangeError` there, so explicit save/download
  fails loudly; `migrateToEnvelope3` maps that `RangeError` to `null`, so
  `openStoredWallet` returns the in-memory legacy wallet and leaves storage
  unchanged. A later `saveStoredWallet` with the same oversize password still
  throws until the user sets a password of 1024 UTF-8 bytes or fewer.
- Downloaded/imported JSON files are never mutated by a download path; only
  device storage migrates.

## Public API (envelope)

- `openEncryptedWallet(obj, password)` → `OpenedWallet | null`
  (`{ raw, keys, envelope }` with `envelope` `1` \| `2` \| `3`)
- `parseEncryptedWalletJson(text)` → object or `null`
- `saveEncryptedWallet` / `saveStoredWallet` → Envelope 3
- `migrateToEnvelope3` — encrypt → verify → return `Envelope3 | null` (callers `JSON.stringify` for storage)
- `normalizeWalletPassword` — **legacy envelopes 1–2 only**

## Live Argon2id tests

Unit tests mock `argon2id`. To exercise the real write profile `(32768,3,1)`:

```bash
CONCEAL_ARGON2_LIVE=1 npm test
```

CI leaves `CONCEAL_ARGON2_LIVE` unset so the live block is skipped.

## Consumer bump notes

**Breaking for readers of new files:** builds that still ship the pre–Envelope 3
codec cannot open Envelope 3. When you cut the minor release, bump
`conceal-next-wallet` and `getnowhere` (and any other consumer) **together**
before shipping downloads/saves that write v3.

For file import, prefer `parseEncryptedWalletJson` instead of bare
`JSON.parse` so oversized inputs are rejected before parse. Official Conceal
JSON backups produced by this codec are Envelope 3; older envelope 1/2 files
remain importable.
