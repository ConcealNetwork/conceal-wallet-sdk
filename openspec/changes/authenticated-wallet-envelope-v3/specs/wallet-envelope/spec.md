## Purpose

Defines how Conceal wallet SDK encrypts, decrypts, and migrates password-protected wallet envelopes for storage and JSON backup files, including legacy formats and Argon2id Envelope 3.

## ADDED Requirements

### Requirement: Envelope version detection is fail-closed
The system MUST detect envelope version from structure before deriving any key, and MUST NOT try the password against multiple envelope versions. If the `envelope` field is present, it MUST be the number `3`; any other value (including the string `"3"` or number `4`) MUST cause open to return null. When `envelope` is `3`, the system MUST decode as Envelope 3 only and MUST NOT use the legacy pad/clamp password KDF. Absent `envelope`, a `data` field that is a number array MUST be treated as Envelope 2; else an `encryptedKeys` field that is a number array MUST be treated as Envelope 1; otherwise open MUST return null. Mixed shapes that claim Envelope 3 while relying on legacy-only cipher fields for decryption MUST be rejected. Wrong password, corruption, or parameter mismatch MUST return null without throwing and without revealing which version failed.

#### Scenario: Envelope 4 is rejected
- **WHEN** a JSON object with `"envelope": 4` is opened with any password
- **THEN** the result is null

#### Scenario: String envelope 3 is rejected
- **WHEN** a JSON object with `"envelope": "3"` is opened
- **THEN** the result is null

#### Scenario: Envelope 3 never uses pad-KDF
- **WHEN** a valid Envelope 3 object is opened
- **THEN** the legacy pad/clamp password normalizer is not invoked

#### Scenario: Dispatch prefers envelope over data
- **WHEN** an object has both `"envelope": 3` and a `data` number array
- **THEN** it is decoded only as Envelope 3 (not as Envelope 2)

### Requirement: Envelope 3 wire format and authenticated plaintext
Envelope 3 MUST be a JSON object with numeric `envelope` equal to `3`, a closed `kdf` object exactly `{ alg, v, m, t, p, salt }` with no extra keys, a hex `nonce`, and a `data` number array of ciphertext bytes (each 0–255). On write, `kdf.alg` MUST be `"argon2id"`, `kdf.v` MUST be `19`, salt MUST be 16 random bytes hex-encoded lowercase, and nonce MUST be 24 random bytes hex-encoded lowercase. The secretbox plaintext MUST be JSON `{ envelope: 3, kdf, nonce, wallet }` where `kdf` and `nonce` match the outer fields and `wallet` is a `RawWalletV1` object. After decrypt, the system MUST require `envelope === 3`, reject unknown keys inside inner `kdf`, require type-strict equality of `alg`/`v`/`m`/`t`/`p`, and require salt and nonce equality as decoded bytes (canonical lowercase hex for Argon2id input). Extra keys on the envelope root MAY be ignored. Mismatch MUST return null.

#### Scenario: Tampered outer m with correct password fails
- **WHEN** a valid Envelope 3 file has outer `kdf.m` changed after encryption and is opened with the correct password
- **THEN** the result is null

#### Scenario: Closed kdf rejects extra key
- **WHEN** outer or inner `kdf` contains an extra property
- **THEN** open returns null

### Requirement: Argon2id key derivation for Envelope 3
For Envelope 3, the system MUST UTF-8-encode the password, hex-encode those bytes, canonicalize the salt to lowercase hex via decode-then-reencode, and call Argon2id with memory `m`, iterations `t`, and parallelism `p` to produce a 32-byte secretbox key. It MUST NOT clamp, pad, or truncate the password for Envelope 3. Before calling Argon2id, it MUST enforce: password UTF-8 length 0–1024; salt decoded length exactly 16; `8*p ≤ m ≤ 65536`; `1 ≤ t ≤ 64`; `1 ≤ p ≤ 4`; then accept only the allowlisted profiles `(19456,2,1)`, `(32768,3,1)`, and `(65536,3,1)`. Writes MUST use `(32768,3,1)`. The secretbox nonce MUST be the 24 raw nonce bytes. Ciphertext `data.length` MUST be ≤ `8_388_608` or open returns null.

#### Scenario: Default write profile
- **WHEN** a wallet is saved with `saveEncryptedWallet`
- **THEN** the envelope has `envelope === 3`, `kdf.m === 32768`, `kdf.t === 3`, `kdf.p === 1`, and `kdf.alg === "argon2id"`

#### Scenario: Allowlisted read profile 19456/2/1 opens
- **WHEN** a valid Envelope 3 written with `(m,t,p)=(19456,2,1)` is opened with the correct password
- **THEN** the wallet plaintext and keys are recovered

#### Scenario: Non-allowlisted profile rejected
- **WHEN** Envelope 3 claims `(m,t,p)` outside the allowlist (even if Argon2id would accept them)
- **THEN** open returns null without deriving

#### Scenario: UTF-8 password round-trip
- **WHEN** a wallet is saved and opened with a non-ASCII UTF-8 password under Envelope 3
- **THEN** the round-trip succeeds (password is not legacy-clamped)

### Requirement: Legacy envelopes remain readable
The system MUST continue to open Envelope 1 (inline `encryptedKeys` number array ciphertext with legacy pad/clamp KDF and UTF-8 base64 nonce trick) and Envelope 2 (`{ data, nonce }` whole-blob with the same legacy KDF). Legacy inner plaintext remains a bare `RawWalletV1` without the Envelope 3 wrapper. `normalizeWalletPassword` MUST remain exported and documented as legacy envelopes 1–2 only.

#### Scenario: Envelope 1 fixture opens
- **WHEN** a legacy inline encrypted wallet fixture is opened with the correct password
- **THEN** keys and raw wallet fields are recovered

#### Scenario: Envelope 2 fixture opens
- **WHEN** a legacy `{ data, nonce }` fixture is opened with the correct password
- **THEN** keys and raw wallet fields are recovered

### Requirement: Writes and storage migration are Envelope 3 only and non-destructive
`saveEncryptedWallet` and `saveStoredWallet` MUST emit only Envelope 3. Opening a stored wallet MUST parse via a size-gated JSON helper that rejects strings longer than `33_554_432` characters before `JSON.parse`. If open succeeds with envelope 1 or 2, the system MUST build Envelope 3 in memory, verify by opening it with the same password, and only then replace the storage value with the full serialized JSON string. If verify fails, or if Envelope 3 cannot be written because the password UTF-8 length exceeds 1024 bytes, the system MUST return the legacy opened wallet and MUST NOT write (`migrateToEnvelope3` returns `null`; `saveEncryptedWallet` still throws `RangeError` for explicit save). If `setItem` throws after verify, the previous storage value MUST remain and the in-memory opened wallet MUST still be returned. If the stored envelope is already 3, open MUST NOT rewrite it solely because it was opened.

#### Scenario: Successful migrate writes v3
- **WHEN** storage holds Envelope 2 and the password is correct
- **THEN** after open, storage contains Envelope 3 and the returned envelope version is 3

#### Scenario: Failed verify does not overwrite
- **WHEN** migration verify fails after a successful legacy open
- **THEN** storage is unchanged and the legacy opened wallet is returned

#### Scenario: Oversize password skips migrate without throwing on open
- **WHEN** storage holds Envelope 1 or 2, the password opens it, and the password UTF-8 length exceeds 1024 bytes
- **THEN** `openStoredWallet` returns the legacy opened wallet, storage is unchanged, and no exception is thrown

#### Scenario: Already v3 is not rewritten on open
- **WHEN** storage already holds Envelope 3 and open succeeds
- **THEN** storage content is not rewritten during that open

### Requirement: Public open result exposes envelope version
`openEncryptedWallet` and successful `openStoredWallet` MUST return `{ raw, keys, envelope }` where `envelope` is `1`, `2`, or `3`. The system MUST export `parseEncryptedWalletJson`, `migrateToEnvelope3`, and the Envelope 3 type. Open and save APIs MUST remain synchronous.

#### Scenario: Additive envelope field
- **WHEN** any supported envelope is opened successfully
- **THEN** the result includes `envelope` equal to the detected version along with `raw` and `keys`
