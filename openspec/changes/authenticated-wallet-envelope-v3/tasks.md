## 1. Crypto facade

- [x] 1.1 Add typed `argon2id` wrapper (+ hex encode/decode helpers as needed) on `src/crypto.ts`; export through existing crypto facade patterns
- [x] 1.2 Document that Envelope 3 open/save is memory-hard and SHOULD run off the UI thread (no Worker in this change)

## 2. Envelope 3 codec + dispatch

- [x] 2.1 Implement `parseEncryptedWalletJson` (`MAX_ENVELOPE_JSON_CHARS`), `Envelope3` type, closed-kdf parsers, canonical hex, bytesEqual salt/nonce
- [x] 2.2 Implement fail-closed dispatch in `openEncryptedWallet` (envelope→3, else data→2, else encryptedKeys→1); rename `isNewFormat`→`isEnvelope2`; return `OpenedWallet`
- [x] 2.3 Implement `saveEncryptedWallet` → Envelope 3 only (write profile 32768/3/1; raw 24-byte nonce; authenticated inner plaintext)
- [x] 2.4 Implement `migrateToEnvelope3`; wire `openStoredWallet` non-destructive 1/2→3 migrate; export symbols from `src/index.ts`; bump package to `0.3.0`

## 3. Tests

- [x] 3.1 Keep/adapt legacy env 1 and env 2 open fixtures; update save assertions to env 3; v3 round-trip; wrong password; tamper; env 4; spy that `normalizeWalletPassword` is not called for v3
- [x] 3.2 Param rejects (m too large, salt≠16, p=0, mixed types, closed kdf extras); UTF-8 password; allowlist `(19456,2,1)` fixture; migrate 2→3; oversize string/ciphertext gates
- [x] 3.3 Mock argon2id in unit tests; add live `(32768,3,1)` test gated by `CONCEAL_ARGON2_LIVE`

## 4. Docs

- [x] 4.1 Author `docs/wallet-envelope.md` (RFC 9106, formats, limits, env var, consumer bump notes); short JSDoc `@see` in `envelope.ts`; README note that official backups are env 3 and 0.2.x cannot open them

## 5. Quality gate

- [x] 5.1 Run `npm run types && npm run lint && npm test` green
