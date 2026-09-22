// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Encrypted wallet envelope — the documented codec for the stored `"wallet"`
 * blob. Ported byte-for-byte from `conceal-web-wallet`'s `WalletRepository`
 * (encode/decode) so the SDK opens EXISTING stored wallets identically:
 *
 * - Cipher: `secretbox` (XSalsa20-Poly1305) from conceal-lib-js — tweetnacl
 *   compatible (keyLength 32, nonceLength 24).
 * - Envelope 1–2 KDF: the password IS the 32-byte key (no hashing). See
 *   {@link normalizeWalletPassword} for the exact clamp/pad/cyrillic rules
 *   (legacy only — Envelope 3 uses Argon2id on raw UTF-8).
 * - Envelope 1–2 nonce: the 24 ASCII bytes of `base64(16 random bytes)` — NOT
 *   the decoded 16 bytes. The base64 string (`rawNonce`) is stored.
 * - Envelope 3: Argon2id + raw 24-byte hex nonce; authenticated inner plaintext.
 *
 * Open dispatch (fail-closed): `envelope`→3, else `data[]`→2, else
 * `encryptedKeys[]`→1. Writes emit Envelope 3 only (profile 32768/3/1).
 *
 * @see docs/wallet-envelope.md
 */
import { secretbox } from "conceal-lib-js";
import type { StorageAdapter } from "./adapters";
import { argon2id, canonicalizeHex, ccxAddress, hexDecode, hexEncode } from "./crypto";
import { normalizeUserKeys, type UserKeys, userKeysFromEncryptedKeysString } from "./keys";
import * as legacyKdf from "./legacy-kdf";
import type { Hex } from "./types";

export { normalizeWalletPassword } from "./legacy-kdf";

/** The IndexedDB / localStorage record key for the encrypted wallet blob. */
export const WALLET_STORAGE_KEY = "wallet";

/** Max secretbox ciphertext byte length accepted on Envelope 3 open. */
export const MAX_ENVELOPE_CIPHERTEXT_BYTES = 8_388_608;

/** Max JSON text length accepted by {@link parseEncryptedWalletJson} before parse. */
export const MAX_ENVELOPE_JSON_CHARS = 33_554_432;

/** Max password UTF-8 byte length accepted before Envelope 3 Argon2id. */
const MAX_ENVELOPE3_PASSWORD_BYTES = 1024;

const ENVELOPE3_SALT_BYTES = 16;
const ENVELOPE3_NONCE_BYTES = 24;
const CLOSED_KDF_KEYS = ["alg", "v", "m", "t", "p", "salt"] as const;

/** Allowlisted Argon2id (m,t,p) profiles for Envelope 3 open. */
const ENVELOPE3_ALLOWED_PROFILES = new Set(["19456:2:1", "32768:3:1", "65536:3:1"]);

/** Default write profile for {@link saveEncryptedWallet}. */
const ENVELOPE3_WRITE_M = 32768;
const ENVELOPE3_WRITE_T = 3;
const ENVELOPE3_WRITE_P = 1;
const ENVELOPE3_WRITE_V = 19;

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder("utf8").decode(bytes);
}

/** Fresh lowercase hex of `byteLength` cryptographically random bytes. */
function generateRandomHex(byteLength: number): string {
  const random = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(random);
  return hexEncode(random);
}

/** Per-transaction private key (txid → hex). */
export type RawTxPrivateKeys = { [txid: string]: string };

/** v1 wallet options blob (`WalletOptions.exportToJson`). */
export interface RawWalletOptions {
  readSpeed?: number;
  checkMinerTx?: boolean;
  customNode?: boolean;
  nodeUrl?: string;
}

/** Address-book entry (v3 only). */
export interface RawAddressEntry {
  id: string;
  label: string;
  address: string;
  paymentId?: string;
  avatar?: string;
}

/**
 * The inner v1 plaintext blob (a typed superset). Unknown / future fields are
 * preserved on open → save so round-trips stay lossless (the index signature
 * keeps v3 sub-shapes opaque-but-carried). `nonce` is ALWAYS `""` inside the
 * plaintext blob — the real nonce lives only in the envelope.
 */
export interface RawWalletV1 {
  deposits: unknown[];
  withdrawals: unknown[];
  transactions: unknown[];
  txPrivateKeys?: RawTxPrivateKeys;
  lastHeight: number;
  /** Always `""` inside the decrypted blob; the envelope carries the real nonce. */
  nonce: string;
  /** Canonical key object (new wallets). */
  keys?: UserKeys;
  /**
   * Legacy pre-`keys` field. In the OLD inline envelope it is the secretbox
   * ciphertext (`number[]`); after decrypt it becomes the hex string (128 =
   * priv pair, 192 = view-only export). New wallets omit it.
   */
  encryptedKeys?: string | number[];
  creationHeight?: number;
  options?: RawWalletOptions;
  coinAddressPrefix?: number;
  /** v3 only — saved contacts (omitted when empty). */
  addressBook?: RawAddressEntry[];
  /** v3 only — sender copies of outgoing messages (omitted when empty). */
  sentMessages?: unknown[];
  // Carry any other fields verbatim on round-trip.
  [key: string]: unknown;
}

/** Envelope 2 wire format (`{ data, nonce }` with legacy pad-KDF). */
export interface RawFullyEncryptedWallet {
  /** secretbox ciphertext bytes (each 0–255) as a JSON array. */
  data: number[];
  /** `rawNonce` — the 24-char base64 string. */
  nonce: string;
}

/**
 * Old inline format — the stored object IS a {@link RawWalletV1} whose
 * `encryptedKeys` field is the secretbox ciphertext as a `number[]` (only the
 * keys are encrypted; the rest of the blob is plaintext).
 */
export type RawInlineEncryptedWallet = RawWalletV1 & { encryptedKeys: number[] };

/** On-disk envelope shapes: env 2 (`data`), env 1 (inline), or Envelope 3. */
export type EncryptedWalletEnvelope =
  | RawFullyEncryptedWallet
  | RawInlineEncryptedWallet
  | Envelope3;

/** Envelope 3 closed Argon2id KDF object (wire shape). */
export interface Envelope3Kdf {
  alg: "argon2id";
  v: number;
  m: number;
  t: number;
  p: number;
  salt: string;
}

/** Envelope 3 wire format (`envelope: 3` + closed kdf + hex nonce + ciphertext). */
export interface Envelope3 {
  envelope: 3;
  kdf: Envelope3Kdf;
  nonce: string;
  data: number[];
}

/** Closed-kdf parse result including decoded/canonical salt for Argon2id. */
export interface ParsedClosedArgon2idKdf extends Envelope3Kdf {
  saltBytes: Uint8Array;
  saltCanonicalHex: Hex;
}

/**
 * Size-gated JSON parse for wallet envelope text (file import / storage).
 * Rejects non-strings, oversize strings, invalid JSON, and non-plain objects.
 * Does not decrypt.
 */
export function parseEncryptedWalletJson(text: string): Record<string, unknown> | null {
  if (typeof text !== "string" || text.length > MAX_ENVELOPE_JSON_CHARS) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
}

/**
 * Parse a closed Argon2id KDF object: exactly `{ alg, v, m, t, p, salt }`.
 * Salt must decode to 16 bytes; {@link canonicalizeHex} before Argon2id use.
 */
export function parseClosedArgon2idKdf(value: unknown): ParsedClosedArgon2idKdf | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length !== CLOSED_KDF_KEYS.length) return null;
  for (const key of CLOSED_KDF_KEYS) {
    if (!Object.hasOwn(obj, key)) return null;
  }

  if (obj.alg !== "argon2id") return null;
  if (
    typeof obj.v !== "number" ||
    typeof obj.m !== "number" ||
    typeof obj.t !== "number" ||
    typeof obj.p !== "number"
  ) {
    return null;
  }
  if (typeof obj.salt !== "string") return null;

  let saltBytes: Uint8Array;
  let saltCanonicalHex: Hex;
  try {
    saltBytes = hexDecode(obj.salt);
    if (saltBytes.length !== ENVELOPE3_SALT_BYTES) return null;
    saltCanonicalHex = canonicalizeHex(obj.salt);
  } catch {
    return null;
  }

  return {
    alg: "argon2id",
    v: obj.v,
    m: obj.m,
    t: obj.t,
    p: obj.p,
    salt: obj.salt,
    saltBytes,
    saltCanonicalHex,
  };
}

/** Decode Envelope 3 hex nonce to exactly 24 bytes; null on mismatch. */
export function parseEnvelope3Nonce(nonce: unknown): Uint8Array | null {
  if (typeof nonce !== "string") return null;
  try {
    const bytes = hexDecode(nonce);
    if (bytes.length !== ENVELOPE3_NONCE_BYTES) return null;
    return bytes;
  } catch {
    return null;
  }
}

/** Constant-time-ish byte equality for salt/nonce comparisons after decode. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

function isEnvelope2(obj: Record<string, unknown>): boolean {
  return Array.isArray(obj.data);
}

function isEnvelope1(obj: Record<string, unknown>): boolean {
  return Array.isArray(obj.encryptedKeys);
}

/** True when `data` is a number[] of integer bytes 0–255 within the size gate. */
function isCiphertextByteArray(data: unknown): data is number[] {
  if (!Array.isArray(data)) return false;
  if (data.length > MAX_ENVELOPE_CIPHERTEXT_BYTES) return false;
  for (const b of data) {
    if (typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255) return false;
  }
  return true;
}

function isAllowlistedProfile(m: number, t: number, p: number): boolean {
  return ENVELOPE3_ALLOWED_PROFILES.has(`${m}:${t}:${p}`);
}

/** Structural Argon2id bounds, then the three allowlisted profiles. */
function acceptEnvelope3KdfParams(kdf: ParsedClosedArgon2idKdf): boolean {
  if (kdf.v !== 19) return false;
  const { m, t, p } = kdf;
  if (!(8 * p <= m && m <= 65536)) return false;
  if (!(1 <= t && t <= 64)) return false;
  if (!(1 <= p && p <= 4)) return false;
  return isAllowlistedProfile(m, t, p);
}

function kdfParamsEqual(a: ParsedClosedArgon2idKdf, b: ParsedClosedArgon2idKdf): boolean {
  return (
    a.alg === b.alg &&
    a.v === b.v &&
    a.m === b.m &&
    a.t === b.t &&
    a.p === b.p &&
    bytesEqual(a.saltBytes, b.saltBytes)
  );
}

/** Resolve canonical {@link UserKeys} from a decrypted blob, mirroring the
 *  defense-in-depth ordering of `Wallet.loadFromRaw` + `WalletRepository`. */
function resolveKeys(raw: RawWalletV1): UserKeys | null {
  // Legacy encryptedKeys hex string (pre-`keys`-object wallets) takes priority,
  // matching `Wallet.loadFromRaw` (:249-272).
  if (typeof raw.encryptedKeys === "string" && raw.encryptedKeys !== "") {
    return userKeysFromEncryptedKeysString(raw.encryptedKeys);
  }
  if (typeof raw.keys !== "undefined") {
    return normalizeUserKeys(raw.keys);
  }
  return null;
}

function finalizeOpened(
  raw: RawWalletV1,
  envelope: 1 | 2 | 3,
  opts?: OpenWalletOptions,
): OpenedWallet | null {
  const keys = resolveKeys(raw);
  if (keys === null) return null;

  // A MISSING coinAddressPrefix defaults to the expected one (legacy
  // `Wallet.loadFromRaw` did this before the guard), so older wallets that
  // predate the field still open; only a PRESENT, mismatched prefix is rejected.
  const expectedPrefix = opts?.expectedAddressPrefix ?? ccxAddress.ADDRESS_PREFIX;
  if (raw.coinAddressPrefix !== undefined && raw.coinAddressPrefix !== expectedPrefix) {
    return null;
  }

  return { raw, keys, envelope };
}

/** Options for {@link openEncryptedWallet}. */
export interface OpenWalletOptions {
  /** CCX address prefix to enforce (defaults to lib-js `address.ADDRESS_PREFIX`). */
  expectedAddressPrefix?: number;
}

/** Successful open result — includes detected envelope version. */
export type OpenedWallet = { raw: RawWalletV1; keys: UserKeys; envelope: 1 | 2 | 3 };

function openEnvelope3(
  obj: Record<string, unknown>,
  password: string,
  opts?: OpenWalletOptions,
): OpenedWallet | null {
  const outerKdf = parseClosedArgon2idKdf(obj.kdf);
  if (outerKdf === null || !acceptEnvelope3KdfParams(outerKdf)) return null;

  const nonceBytes = parseEnvelope3Nonce(obj.nonce);
  if (nonceBytes === null) return null;
  if (!isCiphertextByteArray(obj.data)) return null;

  const passwordBytes = encodeUtf8(password);
  if (passwordBytes.length > MAX_ENVELOPE3_PASSWORD_BYTES) return null;

  let key: Uint8Array;
  try {
    const keyHex = argon2id(
      hexEncode(passwordBytes),
      outerKdf.saltCanonicalHex,
      outerKdf.m,
      outerKdf.t,
      outerKdf.p,
    );
    key = hexDecode(keyHex);
    if (key.length !== 32) return null;
  } catch {
    return null;
  }

  let plain: Uint8Array | null;
  try {
    plain = secretbox.open(Uint8Array.from(obj.data), nonceBytes, key);
  } catch {
    return null;
  }
  if (plain === null) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(decodeUtf8(plain));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const inner = parsed as Record<string, unknown>;
  if (inner.envelope !== 3) return null;

  const innerKdf = parseClosedArgon2idKdf(inner.kdf);
  if (innerKdf === null || !kdfParamsEqual(outerKdf, innerKdf)) return null;

  const innerNonce = parseEnvelope3Nonce(inner.nonce);
  if (innerNonce === null || !bytesEqual(nonceBytes, innerNonce)) return null;

  if (typeof inner.wallet !== "object" || inner.wallet === null || Array.isArray(inner.wallet)) {
    return null;
  }

  return finalizeOpened(inner.wallet as RawWalletV1, 3, opts);
}

function openLegacyEnvelope(
  obj: Record<string, unknown>,
  password: string,
  version: 1 | 2,
  opts?: OpenWalletOptions,
): OpenedWallet | null {
  const key = legacyKdf.normalizeWalletPassword(password);

  // Decrypt defensively: a malformed/corrupt envelope (non-array data, bad nonce
  // length — `secretbox.open` THROWS "bad nonce size") must return null, never
  // throw, since envelopes can come from untrusted storage.
  const decrypt = (data: unknown, nonceStr: unknown): Uint8Array | null => {
    if (!Array.isArray(data) || typeof nonceStr !== "string") return null;
    try {
      return secretbox.open(Uint8Array.from(data as number[]), encodeUtf8(nonceStr), key);
    } catch {
      return null;
    }
  };

  let raw: RawWalletV1;

  if (version === 2) {
    const plain = decrypt(obj.data, obj.nonce);
    if (plain === null) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(decodeUtf8(plain));
    } catch {
      return null;
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    raw = parsed as RawWalletV1;
  } else {
    const plain = decrypt(obj.encryptedKeys, obj.nonce);
    if (plain === null) return null;
    raw = { ...(obj as RawWalletV1), encryptedKeys: decodeUtf8(plain), nonce: "" };
  }

  return finalizeOpened(raw, version, opts);
}

/**
 * Pure codec: decrypt an envelope to its {@link RawWalletV1} plaintext + the
 * canonical {@link UserKeys} + detected {@link OpenedWallet.envelope} version.
 * Returns `null` on a wrong password, unparseable JSON, unresolvable keys,
 * wrong-network prefix, or fail-closed dispatch miss — never throws.
 */
export function openEncryptedWallet(
  envelope: EncryptedWalletEnvelope,
  password: string,
  opts?: OpenWalletOptions,
): OpenedWallet | null {
  if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) {
    return null;
  }
  const obj = envelope as Record<string, unknown>;

  // Fail-closed dispatch: envelope field first (even when data[] is also present).
  if ("envelope" in obj) {
    if (obj.envelope !== 3) return null;
    return openEnvelope3(obj, password, opts);
  }
  if (isEnvelope2(obj)) {
    return openLegacyEnvelope(obj, password, 2, opts);
  }
  if (isEnvelope1(obj)) {
    return openLegacyEnvelope(obj, password, 1, opts);
  }
  return null;
}

/**
 * Pure codec: encrypt a {@link RawWalletV1} into Envelope 3
 * (`{ envelope: 3, kdf, nonce, data }`). Write profile is Argon2id
 * `(m,t,p)=(32768,3,1)` with a raw 24-byte hex nonce and authenticated
 * inner plaintext `{ envelope, kdf, nonce, wallet }`.
 *
 * @throws {RangeError} if `password` UTF-8 length exceeds 1024 bytes.
 */
export function saveEncryptedWallet(raw: RawWalletV1, password: string): Envelope3 {
  const passwordBytes = encodeUtf8(password);
  if (passwordBytes.length > MAX_ENVELOPE3_PASSWORD_BYTES) {
    throw new RangeError(`password UTF-8 length exceeds ${MAX_ENVELOPE3_PASSWORD_BYTES} bytes`);
  }

  const saltHex = generateRandomHex(ENVELOPE3_SALT_BYTES);
  const nonceHex = generateRandomHex(ENVELOPE3_NONCE_BYTES);
  const kdf: Envelope3Kdf = {
    alg: "argon2id",
    v: ENVELOPE3_WRITE_V,
    m: ENVELOPE3_WRITE_M,
    t: ENVELOPE3_WRITE_T,
    p: ENVELOPE3_WRITE_P,
    salt: saltHex,
  };

  const keyHex = argon2id(
    hexEncode(passwordBytes),
    canonicalizeHex(saltHex),
    ENVELOPE3_WRITE_M,
    ENVELOPE3_WRITE_T,
    ENVELOPE3_WRITE_P,
  );
  const key = hexDecode(keyHex);
  if (key.length !== 32) {
    throw new Error("argon2id returned unexpected key length");
  }

  const inner = {
    envelope: 3 as const,
    kdf,
    nonce: nonceHex,
    wallet: raw,
  };
  const cipher = secretbox(encodeUtf8(JSON.stringify(inner)), hexDecode(nonceHex), key);

  return {
    envelope: 3,
    kdf,
    nonce: nonceHex,
    data: Array.from(cipher),
  };
}

/**
 * Re-encrypt an opened wallet to Envelope 3 in memory (no storage I/O).
 * `null` on verify fail or oversize password; other save errors throw.
 * @see docs/wallet-envelope.md
 */
export function migrateToEnvelope3(
  opened: OpenedWallet,
  password: string,
  opts?: OpenWalletOptions,
): Envelope3 | null {
  let v3: Envelope3;
  try {
    v3 = saveEncryptedWallet(opened.raw, password);
  } catch (error) {
    if (error instanceof RangeError) return null;
    throw error;
  }
  if (openEncryptedWallet(v3, password, opts) === null) return null;
  return v3;
}

/**
 * Read + decrypt the stored `"wallet"` record through a {@link StorageAdapter}.
 * Legacy 1/2 migrate to Envelope 3 only after verify; a skip writes nothing.
 * @see docs/wallet-envelope.md
 */
export async function openStoredWallet(
  storage: StorageAdapter,
  password: string,
  opts?: OpenWalletOptions,
): Promise<OpenedWallet | null> {
  const stored = await storage.getItem(WALLET_STORAGE_KEY);
  if (stored === null) return null;
  const parsed = parseEncryptedWalletJson(stored);
  if (parsed === null) return null;
  const opened = openEncryptedWallet(parsed as EncryptedWalletEnvelope, password, opts);
  if (opened === null) return null;
  if (opened.envelope === 3) return opened;

  const v3 = migrateToEnvelope3(opened, password, opts);
  if (v3 === null) return opened;

  try {
    await storage.setItem(WALLET_STORAGE_KEY, JSON.stringify(v3));
  } catch {
    return opened;
  }

  // migrateToEnvelope3 already verified open; do not re-derive Argon2id.
  return { raw: opened.raw, keys: opened.keys, envelope: 3 };
}

/** Encrypt + write the `"wallet"` record (always Envelope 3) through a {@link StorageAdapter}. */
export async function saveStoredWallet(
  storage: StorageAdapter,
  raw: RawWalletV1,
  password: string,
): Promise<void> {
  const envelope = saveEncryptedWallet(raw, password);
  await storage.setItem(WALLET_STORAGE_KEY, JSON.stringify(envelope));
}

/** Whether a `"wallet"` record exists (does not decrypt it). */
export async function hasStoredWallet(storage: StorageAdapter): Promise<boolean> {
  return (await storage.getItem(WALLET_STORAGE_KEY)) !== null;
}
