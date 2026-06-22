// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Encrypted wallet envelope — the documented v1 codec for the stored `"wallet"`
 * blob. Ported byte-for-byte from `conceal-web-wallet`'s `WalletRepository`
 * (encode/decode) so the SDK opens EXISTING stored wallets identically:
 *
 * - Cipher: `secretbox` (XSalsa20-Poly1305) from conceal-lib-js — tweetnacl
 *   compatible (keyLength 32, nonceLength 24).
 * - KDF: the password IS the 32-byte key (no hashing). See
 *   {@link normalizeWalletPassword} for the exact clamp/pad/cyrillic rules.
 * - Nonce: the 24 ASCII bytes of `base64(16 random bytes)` — NOT the decoded
 *   16 bytes. The base64 string (`rawNonce`) is what is stored in the envelope.
 *
 * Two on-disk envelope formats are read (versioned by presence of `data`); only
 * the new `data`/`nonce` format is ever written.
 */
import { secretbox } from "conceal-lib-js";
import type { StorageAdapter } from "./adapters";
import { ccxAddress } from "./crypto";
import { normalizeUserKeys, type UserKeys, userKeysFromEncryptedKeysString } from "./keys";

/** The IndexedDB / localStorage record key for the encrypted wallet blob. */
export const WALLET_STORAGE_KEY = "wallet";

const KEY_LENGTH = 32;

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder("utf8").decode(bytes);
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Standard (RFC 4648) base64 encode — kept inline so the nonce trick has no
 * `nacl.util` dependency. 16 bytes → ceil(16 / 3) * 4 = 24 chars (incl. `=`
 * padding), matching `nacl.util.encodeBase64(nacl.randomBytes(16))`.
 */
function encodeBase64(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = i + 1 < bytes.length ? (bytes[i + 1] ?? 0) : 0;
    const b2 = i + 2 < bytes.length ? (bytes[i + 2] ?? 0) : 0;
    const triplet = (b0 << 16) | (b1 << 8) | b2;
    result += BASE64_ALPHABET[(triplet >> 18) & 0x3f];
    result += BASE64_ALPHABET[(triplet >> 12) & 0x3f];
    result += i + 1 < bytes.length ? BASE64_ALPHABET[(triplet >> 6) & 0x3f] : "=";
    result += i + 2 < bytes.length ? BASE64_ALPHABET[triplet & 0x3f] : "=";
  }
  return result;
}

/**
 * Derive the 32-byte secretbox key from the password — the WHOLE KDF (no
 * hashing). Order is load-bearing for compatibility (`WalletRepository.ts`
 * decode :60-73 / encode :138-148):
 *
 * 1. char-clamp: if `length > 32`, take the first 32 chars;
 * 2. else left-pad with ASCII `'0'` to 32 chars: `("0".repeat(32) + pw).slice(-32)`;
 * 3. UTF-8 encode;
 * 4. cyrillic fix: if the resulting byte length `> 32`, keep the last 32 bytes.
 *
 * Char-clamp first, byte-slice second — a non-latin password can exceed 32
 * bytes after the char clamp.
 */
export function normalizeWalletPassword(password: string): Uint8Array {
  let normalized = password;
  if (normalized.length > KEY_LENGTH) {
    normalized = normalized.slice(0, KEY_LENGTH);
  } else if (normalized.length < KEY_LENGTH) {
    normalized = ("0".repeat(KEY_LENGTH) + normalized).slice(-KEY_LENGTH);
  }

  let key = encodeUtf8(normalized);

  // Fix cyrillic (non-latin) passwords: clamp to the last 32 bytes.
  if (key.length > KEY_LENGTH) {
    key = key.slice(-KEY_LENGTH);
  }

  return key;
}

/** Generate a fresh `rawNonce` = `base64(16 random bytes)` → 24-char string. */
function generateRawNonce(): string {
  const random = new Uint8Array(16);
  globalThis.crypto.getRandomValues(random);
  return encodeBase64(random);
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

/** New ("RawFullyEncryptedWallet") format — written by every save. */
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

/** The two on-disk envelope shapes (versioned by presence of `data`). */
export type EncryptedWalletEnvelope = RawFullyEncryptedWallet | RawInlineEncryptedWallet;

function isNewFormat(envelope: EncryptedWalletEnvelope): envelope is RawFullyEncryptedWallet {
  return typeof (envelope as RawFullyEncryptedWallet).data !== "undefined";
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

/** Options for {@link openEncryptedWallet}. */
export interface OpenWalletOptions {
  /** CCX address prefix to enforce (defaults to lib-js `address.ADDRESS_PREFIX`). */
  expectedAddressPrefix?: number;
}

/**
 * Pure codec: decrypt an envelope to its {@link RawWalletV1} plaintext + the
 * canonical {@link UserKeys}. Returns `null` on a wrong password
 * (`secretbox.open === null`), unparseable JSON, unresolvable keys, or a
 * wrong-network prefix.
 */
export function openEncryptedWallet(
  envelope: EncryptedWalletEnvelope,
  password: string,
  opts?: OpenWalletOptions,
): { raw: RawWalletV1; keys: UserKeys } | null {
  const key = normalizeWalletPassword(password);

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

  if (isNewFormat(envelope)) {
    // New format: the whole blob is the secretbox ciphertext.
    const plain = decrypt(envelope.data, envelope.nonce);
    if (plain === null) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(decodeUtf8(plain));
    } catch {
      return null;
    }
    // Authenticated-but-not-an-object plaintext (e.g. literal `null`/array) must
    // not reach resolveKeys (would dereference a non-object) — reject it.
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    raw = parsed as RawWalletV1;
  } else {
    // Old inline format: only `encryptedKeys` is encrypted; the rest is plaintext.
    const plain = decrypt(envelope.encryptedKeys, envelope.nonce);
    if (plain === null) return null;
    // Inner `nonce` is always "" in the plaintext blob (the real nonce lives only
    // in the envelope); reset it so a later re-save doesn't persist the envelope nonce.
    raw = { ...envelope, encryptedKeys: decodeUtf8(plain), nonce: "" };
  }

  const keys = resolveKeys(raw);
  if (keys === null) return null;

  // A MISSING coinAddressPrefix defaults to the expected one (legacy
  // `Wallet.loadFromRaw` did this before the guard), so older wallets that
  // predate the field still open; only a PRESENT, mismatched prefix is rejected.
  const expectedPrefix = opts?.expectedAddressPrefix ?? ccxAddress.ADDRESS_PREFIX;
  if (raw.coinAddressPrefix !== undefined && raw.coinAddressPrefix !== expectedPrefix) {
    return null;
  }

  return { raw, keys };
}

/**
 * Pure codec: encrypt a {@link RawWalletV1} into a new-format envelope
 * (`{ data, nonce }`). Always writes the new format (encode :137-168).
 */
export function saveEncryptedWallet(raw: RawWalletV1, password: string): RawFullyEncryptedWallet {
  const key = normalizeWalletPassword(password);
  const rawNonce = generateRawNonce();
  const nonce = encodeUtf8(rawNonce);
  const cipher = secretbox(encodeUtf8(JSON.stringify(raw)), nonce, key);
  return {
    data: Array.from(cipher),
    nonce: rawNonce,
  };
}

/**
 * Read + decrypt the stored `"wallet"` record through a {@link StorageAdapter}.
 * Returns `null` when no wallet is stored or decryption fails.
 */
export async function openStoredWallet(
  storage: StorageAdapter,
  password: string,
  opts?: OpenWalletOptions,
): Promise<{ raw: RawWalletV1; keys: UserKeys } | null> {
  const stored = await storage.getItem(WALLET_STORAGE_KEY);
  if (stored === null) return null;
  let envelope: EncryptedWalletEnvelope;
  try {
    envelope = JSON.parse(stored) as EncryptedWalletEnvelope;
  } catch {
    return null;
  }
  return openEncryptedWallet(envelope, password, opts);
}

/** Encrypt + write the `"wallet"` record (always new format) through a {@link StorageAdapter}. */
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
