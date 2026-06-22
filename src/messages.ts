// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

import { MAX_MESSAGE_BODY_BYTES, TX_EXTRA_MESSAGE_CHECKSUM_SIZE } from "./constants/message-const";
/**
 * Conceal transaction-message encryption + the "smart message" protocol, ported
 * from `conceal-web-wallet` (`Cn` encrypt path / `TransactionsExplorer.decryptMessage`)
 * and the wallet's `smart-message` convention. Kept byte-compatible with messages
 * already on-chain so this SDK interops with every Conceal wallet.
 *
 * Shared key is an ECDH derivation of the two parties' SPEND keys (sender uses the
 * recipient's spend pub + a tx secret; recipient uses the tx pub + their spend
 * secret), hashed with two magic bytes into a 32-byte ChaCha key. Ordinary chat
 * rides ChaCha8; recognised smart messages ride ChaCha12. Both ciphers are streams
 * (encrypt === decrypt). A 4-byte zero checksum frames the plaintext.
 */
import { ccxCrypto, cnutils, cypher } from "./crypto";
import type { Hex } from "./types";

/** Magic bytes appended to the ECDH derivation before hashing into the ChaCha key. */
const KEY_MAGIC_1 = "80";
const KEY_MAGIC_2 = "00";
/** Nonce width in bytes (big-endian message index). */
const NONCE_SIZE = 12;

const PREFIX = "{";
const SUFFIX = "}";

/**
 * Ecosystem smart-message modules (conceal-2fa) + this wallet's `status`. Only a
 * brace token whose first part is one of these is treated as an *actionable*
 * command — encoded over ChaCha12 on send and rendered as a command on receive.
 */
export const KNOWN_MODULES: readonly string[] = [
  "2FA",
  "vault",
  "to-do",
  "medical",
  "trust",
  "contact",
  "agent",
  "status",
];
const KNOWN_MODULE_SET = new Set(KNOWN_MODULES);

/**
 * Action shorthands mirrored from conceal-2fa (`smart-message.ts:14-25`) so smart
 * messages this SDK encodes are byte-identical to those produced by conceal-2fa
 * peers. {@link encodeSmartMessage} maps a verbose action to its shorthand;
 * {@link parseSmartMessage} reads either form (the shorthand is what lands on-chain,
 * so consumers compare against the shorthand).
 */
export const ACTION_MAP: Readonly<Record<string, string>> = {
  create: "c",
  update: "u",
  delete: "d",
  complete: "x",
  authorize: "a",
  execute: "e",
  register: "r",
  verify: "v",
  revoke: "k",
};

/**
 * Derive the 32-byte ChaCha message key shared by two parties.
 *
 * `derivation = generate_key_derivation(otherPublicKey, mySecretSpendKey)`;
 * `key = cn_fast_hash(derivation + "80" + "00")`. Uses the SPEND secret (not view),
 * matching the legacy on-chain protocol. ECDH-symmetric: the sender's
 * `(recipientSpendPub, txSecret)` and the recipient's `(txPub, recipientSpendSecret)`
 * yield the same key.
 */
export function deriveMessageKey(otherPublicKey: Hex, mySecretSpendKey: Hex): Hex {
  const derivation = ccxCrypto.generate_key_derivation(otherPublicKey, mySecretSpendKey) as Hex;
  return ccxCrypto.cn_fast_hash(`${derivation}${KEY_MAGIC_1}${KEY_MAGIC_2}`) as Hex;
}

/** 12-byte big-endian nonce for a message `index` (a CCX message tx → index 0 → all zero). */
function buildNonce(index: number): Uint8Array {
  const nonce = new Uint8Array(NONCE_SIZE);
  for (let i = 0; i < NONCE_SIZE; i++) {
    nonce[NONCE_SIZE - 1 - i] = Math.floor(index / 0x100 ** i) & 0xff;
  }
  return nonce;
}

/** True when the trailing {@link TX_EXTRA_MESSAGE_CHECKSUM_SIZE} bytes are all zero. */
function checksumOk(buf: Uint8Array): boolean {
  if (buf.length < TX_EXTRA_MESSAGE_CHECKSUM_SIZE) return false;
  for (let i = 0; i < TX_EXTRA_MESSAGE_CHECKSUM_SIZE; i++) {
    if (buf[buf.length - TX_EXTRA_MESSAGE_CHECKSUM_SIZE + i] !== 0) return false;
  }
  return true;
}

/** UTF-8(body) + 4 zero checksum bytes — the plaintext frame that gets encrypted. */
function frameBody(body: string): Uint8Array {
  const raw = new TextEncoder().encode(body);
  const framed = new Uint8Array(raw.length + TX_EXTRA_MESSAGE_CHECKSUM_SIZE);
  framed.set(raw);
  return framed;
}

/**
 * Encrypt a message body to hex. Recognised smart messages ride ChaCha12, ordinary
 * chat rides ChaCha8. Throws when the UTF-8 body exceeds 251 bytes (the on-chain
 * single-byte length budget once the 4-byte checksum is added).
 */
export function encryptMessage(body: string, keyHex: Hex, index = 0): Hex {
  const bodyBytes = new TextEncoder().encode(body).length;
  if (bodyBytes > MAX_MESSAGE_BODY_BYTES) {
    throw new Error(
      `Message body too long: ${bodyBytes} UTF-8 bytes (max ${MAX_MESSAGE_BODY_BYTES}).`,
    );
  }

  const keyBuf = cnutils.hextobin(keyHex);
  const nonce = buildNonce(index);
  const framed = frameBody(body);
  const cipher = isKnownSmartMessage(body) ? cypher.chacha12 : cypher.chacha8;
  const encrypted: Uint8Array = cipher(keyBuf, nonce, framed);
  return cnutils.bintohex(encrypted) as Hex;
}

/**
 * Decrypt a hex ciphertext back to its plaintext body, or `null` if it doesn't
 * decrypt cleanly under {@link keyHex}.
 *
 * Tries ChaCha12 first (accepted only when the checksum is valid AND the plaintext
 * is structurally a smart message — broad enough for modules we don't recognise),
 * then falls back to ChaCha8 (accepted on a valid checksum). A wrong key or a
 * chat message decrypted under the wrong cipher fails the checksum → `null`.
 */
export function decryptMessage(ciphertextHex: Hex, keyHex: Hex, index = 0): string | null {
  const cipherBytes = ciphertextHex.length / 2;
  if (cipherBytes < TX_EXTRA_MESSAGE_CHECKSUM_SIZE) return null;

  const keyBuf = cnutils.hextobin(keyHex);
  const nonce = buildNonce(index);
  const raw = cnutils.hextobin(ciphertextHex);

  // Smart-message path: ChaCha12. Accept only when checksum holds AND the decoded
  // plaintext is a brace token — otherwise a chat message would be mis-accepted.
  try {
    const c12: Uint8Array = cypher.chacha12(keyBuf, nonce, raw);
    if (checksumOk(c12)) {
      const candidate = new TextDecoder().decode(c12).slice(0, -TX_EXTRA_MESSAGE_CHECKSUM_SIZE);
      if (isSmartMessage(candidate)) return candidate;
    }
  } catch {
    // ChaCha12 unavailable / threw → fall through to ChaCha8.
  }

  // Ordinary chat: ChaCha8. Accept on a valid checksum (decrypt === encrypt).
  const c8: Uint8Array = cypher.chacha8(keyBuf, nonce, raw);
  if (!checksumOk(c8)) return null;
  return new TextDecoder().decode(c8).slice(0, -TX_EXTRA_MESSAGE_CHECKSUM_SIZE);
}

/** A body is a smart message when it's a single brace-wrapped token. */
export function isSmartMessage(body: unknown): boolean {
  if (typeof body !== "string") return false;
  const trimmed = body.trim();
  return trimmed.length >= 2 && trimmed.startsWith(PREFIX) && trimmed.endsWith(SUFFIX);
}

/** True only for a brace token whose first part is a {@link KNOWN_MODULES} module. */
export function isKnownSmartMessage(body: unknown): boolean {
  const parts = parseSmartMessage(body);
  return parts !== null && parts.length >= 2 && KNOWN_MODULE_SET.has(parts[0] as string);
}

/**
 * `encodeSmartMessage("vault","update","x")` → `"{vault,u,x}"`. A verbose `action`
 * listed in {@link ACTION_MAP} is shortened to its single-char form on the way out so
 * the encoding is byte-compatible with conceal-2fa peers; unknown actions pass through.
 */
export function encodeSmartMessage(module: string, action: string, ...data: string[]): string {
  const invalid = [module, action, ...data].find(
    (part) => part.includes(",") || part.includes("{") || part.includes("}"),
  );
  if (invalid !== undefined) {
    throw new Error(
      `Smart-message parts cannot contain "," "{" or "}": ${JSON.stringify(invalid)}`,
    );
  }
  const serializedAction = Object.hasOwn(ACTION_MAP, action) ? ACTION_MAP[action] : action;
  return `${PREFIX}${[module, serializedAction, ...data].join(",")}${SUFFIX}`;
}

/** Split a smart message into its trimmed `[module, action, ...data]` parts, or `null`. */
export function parseSmartMessage(body: unknown): string[] | null {
  if (!isSmartMessage(body)) return null;
  const inner = (body as string).trim().slice(1, -1);
  return inner.split(",").map((part) => part.trim());
}

/**
 * Convert a TTL duration in `minutes` to the absolute Unix expiry timestamp
 * (seconds) the on-chain `0x05` TTL record stores — `nowSeconds + minutes*60`.
 * Returns `0` ("no TTL") for `null`/`≤0`, matching the wallet's
 * `messageTtlMinutesToUnix` (`messages/page.tsx:761-764`).
 *
 * `nowSeconds` is injected (defaults to the wall clock at the call boundary) to keep
 * the function pure and deterministically testable.
 */
export function ttlMinutesToUnix(
  minutes: number | null,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): number {
  if (!minutes || minutes <= 0) return 0;
  return nowSeconds + minutes * 60;
}
