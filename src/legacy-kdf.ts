// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Legacy pad/clamp password KDF for Envelope 1–2 only.
 * Envelope 3 MUST NOT call this — it uses Argon2id on the raw UTF-8 password.
 */

const KEY_LENGTH = 32;

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
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
