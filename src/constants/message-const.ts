// Copyright (c) 2026 Conceal Network
// SPDX-License-Identifier: MIT

/**
 * tx_extra record tags and on-chain encrypted-message size limits.
 */

/** tx_extra record tag — padding (zero-run, no size byte). */
export const TX_EXTRA_TAG_PADDING = 0x00;
/** tx_extra record tag — 32-byte tx public key `R` (no size byte; fixed 32 bytes). */
export const TX_EXTRA_TAG_PUBKEY = 0x01;
/** tx_extra record tag — nonce (has a size byte; sub-tags = plaintext / encrypted payment id). */
export const TX_EXTRA_NONCE = 0x02;
/** tx_extra record tag — merge-mining (has a size byte). */
export const TX_EXTRA_MERGE_MINING_TAG = 0x03;
/** tx_extra record tag — encrypted message (size byte = ciphertext length). */
export const TX_EXTRA_MESSAGE_TAG = 0x04;
/** tx_extra record tag — TTL (size byte = value-varint byte length). */
export const TX_EXTRA_TTL = 0x05;
/** tx_extra record tag — mysterious minergate (has a size byte). */
export const TX_EXTRA_MYSTERIOUS_MINERGATE_TAG = 0xde;

/** Nonce sub-tag (first byte of a `0x02` record's data) — plaintext payment id. */
export const TX_EXTRA_NONCE_PAYMENT_ID = 0x00;
/** Nonce sub-tag (first byte of a `0x02` record's data) — encrypted payment id. */
export const TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID = 0x01;

/** Integrated / encrypted payment id length in bytes (16 hex chars on-chain). */
export const INTEGRATED_PAYMENT_ID_BYTE_SIZE = 8;
/** Magic byte appended when hashing the ECDH derivation to decrypt an encrypted payment id. */
export const ENCRYPTED_PAYMENT_ID_TAIL = 141;

/** Trailing zero bytes in the encrypted-message plaintext frame. */
export const TX_EXTRA_MESSAGE_CHECKSUM_SIZE = 4;
/** Single-byte length-field cap: the encrypted message can be at most 255 bytes. */
export const MAX_CIPHERTEXT_BYTES = 255;
/** Max UTF-8 body bytes (255 ciphertext cap − 4-byte checksum). */
export const MAX_MESSAGE_BODY_BYTES = MAX_CIPHERTEXT_BYTES - TX_EXTRA_MESSAGE_CHECKSUM_SIZE;
