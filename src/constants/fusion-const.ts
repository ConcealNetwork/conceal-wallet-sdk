// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Fusion / optimization rules and transaction byte-size model.
 */

import { CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE } from "./blockchain";

/** Minimum inputs in a fusion tx (`Currency.fusionTxMinInputCount`, C++ default 12). */
export const FUSION_TX_MIN_INPUT_COUNT = 12;
/**
 * C++ default max fusion input count (`Currency.fusionTxMaxInputCount`). NOT gated on
 * by the JS path — the size estimate is the effective cap. Exported for parity only.
 */
export const FUSION_TX_MAX_INPUT_COUNT = 100;
/** Min vin/vout ratio for the on-chain fusion-flag heuristic. */
export const FUSION_TX_MIN_IN_OUT_COUNT_RATIO = 4;
/** Maximum outputs a fusion tx may have. */
export const MAX_FUSION_OUTPUTS = 8;
/** Max serialized fusion tx size in bytes (`fusionTxMaxSize` = 100000 * 30 / 100 = 30000). */
export const FUSION_TX_MAX_SIZE = (CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE * 30) / 100;
/** Status gate + per-bucket "ready" count. */
export const OPTIMIZE_OUTPUTS = 100;
/** Default starting fusion threshold, atomic. */
export const OPTIMIZE_THRESHOLD = 900000000;
/** Number of power-of-ten buckets (a u64 has up to 19–20 decimal digits). */
export const NUM_BUCKETS = 20;

// --- transaction byte-size model (Currency.ts:16-30) — internal to fusion sizing ---

/** sizeof(crypto::KeyImage). */
export const KEY_IMAGE_SIZE = 32;
/** sizeof(decltype(KeyOutput::key)). */
export const OUTPUT_KEY_SIZE = 32;
/** sizeof(uint64_t) + 2 for varint. */
export const AMOUNT_SIZE = 10;
/** sizeof(uint8_t) for varint. */
export const GLOBAL_INDEXES_VECTOR_SIZE_SIZE = 1;
/** sizeof(uint32_t) for varint. */
export const GLOBAL_INDEXES_INITIAL_VALUE_SIZE = 4;
/** sizeof(uint32_t) for varint. */
export const GLOBAL_INDEXES_DIFFERENCE_SIZE = 4;
/** sizeof(crypto::Signature). */
export const SIGNATURE_SIZE = 64;
/** sizeof(uint8_t). */
export const EXTRA_TAG_SIZE = 1;
/** sizeof(uint8_t). */
export const INPUT_TAG_SIZE = 1;
/** sizeof(uint8_t). */
export const OUTPUT_TAG_SIZE = 1;
/** sizeof(crypto::PublicKey). */
export const PUBLIC_KEY_SIZE = 32;
/** sizeof(uint8_t). */
export const TRANSACTION_VERSION_SIZE = 1;
/** sizeof(uint64_t). */
export const TRANSACTION_UNLOCK_TIME_SIZE = 8;

/**
 * The "pretty" denomination ladder — every `{1..9} × 10^k` value, copied VERBATIM from
 * the legacy `config.PRETTY_AMOUNTS`. Fusion only consolidates outputs whose amount is an
 * exact member of this ladder.
 */
export const PRETTY_AMOUNTS: readonly number[] = [
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700,
  800, 900, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 20000, 30000, 40000, 50000,
  60000, 70000, 80000, 90000, 100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000,
  900000, 1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000, 9000000, 10000000,
  20000000, 30000000, 40000000, 50000000, 60000000, 70000000, 80000000, 90000000, 100000000,
  200000000, 300000000, 400000000, 500000000, 600000000, 700000000, 800000000, 900000000,
  1000000000, 2000000000, 3000000000, 4000000000, 5000000000, 6000000000, 7000000000, 8000000000,
  9000000000, 10000000000, 20000000000, 30000000000, 40000000000, 50000000000, 60000000000,
  70000000000, 80000000000, 90000000000, 100000000000, 200000000000, 300000000000, 400000000000,
  500000000000, 600000000000, 700000000000, 800000000000, 900000000000, 1000000000000,
  2000000000000, 3000000000000, 4000000000000, 5000000000000, 6000000000000, 7000000000000,
  8000000000000, 9000000000000, 10000000000000, 20000000000000, 30000000000000, 40000000000000,
  50000000000000, 60000000000000, 70000000000000, 80000000000000, 90000000000000, 100000000000000,
  200000000000000, 300000000000000, 400000000000000, 500000000000000, 600000000000000,
  700000000000000, 800000000000000, 900000000000000, 1000000000000000, 2000000000000000,
  3000000000000000, 4000000000000000, 5000000000000000, 6000000000000000, 7000000000000000,
  8000000000000000, 9000000000000000, 10000000000000000, 20000000000000000, 30000000000000000,
  40000000000000000, 50000000000000000, 60000000000000000, 70000000000000000, 80000000000000000,
  90000000000000000, 100000000000000000, 200000000000000000, 300000000000000000, 400000000000000000,
  500000000000000000, 600000000000000000, 700000000000000000, 800000000000000000,
  900000000000000000, 1000000000000000000, 2000000000000000000, 3000000000000000000,
  4000000000000000000, 5000000000000000000, 6000000000000000000, 7000000000000000000,
  8000000000000000000, 9000000000000000000, 10000000000000000000,
];

/** O(1) membership for {@link isPrettyAmount} (hot path: input selection). */
const PRETTY_AMOUNT_SET: ReadonlySet<number> = new Set(PRETTY_AMOUNTS);

/**
 * True when `amount` is an exact member of {@link PRETTY_AMOUNTS} (`{1..9} × 10^k`).
 * Non-pretty amounts (e.g. malformed change like 12345) cannot be ring-mixed at
 * non-zero mixin — no on-chain decoys share that denomination.
 */
export function isPrettyAmount(amount: number): boolean {
  return PRETTY_AMOUNT_SET.has(amount);
}
