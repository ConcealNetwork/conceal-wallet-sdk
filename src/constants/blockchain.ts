// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Chain / consensus scalars — currency, fork heights, deposit rules, network sizing/timing.
 * When C++ / daemon parameters change, edit here first.
 */

// --- currency ---

/** Atomic units per CCX exponent (`COIN_UNIT_PLACES`). */
export const COIN_UNIT_PLACES = 6;
/** `m_coin` = 10^coinUnitPlaces = 1e6 (atomic units per CCX). */
export const M_COIN = 10 ** COIN_UNIT_PLACES;

// --- fork / upgrade heights ---

/** Fork height below which fusion inputs additionally require `amount >= DUST_THRESHOLD`. */
export const UPGRADE_HEIGHT_V4 = 45000;
/** Height when V3 deposit rates were activated. */
export const DEPOSIT_HEIGHT_V3 = 413400;
/** Block with special interest handling. */
export const BLOCK_WITH_MISSING_INTEREST = 425799;
/** Early-deposit 100× multiplier boundary. */
export const END_MULTIPLIER_BLOCK = 12750;

// --- deposit rules (consensus / banking) ---

/** Transaction version for ALL non-regular (deposit + withdraw) txs. */
export const DEPOSIT_TX_VERSION = 2;
/** One month, in blocks. The V3 term is `months * this`. */
export const DEPOSIT_MIN_TERM_BLOCK = 21900;
/** Minimum deposit term in months. */
export const DEPOSIT_MIN_TERM_MONTH = 1;
/** Maximum deposit term in months. */
export const DEPOSIT_MAX_TERM_MONTH = 12;
/** Minimum deposit amount in whole CCX. */
export const DEPOSIT_MIN_AMOUNT_COIN = 1;
/** Minimum deposit amount in atomic units (`depositMinAmountCoin * m_coin` = 1e6). */
export const DEPOSIT_MIN_AMOUNT_ATOMIC = DEPOSIT_MIN_AMOUNT_COIN * 10 ** COIN_UNIT_PLACES;
/** Maximum deposit term in blocks (`depositMaxTermMonth * depositMinTermBlock` = 262800). */
export const DEPOSIT_MAX_TERM_BLOCK = DEPOSIT_MAX_TERM_MONTH * DEPOSIT_MIN_TERM_BLOCK;
/** V3 monthly base rates by amount tier: `[ <10000, >=10000 & <20000, >=20000 ]`. */
export const DEPOSIT_RATE_V3: readonly number[] = [0.029, 0.039, 0.049];

// --- interest dispatch (Interest.ts verbatim) ---

/** One week, in blocks. */
export const DEPOSIT_MIN_TERM = 5040;
/** One year (legacy V1 divisor). */
export const DEPOSIT_MAX_TERM = 1 * 12 * DEPOSIT_MIN_TERM_BLOCK;
/** One month — same as {@link DEPOSIT_MIN_TERM_BLOCK}. */
export const DEPOSIT_MIN_TERM_V3 = DEPOSIT_MIN_TERM_BLOCK;
/** Constant rate factor for legacy V1 deposits. */
export const DEPOSIT_MIN_TOTAL_RATE_FACTOR = 0;
/** Legacy deposits max total rate. */
export const DEPOSIT_MAX_TOTAL_RATE = 4;
/** Early-deposit multiplier factor. */
export const MULTIPLIER_FACTOR = 100;
/** V2 investment MQ coefficient. */
export const INVESTMENT_MQ = 1.4473;
/** V2 weekly base interest rate. */
export const WEEKLY_BASE_INTEREST = 0.0696;
/** V2 weekly interest increment per week. */
export const WEEKLY_INTEREST_INCREMENT = 0.0002;

// --- network sizing (CryptoNoteConfig) ---

/** The CryptoNote full-reward-zone constant. */
export const CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE = 100000;

// --- network timing (CryptoNoteConfig / legacy config.ts) ---

/** Target average block time in seconds (`config.avgBlockTime`). */
export const AVG_BLOCK_TIME_SECONDS = 120;
/** Mempool transaction lifetime in seconds (`config.cryptonoteMemPoolTxLifetime`, 12 h). */
export const CRYPTONOTE_MEMPOOL_TX_LIFETIME_SECONDS = 60 * 60 * 12;
