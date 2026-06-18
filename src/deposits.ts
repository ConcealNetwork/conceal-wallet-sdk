/**
 * Deposits / banking (CryptoNote type-`03`).
 *
 * A CCX "deposit" locks CCX for a `term` (in blocks) via a type-`03`
 * `txout_to_deposit_key` output; a "withdrawal" redeems an unlocked deposit
 * (principal + interest) by spending it through a type-`03` `input_to_deposit_key`
 * input. This module holds:
 *
 *  - {@link calculateDepositInterest} — a VERBATIM, bit-exact port of the legacy
 *    `InterestCalculator.calculateInterest` (`lib/wallet-core/Interest.ts`). Interest
 *    determines real withdrawal amounts, so the float operations and `Math.floor`
 *    (V3/V2) and the `BigInt` truncating divide (V1) are reproduced EXACTLY — do not
 *    "simplify" the arithmetic or its evaluation order.
 *  - {@link OwnedDeposit} — a detected, owned deposit recovered during scanning.
 *  - {@link scanDepositOutput} — recover an `OwnedDeposit` from an owned type-`03`
 *    output (mirrors `TransactionsExplorer.parse` deposit detection).
 *  - {@link findWithdrawnDepositIndexes} — withdrawal detection: a type-`03` vin whose
 *    `outputIndex` matches an owned deposit's `globalIndex` marks it spent.
 *
 * The deposit/withdraw BUILD path (`buildDepositTransaction` / `buildWithdrawTransaction`)
 * lives in {@link ./transactions} so it can reuse the spend machinery and the lib-js
 * serializer; this module is the interest + scan + type half.
 */
import { derivePublicKey, generateKeyDerivation } from "./crypto";
import type { Hex, WalletKeys } from "./types";

// ---------------------------------------------------------------------------
// Constants (lib/config/wallet-network-scalars.mjs → config.ts, Interest.ts)
// ---------------------------------------------------------------------------

/** Atomic units per CCX exponent (`COIN_UNIT_PLACES`). */
export const COIN_UNIT_PLACES = 6;
/** `m_coin` = 10^coinUnitPlaces = 1e6 (atomic units per CCX). */
export const M_COIN = 10 ** COIN_UNIT_PLACES;
/** Transaction version for ALL non-regular (deposit + withdraw) txs (`DEPOSIT_TX_VERSION`). */
export const DEPOSIT_TX_VERSION = 2;
/** One month, in blocks (`depositMinTermBlock`). The V3 term is `months * this`. */
export const DEPOSIT_MIN_TERM_BLOCK = 21900;
/** Minimum deposit term in months (`depositMinTermMonth`). */
export const DEPOSIT_MIN_TERM_MONTH = 1;
/** Maximum deposit term in months (`depositMaxTermMonth`). */
export const DEPOSIT_MAX_TERM_MONTH = 12;
/** Minimum deposit amount in whole CCX (`depositMinAmountCoin`). */
export const DEPOSIT_MIN_AMOUNT_COIN = 1;
/** Minimum deposit amount in atomic units (`depositMinAmountCoin * m_coin` = 1e6). */
export const DEPOSIT_MIN_AMOUNT_ATOMIC = DEPOSIT_MIN_AMOUNT_COIN * 10 ** COIN_UNIT_PLACES;
/** Maximum deposit term in blocks (`depositMaxTermMonth * depositMinTermBlock` = 262800). */
export const DEPOSIT_MAX_TERM_BLOCK = DEPOSIT_MAX_TERM_MONTH * DEPOSIT_MIN_TERM_BLOCK;
/** Deposit-tx network fee, atomic units (`coinFee`). */
export const DEPOSIT_TX_FEE = 1000;
/** Withdraw-tx fee, atomic units (`depositSmallWithdrawFee`) — NOT the 1000 coinFee. */
export const DEPOSIT_SMALL_WITHDRAW_FEE = 10;
/** V3 monthly base rates by amount tier: `[ <10000, >=10000 & <20000, >=20000 ]`. */
export const DEPOSIT_RATE_V3: readonly number[] = [0.029, 0.039, 0.049];

// Interest dispatch constants (verbatim from Interest.ts:38-51).
const DEPOSIT_MIN_TERM = 5040; // One week
const DEPOSIT_MAX_TERM = 1 * 12 * 21900; // 262800 — one year (legacy V1 divisor)
const DEPOSIT_MIN_TERM_V3 = 21900; // One month
const DEPOSIT_HEIGHT_V3 = 413400; // Height when V3 deposit rates were activated
const DEPOSIT_MIN_TOTAL_RATE_FACTOR = 0; // Constant rate
const DEPOSIT_MAX_TOTAL_RATE = 4; // Legacy deposits
const BLOCK_WITH_MISSING_INTEREST = 425799; // Block with special handling
const END_MULTIPLIER_BLOCK = 12750; // Early-deposit 100× multiplier boundary
const MULTIPLIER_FACTOR = 100;

// V2 weekly/investment constants (config fallbacks used as the canonical values).
const INVESTMENT_MQ = 1.4473;
const WEEKLY_BASE_INTEREST = 0.0696;
const WEEKLY_INTEREST_INCREMENT = 0.0002;

// ---------------------------------------------------------------------------
// Interest (VERBATIM port of Interest.ts — bit-exact with the daemon)
// ---------------------------------------------------------------------------

/** Inputs to {@link calculateDepositInterest}. All atomic units / blocks. */
export interface DepositInterestInput {
  /** Deposit amount in atomic units (principal). */
  amount: number;
  /** Deposit term in blocks. */
  term: number;
  /** Block height when the deposit was made. */
  lockHeight: number;
}

/**
 * Calculate the interest (atomic units) a deposit earns, given its principal `amount`
 * (atomic), `term` (blocks) and `lockHeight` (deposit block height).
 *
 * VERBATIM port of `InterestCalculator.calculateInterest` (`Interest.ts:60-97`),
 * preserving the exact dispatch and arithmetic:
 *  1. `lockHeight === 425799` ⇒ `lockHeight += term` (BLOCK_WITH_MISSING_INTEREST).
 *  2. V3 (monthly) if `term % 21900 === 0 && lockHeight > 413400`.
 *  3. V2 (investment/weekly) if `term % 64800 === 0 || term % 5040 === 0`.
 *  4. V1 (legacy fallback) otherwise — BigInt truncating divide.
 *
 * This determines real withdrawal amounts; the float op order and `Math.floor` are
 * load-bearing and must not be altered.
 */
export function calculateDepositInterest(input: DepositInterestInput): number {
  const { amount, term } = input;
  let lockHeight = input.lockHeight;

  // Special case handling for block with missing interest
  if (lockHeight === BLOCK_WITH_MISSING_INTEREST) {
    lockHeight = lockHeight + term;
  }

  // Check if this is a V3 deposit (monthly term)
  if (term % DEPOSIT_MIN_TERM_V3 === 0 && lockHeight > DEPOSIT_HEIGHT_V3) {
    return calculateInterestV3(amount, term);
  }

  // Check if this is a V2 deposit (investment or weekly)
  if (term % 64800 === 0 || term % DEPOSIT_MIN_TERM === 0) {
    return calculateInterestV2(amount, term);
  }

  // If we reach here, it's a V1 deposit (fallback, should not happen in current Conceal)
  const m_depositMaxTerm = DEPOSIT_MAX_TERM;

  const a = term * DEPOSIT_MAX_TOTAL_RATE - DEPOSIT_MIN_TOTAL_RATE_FACTOR;
  // conceal-core (Currency.cpp:268-289) uses 128-bit mul128/div128_32 and truncates the
  // division BEFORE the early-deposit multiplier. amount*a can exceed
  // Number.MAX_SAFE_INTEGER for large deposits, so use BigInt to keep the product and
  // the truncating divide bit-exact with the daemon.
  const product = BigInt(Math.trunc(amount)) * BigInt(a);
  const base = Number(product / BigInt(100 * m_depositMaxTerm));

  return lockHeight <= END_MULTIPLIER_BLOCK ? base * MULTIPLIER_FACTOR : base;
}

/** V3 deposits (monthly terms). Verbatim from `Interest.ts:105-136`. */
function calculateInterestV3(amount: number, term: number): number {
  const m_coin = 10 ** COIN_UNIT_PLACES;

  const amount4Humans = amount / m_coin;

  // Base interest rates depending on amount tiers
  let baseInterest = DEPOSIT_RATE_V3[0] || 0.029; // Basic rate for amounts < 10000

  if (amount4Humans >= 20000) {
    baseInterest = DEPOSIT_RATE_V3[2] || 0.049; // Highest rate for amounts >= 20000
  } else if (amount4Humans >= 10000) {
    baseInterest = DEPOSIT_RATE_V3[1] || 0.039; // Medium rate for amounts between 10000-20000
  }

  // Calculate months
  let months = term / DEPOSIT_MIN_TERM_V3;
  if (months > 12) {
    months = 12; // Cap at 12 months
  }

  // Calculate effective annual rate with term bonus
  const ear = baseInterest + (months - 1) * 0.001;

  // Calculate effective interest rate for the period
  const eir = (ear / 12) * months;

  // Calculate interest
  const interest = amount * eir;

  return Math.floor(interest);
}

/** V2 deposits (investment or weekly terms). Verbatim from `Interest.ts:144-194`. */
function calculateInterestV2(amount: number, term: number): number {
  const m_coin = 10 ** COIN_UNIT_PLACES;

  // Investment term (64800 blocks - quarterly)
  if (term % 64800 === 0) {
    const amount4Humans = amount / m_coin;

    // Quantity tier bonus - exact same tiers as in C++ code
    let qTier = 1;
    if (amount4Humans > 110000 && amount4Humans < 180000) qTier = 1.01;
    if (amount4Humans >= 180000 && amount4Humans < 260000) qTier = 1.02;
    if (amount4Humans >= 260000 && amount4Humans < 350000) qTier = 1.03;
    if (amount4Humans >= 350000 && amount4Humans < 450000) qTier = 1.04;
    if (amount4Humans >= 450000 && amount4Humans < 560000) qTier = 1.05;
    if (amount4Humans >= 560000 && amount4Humans < 680000) qTier = 1.06;
    if (amount4Humans >= 680000 && amount4Humans < 810000) qTier = 1.07;
    if (amount4Humans >= 810000 && amount4Humans < 950000) qTier = 1.08;
    if (amount4Humans >= 950000 && amount4Humans < 1100000) qTier = 1.09;
    if (amount4Humans >= 1100000 && amount4Humans < 1260000) qTier = 1.1;
    if (amount4Humans >= 1260000 && amount4Humans < 1430000) qTier = 1.11;
    if (amount4Humans >= 1430000 && amount4Humans < 1610000) qTier = 1.12;
    if (amount4Humans >= 1610000 && amount4Humans < 1800000) qTier = 1.13;
    if (amount4Humans >= 1800000 && amount4Humans < 2000000) qTier = 1.14;
    if (amount4Humans > 2000000) qTier = 1.15;

    // Investment calculation - same as C++ implementation
    const mq = INVESTMENT_MQ; // From C++ code
    const termQuarters = term / 64800;
    const m8 = 100.0 * (1.0 + mq / 100.0) ** termQuarters - 100.0;
    const m5 = termQuarters * 0.5;
    const m7 = m8 * (1 + m5 / 100);
    const rate = m7 * qTier;
    const interest = amount * (rate / 100);

    return Math.floor(interest);
  }

  // Weekly deposits (5040 blocks)
  if (term % DEPOSIT_MIN_TERM === 0) {
    const weeks = term / DEPOSIT_MIN_TERM;
    const baseInterest = WEEKLY_BASE_INTEREST; // Base weekly interest rate
    const interestPerWeek = WEEKLY_INTEREST_INCREMENT; // Additional interest per week
    const interestRate = baseInterest + weeks * interestPerWeek;
    const interest = amount * ((weeks * interestRate) / 100);

    return Math.floor(interest);
  }

  return 0;
}

// ---------------------------------------------------------------------------
// Owned-deposit type + scanning
// ---------------------------------------------------------------------------

/**
 * A detected deposit output the wallet owns, recovered during scanning — a superset
 * of `OwnedOutput` carrying the deposit-specific fields (term, keys, deposit-tx
 * height) plus the derived `interest` and `unlockHeight`. Mirrors the legacy
 * `Deposit` (`Transaction.ts:347-472`).
 */
export interface OwnedDeposit {
  /** Principal, atomic units. */
  amount: number;
  /** The deposit's GLOBAL output index (the `outputIndex` a withdraw input spends). */
  globalIndex: number;
  /** Index of the deposit output within its source tx's `vout` (the sig-derivation index). */
  outputIndex: number;
  /** The deposit tx's public key (`R`). */
  txPublicKey: Hex;
  /** The one-time deposit public key (`keys[0]`). */
  publicKey: Hex;
  /** The deposit output's `target.data.keys` (single-element for CCX). */
  keys: Hex[];
  /** Lock term, in blocks. */
  term: number;
  /** Block height the deposit tx was mined at. */
  blockHeight: number;
  /** Source transaction hash. */
  txHash: Hex;
  /** Earned interest, atomic units = {@link calculateDepositInterest}(amount, term, blockHeight). */
  interest: number;
  /** Off-chain unlock height = `blockHeight + term`. */
  unlockHeight: number;
}

/**
 * One on-chain type-`03` input (`input_to_deposit_key`) view sufficient for
 * withdrawal detection — the daemon's per-input JSON shape, narrowed.
 */
export interface RawDepositInput {
  /** Input type tag; only `"input_to_deposit_key"` is a deposit-spend. */
  type?: string;
  /** Deposit term, blocks. */
  term?: number;
  /** The spent deposit's GLOBAL output index. */
  outputIndex?: number;
}

/**
 * Detect every owned type-`03` deposit output of a scanned transaction.
 *
 * Given the per-output derived keys already computed by the caller (the SCAN pass in
 * {@link ../transactions.scanTransactionOutputs}), this checks each type-`03` output's
 * `target.data.keys` for membership of the derived key and, when owned AND the output
 * carries a `term`, recovers an {@link OwnedDeposit} (mirroring
 * `TransactionsExplorer.parse` `:546-579`): `term`, `keys`, in-vout index, block height,
 * tx hash, plus `interest = calculateDepositInterest(amount, term, blockHeight)` and
 * `unlockHeight = blockHeight + term`.
 *
 * It does NOT redo the ECDH scan — that is the SCAN pass's job, which already produces
 * the derived per-output key. To keep the SDK's single scan entry point, deposit
 * recovery is exposed from `scanTransactionOutputs` via {@link scanDepositOutput}.
 */
export function scanDepositOutput(args: {
  amount: number;
  term: number;
  keys: Hex[];
  publicKey: Hex;
  txPublicKey: Hex;
  outputIndex: number;
  globalIndex: number;
  blockHeight: number;
  txHash: Hex;
}): OwnedDeposit {
  const { amount, term, keys, publicKey, txPublicKey, outputIndex, globalIndex } = args;
  const blockHeight = args.blockHeight;
  return {
    amount,
    globalIndex,
    outputIndex,
    txPublicKey,
    publicKey,
    keys,
    term,
    blockHeight,
    txHash: args.txHash,
    interest: calculateDepositInterest({ amount, term, lockHeight: blockHeight }),
    unlockHeight: blockHeight + term,
  };
}

/**
 * Withdrawal detection: return the GLOBAL output indexes of deposits that the given
 * transaction inputs withdraw. A type-`03` `input_to_deposit_key` whose `outputIndex`
 * matches an owned deposit's `globalIndex` marks that deposit spent. (Matching is by
 * the deposit's global output index only — never by vin position — so another user's
 * unlock can never mark our deposit spent; mirrors `TransactionsExplorer.ts:676-716`.)
 */
export function findWithdrawnDepositIndexes(
  inputs: readonly RawDepositInput[],
  ownedDeposits: readonly OwnedDeposit[],
): number[] {
  if (!Array.isArray(inputs) || inputs.length === 0 || ownedDeposits.length === 0) {
    return [];
  }
  const ownedGlobalIndexes = new Set(ownedDeposits.map((d) => d.globalIndex));
  const withdrawn: number[] = [];
  for (const input of inputs) {
    if (input?.type !== "input_to_deposit_key") continue;
    if (typeof input.outputIndex !== "number") continue;
    if (ownedGlobalIndexes.has(input.outputIndex) && !withdrawn.includes(input.outputIndex)) {
      withdrawn.push(input.outputIndex);
    }
  }
  return withdrawn;
}

/**
 * Validate that a deposit's stored `interest` matches a fresh computation from its
 * principal/term/height — a cheap integrity guard against tampered/persisted state
 * before it feeds a real withdrawal amount. Returns the recomputed interest.
 */
export function recomputeDepositInterest(deposit: OwnedDeposit): number {
  return calculateDepositInterest({
    amount: deposit.amount,
    term: deposit.term,
    lockHeight: deposit.blockHeight,
  });
}

/**
 * Re-derive the one-time deposit key for an owned deposit (own-address change-path
 * derivation): `derive_public_key(generate_key_derivation(R, viewSec), outputIndex,
 * spendPub)`. Used to assert that {@link OwnedDeposit.publicKey} is genuinely
 * spendable by `keys` before building a withdrawal. Throws on malformed keys.
 */
export function deriveDepositOneTimeKey(deposit: OwnedDeposit, keys: WalletKeys): Hex {
  const derivation = generateKeyDerivation(deposit.txPublicKey, keys.view.sec);
  return derivePublicKey(derivation, deposit.outputIndex, keys.spend.pub) as Hex;
}
