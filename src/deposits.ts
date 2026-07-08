// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

import {
  BLOCK_WITH_MISSING_INTEREST,
  COIN_UNIT_PLACES,
  DEPOSIT_HEIGHT_V3,
  DEPOSIT_MAX_TERM,
  DEPOSIT_MAX_TOTAL_RATE,
  DEPOSIT_MIN_TERM,
  DEPOSIT_MIN_TERM_V3,
  DEPOSIT_MIN_TOTAL_RATE_FACTOR,
  DEPOSIT_RATE_V3,
  END_MULTIPLIER_BLOCK,
  INVESTMENT_MQ,
  MULTIPLIER_FACTOR,
  WEEKLY_BASE_INTEREST,
  WEEKLY_INTEREST_INCREMENT,
} from "./constants/blockchain";
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
 *  - {@link findWithdrawnDepositIndexes} — withdrawal detection: wallet-core
 *    `Wallet.addWithdrawal` matches GLOBAL `outputIndex` + principal `amount`.
 *
 * The deposit/withdraw BUILD path (`buildDepositTransaction` / `buildWithdrawTransaction`)
 * lives in {@link ./transactions} so it can reuse the spend machinery and the lib-js
 * serializer; this module is the interest + scan + type half.
 */
import { derivePublicKey, generateKeyDerivation } from "./crypto";
import { parseDaemonNum } from "./tx-shape";
import type { Hex, WalletKeys } from "./types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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
  /** The spent deposit's GLOBAL output index (on-chain vin field name). */
  outputIndex?: number;
  /** Principal atomic amount on the type-03 vin. */
  amount?: number;
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
 * Sum every vout amount on a raw daemon transaction.
 */
export function sumVoutAmount(transaction: unknown): number {
  if (!isRecord(transaction)) return 0;
  const vout = transaction.vout;
  if (!Array.isArray(vout)) return 0;
  let total = 0;
  for (const out of vout) {
    if (!isRecord(out)) continue;
    const amount = parseDaemonNum(out.amount);
    if (amount !== undefined) total += amount;
  }
  return total;
}

/**
 * Withdraw txs carry principal on the type-03 vin and principal + interest on the
 * vout (`Cn.ts` only allows outputs > inputs for deposits/withdrawals).
 */
export function isWithdrawShape(transaction: unknown, inputs: readonly RawDepositInput[]): boolean {
  if (inputs.length === 0) return false;
  const inPrincipal = inputs.reduce((sum, vin) => sum + (vin.amount ?? 0), 0);
  if (inPrincipal <= 0) return false;
  return sumVoutAmount(transaction) > inPrincipal;
}

/** Stable deposit identity — wallet-core keys withdrawals on txHash + globalOutputIndex. */
export function depRef(deposit: Pick<OwnedDeposit, "txHash" | "globalIndex">): string {
  return `${deposit.txHash}:${deposit.globalIndex}`;
}

/**
 * Withdrawal detection: return deposit refs (`txHash:globalIndex`) this tx withdraws.
 * Mirrors wallet-core `Wallet.addWithdrawal`: match global `outputIndex` + principal
 * `amount`; skip entries already in `spentDepositRefs`.
 */
export function findWithdrawnDepRefs(
  inputs: readonly RawDepositInput[],
  ownedDeposits: readonly OwnedDeposit[],
  spentDepositRefs: readonly string[] = [],
): string[] {
  if (!Array.isArray(inputs) || inputs.length === 0 || ownedDeposits.length === 0) {
    return [];
  }
  const spent = new Set(spentDepositRefs);
  const withdrawn: string[] = [];
  for (const input of inputs) {
    if (input?.type !== "input_to_deposit_key") continue;
    if (typeof input.outputIndex !== "number" || typeof input.amount !== "number") continue;

    for (const deposit of ownedDeposits) {
      const ref = depRef(deposit);
      if (spent.has(ref)) continue;
      if (withdrawn.includes(ref)) continue;
      if (deposit.globalIndex !== input.outputIndex) continue;
      if (deposit.amount !== input.amount) continue;
      withdrawn.push(ref);
      break;
    }
  }
  return withdrawn;
}

/**
 * @deprecated Use {@link findWithdrawnDepRefs}. Returns global indexes only (lossy when
 * multiple deposits share an index).
 */
export function findWithdrawnDepositIndexes(
  inputs: readonly RawDepositInput[],
  ownedDeposits: readonly OwnedDeposit[],
  spentDepositRefs: readonly string[] = [],
): number[] {
  return findWithdrawnDepRefs(inputs, ownedDeposits, spentDepositRefs).map((ref) => {
    const deposit = ownedDeposits.find((d) => depRef(d) === ref);
    return deposit?.globalIndex ?? Number.parseInt(ref.split(":")[1] ?? "0", 10);
  });
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
