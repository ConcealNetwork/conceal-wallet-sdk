// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * UI-facing transaction classification — ports legacy `resolveTransactionType` /
 * `TransactionsExplorer.isMinerTx` / fusion heuristics from conceal-web-wallet.
 *
 * Kinds are decided at scan/fold time (while the raw daemon tx is still in hand)
 * and stored on {@link WalletTransaction.kind}.
 */
import {
  FUSION_TX_MIN_IN_OUT_COUNT_RATIO,
  FUSION_TX_MIN_INPUT_COUNT,
  MAX_FUSION_OUTPUTS,
} from "./constants/fusion-const";
import { DUST_THRESHOLD, MESSAGE_TX_AMOUNT_ATOMIC, MINIMUM_FEE_V2 } from "./constants/tx-const";
import type { RawDepositInput } from "./deposits";
import type { OwnedOutput } from "./transactions";
import type { TransactionDirection, WalletTransaction } from "./wallet";

/** Effective transaction type for UI lists (icons, filters, CSV). */
export type WalletTransactionKind =
  | "receive"
  | "send"
  | "miner"
  | "deposit"
  | "withdrawal"
  | "fusion";

/** Raw-tx shape hints extracted once during scan (JSON-safe). */
export interface TxKindHints {
  isCoinbase: boolean;
  vinCount: number;
  voutCount: number;
  hasDepositVin: boolean;
  hasDepositVout: boolean;
  fee: number;
}

/** Optional scan context passed to {@link classifyTransactionKind}. */
export interface ClassifyTransactionKindInput {
  direction: TransactionDirection;
  ownedOutputs: readonly OwnedOutput[];
  ownedDeposits?: readonly unknown[];
  depositInputs?: readonly RawDepositInput[];
  rawTransaction?: unknown;
  fee?: number;
  receivedAmount: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** True for a coinbase (miner-reward) vin — legacy `TransactionsExplorer.isMinerTx`. */
export function isCoinbaseRawTransaction(transaction: unknown): boolean {
  if (!isRecord(transaction)) return false;
  const vin = transaction.vin;
  if (!Array.isArray(vin)) return false;
  if (vin.length === 0) return true;
  if (vin.length !== 1) return false;
  const input = vin[0];
  return isRecord(input) && ("gen" in input || input.type === "ff");
}

/** Extract vin/vout shape used by fusion + coinbase heuristics. */
export function extractTxKindHints(transaction: unknown, fee = 0): TxKindHints {
  let vinCount = 0;
  let voutCount = 0;
  let hasDepositVin = false;
  let hasDepositVout = false;

  if (isRecord(transaction)) {
    const vin = transaction.vin;
    if (Array.isArray(vin)) {
      vinCount = vin.length;
      for (const input of vin) {
        if (!isRecord(input)) continue;
        const source = isRecord(input.value) ? input.value : input;
        const type = input.type ?? source.type;
        if (type === "03" || type === "input_to_deposit_key") hasDepositVin = true;
      }
    }
    const vout = transaction.vout;
    if (Array.isArray(vout)) {
      voutCount = vout.length;
      for (const out of vout) {
        if (!isRecord(out)) continue;
        const target = out.target;
        if (
          isRecord(target) &&
          (target.type === "03" || target.type === "txout_to_deposit_key")
        ) {
          hasDepositVout = true;
        }
      }
    }
  }

  return {
    isCoinbase: isCoinbaseRawTransaction(transaction),
    vinCount,
    voutCount,
    hasDepositVin,
    hasDepositVout,
    fee,
  };
}

/** True when the raw tx shape matches a fusion (optimize) transaction. */
export function isFusionShape(hints: TxKindHints): boolean {
  if (hints.hasDepositVin || hints.hasDepositVout) return false;
  if (hints.voutCount <= 0) return false;
  return (
    hints.vinCount > FUSION_TX_MIN_INPUT_COUNT &&
    hints.voutCount <= MAX_FUSION_OUTPUTS &&
    hints.vinCount / hints.voutCount > FUSION_TX_MIN_IN_OUT_COUNT_RATIO &&
    (hints.fee === 0 || hints.fee === MINIMUM_FEE_V2)
  );
}

/**
 * Classify a transaction the wallet touched during sync. Mirrors legacy
 * `resolveTransactionType` priority: deposit → withdrawal → fusion → miner → send/receive.
 */
export function classifyTransactionKind(input: ClassifyTransactionKindInput): WalletTransactionKind {
  const ownedDeposits = input.ownedDeposits ?? [];
  const depositInputs = input.depositInputs ?? [];

  if (ownedDeposits.length > 0) return "deposit";
  if (depositInputs.length > 0) return "withdrawal";

  const hints =
    input.rawTransaction !== undefined
      ? extractTxKindHints(input.rawTransaction, input.fee ?? 0)
      : null;

  if (hints && isFusionShape(hints)) return "fusion";

  if (
    hints?.isCoinbase &&
    input.receivedAmount > 0 &&
    input.receivedAmount !== MESSAGE_TX_AMOUNT_ATOMIC
  ) {
    return "miner";
  }

  return input.direction === "out" ? "send" : "receive";
}

/** Read a history entry's kind, falling back to direction for pre-kind blobs. */
export function resolveWalletTransactionKind(tx: WalletTransaction): WalletTransactionKind {
  return tx.kind ?? (tx.direction === "out" ? "send" : "receive");
}

/** True when an output amount is dust (legacy `Currency.isDustOutput`). */
export function isDustOutput(amount: number, dustThreshold = DUST_THRESHOLD): boolean {
  return amount > 0 && amount < dustThreshold;
}
