// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Wallet fusion / optimization — a CryptoNote "sweep dust / optimize" primitive,
 * ported VERBATIM from the legacy `conceal-web-wallet` engine
 * (`Currency.isAmountApplicableInFusionTransactionInput` / `getApproximateMaximumInputCount`
 * / `getApproximateTransactionSize`, and `Wallet.estimateFusionReadyness` /
 * `optimizationNeeded` / `pickRandomFusionInputs` / `createFusionTransaction`).
 *
 * A fusion transaction is a **self-send that consolidates many small, same-power-of-ten
 * outputs into a few larger outputs**, shrinking the wallet's UTXO count so future
 * spends need fewer inputs (smaller, cheaper, faster txs).
 *
 * Three cooperating pure functions reproduce the legacy logic with no `Wallet`
 * instance and no network:
 *  - {@link isOptimizationNeeded} — "is optimization needed?" status (legacy `optimizationNeeded`).
 *  - {@link selectFusionInputs} — bucket selection + input draw (legacy `pickRandomFusionInputs`).
 *  - {@link buildFusionTransaction} — the size-bounded self-send build (legacy
 *    `createFusionTransaction`), a thin wrapper over {@link buildTransaction}.
 *
 * All cryptography / serialization stays inside {@link buildTransaction} (lib-js);
 * this module only orchestrates selection, sizing and the self-send destination.
 * Daemon-derived values (height, balance, decoys) are SUPPLIED, never fetched —
 * matching the rest of the SDK builder. Broadcast + mempool refresh stay app-side.
 */
import { UPGRADE_HEIGHT_V4 } from "./constants/blockchain";
import * as fusionConst from "./constants/fusion-const";
import { MINIMUM_FEE_V2, DEFAULT_MIXIN, DUST_THRESHOLD } from "./constants/tx-const";
import {
  type BuiltTransaction,
  buildTransaction,
  type DecoySet,
  type SpendableOutput,
} from "./transactions";
import type { Hex, WalletKeys } from "./types";

// ---------------------------------------------------------------------------
// Eligibility + byte-size model (Currency.ts:52-126)
// ---------------------------------------------------------------------------

/** Result of {@link isAmountApplicableInFusionInput}: eligibility + power-of-ten bucket. */
export interface FusionAmountApplicability {
  /** True when `amount` qualifies as a fusion input at this `threshold`/`height`. */
  applicable: boolean;
  /** Power-of-ten bucket index (`floor(prettyIndex / 9)`), present only when applicable. */
  amountPowerOfTen?: number;
}

/**
 * Whether an output `amount` qualifies as a fusion input at `threshold` and chain
 * `height`. Ports `Currency.isAmountApplicableInFusionTransactionInput` (`Currency.ts:52-75`)
 * verbatim. ALL must hold:
 *  1. `amount < threshold` (strictly below).
 *  2. Below {@link UPGRADE_HEIGHT_V4}: `amount >= DUST_THRESHOLD` (dropped at/after V4).
 *  3. `amount` is an exact "pretty" amount — `idx = PRETTY_AMOUNTS.findIndex(a => a >= amount)`
 *     and `PRETTY_AMOUNTS[idx] === amount`. Non-pretty amounts (e.g. change like 12345)
 *     are rejected.
 *  4. Bucket = `Math.floor(idx / 9)` (the ladder has 9 entries per decade).
 */
export function isAmountApplicableInFusionInput(
  amount: number,
  threshold: number,
  height: number,
): FusionAmountApplicability {
  if (amount >= threshold) {
    return { applicable: false };
  }

  if (height < UPGRADE_HEIGHT_V4 && amount < DUST_THRESHOLD) {
    return { applicable: false };
  }

  const idx = fusionConst.PRETTY_AMOUNTS.findIndex((a) => a >= amount);

  if (idx === -1 || fusionConst.PRETTY_AMOUNTS[idx] !== amount) {
    return { applicable: false };
  }

  const amountPowerOfTen = Math.floor(idx / 9);

  return { applicable: true, amountPowerOfTen };
}

/**
 * Approximate maximum number of inputs that fit in a transaction of `transactionSize`
 * bytes with `outputCount` outputs and `mixinCount` mixins per input. Verbatim port of
 * `Currency.getApproximateMaximumInputCount` (`Currency.ts:84-104`).
 */
export function getApproximateMaximumInputCount(
  transactionSize: number,
  outputCount: number,
  mixinCount: number,
): number {
  const outputsSize =
    outputCount *
    (fusionConst.OUTPUT_TAG_SIZE + fusionConst.OUTPUT_KEY_SIZE + fusionConst.AMOUNT_SIZE);
  const headerSize =
    fusionConst.TRANSACTION_VERSION_SIZE +
    fusionConst.TRANSACTION_UNLOCK_TIME_SIZE +
    fusionConst.EXTRA_TAG_SIZE +
    fusionConst.PUBLIC_KEY_SIZE;
  const inputSize =
    fusionConst.INPUT_TAG_SIZE +
    fusionConst.AMOUNT_SIZE +
    fusionConst.KEY_IMAGE_SIZE +
    fusionConst.SIGNATURE_SIZE +
    fusionConst.GLOBAL_INDEXES_VECTOR_SIZE_SIZE +
    fusionConst.GLOBAL_INDEXES_INITIAL_VALUE_SIZE +
    mixinCount * (fusionConst.GLOBAL_INDEXES_DIFFERENCE_SIZE + fusionConst.SIGNATURE_SIZE);

  return Math.floor((transactionSize - headerSize - outputsSize) / inputSize);
}

/**
 * Approximate serialized size (bytes) of a transaction with `inputCount` inputs,
 * `outputCount` outputs and `mixinCount` mixins per input. Verbatim port of
 * `Currency.getApproximateTransactionSize` (`Currency.ts:106-126`).
 */
export function getApproximateTransactionSize(
  inputCount: number,
  outputCount: number,
  mixinCount: number,
): number {
  const outputsSize =
    outputCount *
    (fusionConst.OUTPUT_TAG_SIZE + fusionConst.OUTPUT_KEY_SIZE + fusionConst.AMOUNT_SIZE);
  const headerSize =
    fusionConst.TRANSACTION_VERSION_SIZE +
    fusionConst.TRANSACTION_UNLOCK_TIME_SIZE +
    fusionConst.EXTRA_TAG_SIZE +
    fusionConst.PUBLIC_KEY_SIZE;
  const inputSize =
    fusionConst.INPUT_TAG_SIZE +
    fusionConst.AMOUNT_SIZE +
    fusionConst.KEY_IMAGE_SIZE +
    fusionConst.SIGNATURE_SIZE +
    fusionConst.GLOBAL_INDEXES_VECTOR_SIZE_SIZE +
    fusionConst.GLOBAL_INDEXES_INITIAL_VALUE_SIZE +
    mixinCount * (fusionConst.GLOBAL_INDEXES_DIFFERENCE_SIZE + fusionConst.SIGNATURE_SIZE);

  return headerSize + inputCount * inputSize + outputsSize;
}

// ---------------------------------------------------------------------------
// Optimization status (Wallet.estimateFusionReadyness + optimizationNeeded)
// ---------------------------------------------------------------------------

/** Inputs to {@link isOptimizationNeeded}. */
export interface FusionStatusInput {
  /** The wallet's current spendable (unspent) outputs. */
  unspentOutputs: SpendableOutput[];
  /** Available balance, atomic (legacy `availableAmount(height)`). */
  balance: number;
  /** Current blockchain height. */
  blockchainHeight: number;
  /** Starting threshold, atomic; defaults to {@link OPTIMIZE_THRESHOLD} (900000000). */
  threshold?: number;
}

/**
 * Optimization status. Shape matches the legacy `OptimizationStatus` service type
 * (`{ isNeeded, unspentOutputs }`) so the real settings.service can map it 1:1.
 */
export interface FusionStatus {
  /** True when a fusion is worth running (see {@link isOptimizationNeeded}). */
  isNeeded: boolean;
  /** Count of the wallet's unspent outputs (legacy `numOutputs`). */
  unspentOutputs: number;
}

/**
 * Count, for a single `threshold`, how many eligible pretty outputs sit in buckets that
 * are "fusion ready" (bucket has `>= OPTIMIZE_OUTPUTS` eligible outs). Verbatim port of
 * `Wallet.estimateFusionReadyness` (`Wallet.ts:1026-1065`).
 */
function estimateFusionReadyness(
  unspentOutputs: readonly SpendableOutput[],
  threshold: number,
  blockchainHeight: number,
): number {
  const bucketSizes = new Array<number>(fusionConst.NUM_BUCKETS).fill(0);

  for (const out of unspentOutputs) {
    const result = isAmountApplicableInFusionInput(out.amount, threshold, blockchainHeight);
    if (result.applicable && typeof result.amountPowerOfTen === "number") {
      if (result.amountPowerOfTen < fusionConst.NUM_BUCKETS) {
        bucketSizes[result.amountPowerOfTen] = (bucketSizes[result.amountPowerOfTen] ?? 0) + 1;
      }
    }
  }

  let fusionReadyCount = 0;
  for (const bucketSize of bucketSizes) {
    if (bucketSize >= fusionConst.OPTIMIZE_OUTPUTS) {
      fusionReadyCount += bucketSize;
    }
  }

  return fusionReadyCount;
}

/**
 * Whether the wallet needs optimization. Verbatim port of `Wallet.optimizationNeeded`
 * (`Wallet.ts:1148-1182`):
 *  1. `< OPTIMIZE_OUTPUTS (100)` unspent outputs → `isNeeded = false` (primary gate).
 *  2. Otherwise climb `threshold` by ×10 while `threshold <= balance`; for each, count
 *     buckets with `>= 100` eligible outs ({@link estimateFusionReadyness}); if that
 *     count `> OPTIMIZE_OUTPUTS / 2 (50)` → `isNeeded = true`, stop.
 *
 * Return shape matches the existing `OptimizationStatus` service type.
 */
export function isOptimizationNeeded(input: FusionStatusInput): FusionStatus {
  const { unspentOutputs, balance, blockchainHeight } = input;
  let threshold = input.threshold ?? fusionConst.OPTIMIZE_THRESHOLD;

  const unspentOutsCount = unspentOutputs.length;
  if (unspentOutsCount < fusionConst.OPTIMIZE_OUTPUTS) {
    return { isNeeded: false, unspentOutputs: unspentOutsCount };
  }

  let fusionReady = false;
  while (threshold <= balance && !fusionReady) {
    const fusionReadyCount = estimateFusionReadyness(unspentOutputs, threshold, blockchainHeight);
    if (fusionReadyCount > fusionConst.OPTIMIZE_OUTPUTS / 2) {
      fusionReady = true;
      break;
    }
    threshold = 10 * threshold;
  }

  return { isNeeded: fusionReady, unspentOutputs: unspentOutsCount };
}

// ---------------------------------------------------------------------------
// Input selection (Wallet.pickRandomFusionInputs)
// ---------------------------------------------------------------------------

/** Result of {@link selectFusionInputs}. */
export interface FusionInputSelection {
  /** Selected outputs from ONE bucket, ascending by amount, `>= minInputCount`, `<= maxInputCount`. */
  selected: SpendableOutput[];
  /** The power-of-ten bucket the inputs were drawn from. */
  bucketPowerOfTen: number;
}

/**
 * A shuffle/picker seam: given `n`, return an index in `[0, n)`. Mirrors the
 * `order`/`ShuffleGenerator` seam in `selectInputs` so tests are reproducible while the
 * live wallet shuffles. The default picks index 0 (deterministic, ascending).
 */
export type FusionShuffle = (n: number) => number;

/** Default shuffle: a uniform random index in `[0, n)` (the live-wallet behavior). */
function defaultFusionShuffle(n: number): number {
  return Math.floor(Math.random() * n);
}

/**
 * Pick fusion inputs from a SINGLE power-of-ten bucket. Verbatim port of
 * `Wallet.pickRandomFusionInputs` (`Wallet.ts:1067-1146`):
 *  1. Tally per-bucket counts of eligible pretty outputs ({@link isAmountApplicableInFusionInput}).
 *  2. Shuffle the {@link NUM_BUCKETS} bucket indices (via `shuffle`) and pick the FIRST
 *     bucket whose count `>= minInputCount`; if none, return `null`.
 *  3. Take all eligible outs in `[10^bucket, 10^(bucket+1))` (top bucket upper bound =
 *     `Number.MAX_SAFE_INTEGER`); `< minInputCount` → `null`; else sort ascending.
 *  4. If `> maxInputCount`, randomly down-sample to `maxInputCount` (via `shuffle`) then
 *     re-sort ascending.
 *
 * `maxInputCount` defaults to the size-bounded cap
 * (`getApproximateMaximumInputCount(FUSION_TX_MAX_SIZE, MAX_FUSION_OUTPUTS, DEFAULT_MIXIN)`).
 * Returns `null` when no bucket qualifies (= "nothing to optimize").
 */
export function selectFusionInputs(
  unspentOutputs: readonly SpendableOutput[],
  threshold: number,
  blockchainHeight: number,
  minInputCount: number = fusionConst.FUSION_TX_MIN_INPUT_COUNT,
  maxInputCount: number = getApproximateMaximumInputCount(
    fusionConst.FUSION_TX_MAX_SIZE,
    fusionConst.MAX_FUSION_OUTPUTS,
    DEFAULT_MIXIN,
  ),
  shuffle: FusionShuffle = defaultFusionShuffle,
): FusionInputSelection | null {
  const bucketSizes = new Array<number>(fusionConst.NUM_BUCKETS).fill(0);
  const allFusionReadyOuts: SpendableOutput[] = [];

  // First pass: collect all fusion-ready outputs and count bucket sizes.
  for (const out of unspentOutputs) {
    const result = isAmountApplicableInFusionInput(out.amount, threshold, blockchainHeight);
    if (result.applicable) {
      allFusionReadyOuts.push(out);
      const powerOfTen = result.amountPowerOfTen ?? 0;
      if (powerOfTen < fusionConst.NUM_BUCKETS) {
        bucketSizes[powerOfTen] = (bucketSizes[powerOfTen] ?? 0) + 1;
      }
    }
  }

  // Shuffle the bucket indices, then pick the first bucket with enough inputs.
  const bucketNumbers = Array.from({ length: fusionConst.NUM_BUCKETS }, (_, i) => i);
  const shuffledBucketNumbers: number[] = [];
  for (let i = 0; i < fusionConst.NUM_BUCKETS; i++) {
    const remaining = fusionConst.NUM_BUCKETS - i;
    const pickIndex = Math.min(Math.max(shuffle(remaining), 0), remaining - 1);
    const [picked] = bucketNumbers.splice(pickIndex, 1);
    shuffledBucketNumbers.push(picked as number);
  }

  const selectedBucket = shuffledBucketNumbers.find(
    (bucket) => (bucketSizes[bucket] as number) >= minInputCount,
  );
  if (selectedBucket === undefined) {
    return null;
  }

  // Calculate bounds for the selected bucket.
  let lowerBound = 1;
  for (let i = 0; i < selectedBucket; ++i) {
    lowerBound *= 10;
  }
  const upperBound =
    selectedBucket === fusionConst.NUM_BUCKETS - 1 ? Number.MAX_SAFE_INTEGER : lowerBound * 10;

  // Select outputs within bounds.
  const selectedOuts = allFusionReadyOuts.filter(
    (out) => out.amount >= lowerBound && out.amount < upperBound,
  );
  if (selectedOuts.length < minInputCount) {
    return null;
  }
  selectedOuts.sort((a, b) => a.amount - b.amount);

  // If more than maxInputCount, randomly down-sample to maxInputCount and re-sort.
  if (selectedOuts.length > maxInputCount) {
    const pool = [...selectedOuts];
    const trimmedSelectedOuts: SpendableOutput[] = [];
    for (let i = 0; i < maxInputCount; ++i) {
      const remaining = pool.length;
      const pickIndex = Math.min(Math.max(shuffle(remaining), 0), remaining - 1);
      const [picked] = pool.splice(pickIndex, 1);
      trimmedSelectedOuts.push(picked as SpendableOutput);
    }
    trimmedSelectedOuts.sort((a, b) => a.amount - b.amount);
    return { selected: trimmedSelectedOuts, bucketPowerOfTen: selectedBucket };
  }

  return { selected: selectedOuts, bucketPowerOfTen: selectedBucket };
}

// ---------------------------------------------------------------------------
// Build (Wallet.createFusionTransaction)
// ---------------------------------------------------------------------------

/** Inputs to {@link buildFusionTransaction}. */
export interface BuildFusionTransactionInput {
  /** Spending wallet keys. */
  keys: WalletKeys;
  /** The wallet's OWN decoded address — the single self-send destination. */
  selfKeys: { spendPublicKey: Hex; viewPublicKey: Hex };
  /** Inputs to consolidate (from {@link selectFusionInputs}); ALL are spent. */
  fusionInputs: SpendableOutput[];
  /** Decoy outputs (one {@link DecoySet} per input amount), as `getRandomOuts(amounts, mixin+1)`. */
  decoys: DecoySet[];
  /** Network fee, atomic; defaults to {@link MINIMUM_FEE_V2} (1000). */
  fee?: number;
  /** Ring size minus one; defaults to {@link DEFAULT_MIXIN} (5). */
  mixin?: number;
  /** Maximum outputs; defaults to {@link MAX_FUSION_OUTPUTS} (8). */
  maxOutputs?: number;
  /** Maximum serialized size, bytes; defaults to {@link FUSION_TX_MAX_SIZE} (30000). */
  maxTxSize?: number;
}

/**
 * Build a broadcast-ready, signed fusion (optimization) transaction — a thin wrapper
 * over {@link buildTransaction}. Ports `Wallet.createFusionTransaction`
 * (`Wallet.ts:1184-1290`):
 *  - ONE destination back to `selfKeys` for `Σ fusionInputs − fee` (no change output,
 *    no remote-node fee output — fusion is a pure self-consolidation).
 *  - `fusionInputs` are passed as `unspentOutputs` with the target exactly their sum
 *    minus fee and `dustThreshold: 0`, so the existing `selectInputs` picks ALL of them
 *    (no dust skipping inside the bucket). Everything downstream — decompose → outputs,
 *    ring assembly, prefix hash, ring sigs, serialize — is the unchanged
 *    {@link buildTransaction} pipeline.
 *  - SHRINK-TO-FIT loop (legacy `Wallet.ts:1222-1270`): build, compute the approximate
 *    size ({@link getApproximateTransactionSize}); while `size > maxTxSize` and inputs
 *    still `>= FUSION_TX_MIN_INPUT_COUNT`, drop the LARGEST input and rebuild.
 *  - POST-CONDITIONS (throw, legacy messages): inputs `>= 12` ("Nothing to optimize"),
 *    outputs `> 0` ("Transaction has no outputs"), outputs `<= maxOutputs`
 *    ("Maximum output count exceeded"). Threshold/inputs are gated up front.
 *
 * Broadcast + mempool refresh stay in the app layer (the SDK returns the signed
 * {@link BuiltTransaction}; the caller sends `serialized` via `daemon.sendRawTx`).
 */
export function buildFusionTransaction(input: BuildFusionTransactionInput): BuiltTransaction {
  const fee = input.fee ?? MINIMUM_FEE_V2;
  const mixin = input.mixin ?? DEFAULT_MIXIN;
  const maxOutputs = input.maxOutputs ?? fusionConst.MAX_FUSION_OUTPUTS;
  const maxTxSize = input.maxTxSize ?? fusionConst.FUSION_TX_MAX_SIZE;

  // Up-front threshold gate: a fusion at a threshold at or below dust is meaningless
  // (legacy `Wallet.ts:1193-1195`). The sum of the inputs must exceed the fee for a
  // positive self-send amount.
  // `fusionInputs` are sorted ascending so the LARGEST sits last (popped first to shrink).
  const sortedInputs = [...input.fusionInputs].sort((a, b) => a.amount - b.amount);

  // Shrink-to-fit: drop the largest input while the tx is too big and we still have
  // more than the minimum, rebuilding each round. The first round drops nothing.
  let working = sortedInputs;
  let built: BuiltTransaction | null = null;

  do {
    const inputsAmount = working.reduce((sum, out) => sum + out.amount, 0);
    const sendAmount = inputsAmount - fee;
    if (sendAmount <= 0) {
      throw new Error("Threshold is too low");
    }

    built = buildTransaction({
      keys: input.keys,
      destinations: [
        {
          spendPublicKey: input.selfKeys.spendPublicKey,
          viewPublicKey: input.selfKeys.viewPublicKey,
          amount: sendAmount,
        },
      ],
      changeKeys: input.selfKeys,
      unspentOutputs: working,
      decoys: input.decoys,
      fee,
      mixin,
      dustThreshold: 0,
    });

    const transactionSize = getApproximateTransactionSize(
      built.inputs.length,
      built.outputs.length,
      mixin,
    );

    if (transactionSize <= maxTxSize || working.length <= fusionConst.FUSION_TX_MIN_INPUT_COUNT) {
      break;
    }
    // Drop the LARGEST input (last, since `working` is ascending) and rebuild.
    working = working.slice(0, -1);
  } while (working.length >= fusionConst.FUSION_TX_MIN_INPUT_COUNT);

  // Post-conditions (legacy `Wallet.ts:1272-1280`).
  if (built === null || built.inputs.length < fusionConst.FUSION_TX_MIN_INPUT_COUNT) {
    throw new Error("Nothing to optimize");
  }
  if (built.outputs.length === 0) {
    throw new Error("Transaction has no outputs");
  }
  if (built.outputs.length > maxOutputs) {
    throw new Error("Maximum output count exceeded");
  }

  return built;
}
