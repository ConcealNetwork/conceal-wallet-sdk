// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Transaction scanning + spend building, ported from `conceal-web-wallet`
 * (`TransactionsExplorer` scan `parse`/`ownsTx` + `Cn.createTx`/`construct_tx`)
 * and modernized onto the typed {@link ./crypto} facade. All cryptography is
 * delegated to the audited conceal-lib-js primitives (`crypto.*`, `transactions.*`,
 * `cnutils.*`) — this module only orchestrates them; it never reimplements EC math.
 *
 * Two capabilities:
 *  - SCAN: detect which outputs of a raw daemon transaction the wallet owns,
 *    recovering each owned output's amount, global index, one-time public key and
 *    spendable key image.
 *  - BUILD: assemble and serialize a signed (non-RingCT) CryptoNote spend —
 *    input selection, change/fee math, decoy-ring assembly, key images, ring
 *    signatures over the real consensus prefix hash, and the broadcast-ready blob.
 *    The byte-exact serialization, prefix hash and tx hash are produced by lib-js's
 *    mainnet-proven serializer (`transactions.serializeTransactionWithHash` /
 *    `getTransactionPrefixHash`), so {@link buildTransaction} returns a chain-accurate
 *    transaction (see {@link BuiltTransaction.serialized}).
 */
import { transactions as ccxTransactions } from "conceal-lib-js";
import {
  DEPOSIT_MAX_TERM_BLOCK,
  DEPOSIT_MIN_AMOUNT_ATOMIC,
  DEPOSIT_MIN_TERM_BLOCK,
  DEPOSIT_TX_VERSION,
} from "./constants/blockchain";
import {
  MAX_CIPHERTEXT_BYTES,
  MAX_MESSAGE_BODY_BYTES,
  TX_EXTRA_MERGE_MINING_TAG,
  TX_EXTRA_MESSAGE_TAG,
  TX_EXTRA_MYSTERIOUS_MINERGATE_TAG,
  TX_EXTRA_NONCE,
  TX_EXTRA_TAG_PADDING,
  TX_EXTRA_TAG_PUBKEY,
  TX_EXTRA_TTL,
} from "./constants/message-const";
import { DEPOSIT_SMALL_WITHDRAW_FEE, MESSAGE_TX_AMOUNT_ATOMIC } from "./constants/tx-const";
import {
  ccxCrypto,
  checkSignature,
  cnutils,
  derivePublicKey,
  deriveSecretKey,
  generateKeyDerivation,
  generateKeyImage,
  generateSignature,
} from "./crypto";
import {
  deriveDepositOneTimeKey,
  type OwnedDeposit,
  recomputeDepositInterest,
  scanDepositOutput,
} from "./deposits";
import { decryptMessage, deriveMessageKey, encryptMessage } from "./messages";
import type { Hex, WalletKeys } from "./types";

/** Re-export the shared hex alias for convenience. */
export type { Hex } from "./types";

// ---------------------------------------------------------------------------
// SCAN
// ---------------------------------------------------------------------------

/**
 * One on-chain output target. CryptoNote outputs are plaintext-amount (`vout.amount`)
 * with a `target` carrying either a single key (type `"02"`) or a tagged key set
 * (type `"03"`, e.g. deposits). Shape mirrors the daemon's `getWalletSyncData`
 * (`get_raw_transactions_by_heights`) per-output JSON.
 */
export interface RawTransactionOutput {
  /** Plaintext atomic amount carried by this output. */
  amount: number;
  target: {
    /** `"02"` = single key, `"03"` = tagged key set. */
    type: string;
    data: {
      /** Output public key for a type-`"02"` target. */
      key?: Hex;
      /** Output public keys for a type-`"03"` target. */
      keys?: Hex[];
      /** Deposit term, present on type-`"03"` deposit outputs. */
      term?: number;
      /** Required signatures, present on type-`"03"` (multisig/deposit) outputs. */
      required_signatures?: number;
    };
  };
}

/**
 * The daemon's per-transaction payload (inner `transaction` object plus the block
 * metadata the wallet needs). A minimal, scan-focused view of the legacy
 * `RawDaemon_Transaction`.
 */
export interface RawTransaction {
  /** Transaction `extra` field as hex (carries the tx public key + nonce/message tags). */
  extra: Hex;
  /** Transaction outputs. */
  vout: RawTransactionOutput[];
  /**
   * Per-output global indexes, aligned to `vout` order. When present,
   * `outputIndexes[i]` is the global chain index of `vout[i]`; otherwise the
   * in-tx index is used (legacy fallback).
   */
  outputIndexes?: number[];
  /** Transaction hash (hex), when known. */
  hash?: Hex;
  /** Block height the transaction was mined at, when known. */
  height?: number;
}

/** Keys required to scan + build: a full spend pair and view pair. */
export type ScanKeys = WalletKeys;

/** An output of {@link RawTransaction} that the scanning account owns. */
export interface OwnedOutput {
  /** Plaintext atomic amount of the output. */
  amount: number;
  /** Global chain index (or in-tx index when the tx carries no global indexes). */
  globalIndex: number;
  /** Position of the output within the transaction's `vout` array. */
  outputIndex: number;
  /** The transaction's public key (`R`, from `extra`). */
  txPublicKey: Hex;
  /** The one-time output public key (`P`) on chain. */
  publicKey: Hex;
  /** Key image proving spend authority over this output (spend-secret derived). */
  keyImage: Hex;
}

/** True for a 64-char lowercase-hex string (a 32-byte key/scalar). */
function isHex32(value: unknown): value is Hex {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

/**
 * The on-chain output key for a target, and whether `derivedKey` matches it.
 * Type `"02"` compares the single key; type `"03"` checks set membership and
 * returns the derived key as the canonical owned key (legacy `parse` behavior).
 */
function matchOutputTarget(
  output: RawTransactionOutput,
  derivedKey: Hex,
): { owned: boolean; publicKey: Hex } {
  const { type, data } = output.target;
  if (type === "02" && typeof data.key === "string") {
    return { owned: data.key === derivedKey, publicKey: data.key };
  }
  if (type === "03" && Array.isArray(data.keys)) {
    const owned = data.keys.includes(derivedKey);
    return { owned, publicKey: derivedKey };
  }
  return { owned: false, publicKey: derivedKey };
}

/**
 * Extract the transaction public key (`R`) from a tx `extra` hex, or `null` when
 * the field carries no `TX_EXTRA_TAG_PUBKEY`. Thin typed wrapper over lib-js.
 */
export function extractTransactionPublicKey(extraHex: Hex): Hex | null {
  const result = ccxTransactions.extractTxPublicKey(extraHex);
  return typeof result === "string" && result.length > 0 ? (result as Hex) : null;
}

/**
 * Detect every output of `tx` that `keys` owns, recovering amount, global index,
 * one-time public key and spendable key image for each.
 *
 * Algorithm (CryptoNote, matching legacy `TransactionsExplorer.parse`):
 *  1. `R` = tx public key from `extra`; bail if absent (nothing receivable).
 *  2. `D = generate_key_derivation(R, viewSecret)` (recipient ECDH derivation).
 *  3. For output `i`: `P' = derive_public_key(D, i, spendPublic)`; the output is
 *     owned iff `P'` equals the on-chain key (type `"02"`) or is among the keys
 *     (type `"03"`).
 *  4. Key image: `x = derive_secret_key(D, i, spendSecret)`, then
 *     `keyImage = generate_key_image(P', x)` — requires the spend secret.
 *
 * A fast `scanReceiveOutputs` pre-check (single WASM call) short-circuits txs the
 * wallet doesn't own at all. Returns `[]` for a tx with no tx public key, no
 * outputs, or no owned outputs. Throws only on structurally invalid keys.
 */
export function scanTransactionOutputs(tx: RawTransaction, keys: ScanKeys): OwnedOutput[] {
  return scanTransactionOutputsAndDeposits(tx, keys).outputs;
}

/** Owned ordinary (spendable) outputs and owned deposit outputs detected in one scan. */
export interface ScannedOutputs {
  /**
   * Owned SPENDABLE outputs only — type-`02` `txout_to_key`. Type-`03` deposit
   * outputs are NOT here (they go to {@link ScannedOutputs.deposits}), so locked
   * principal never enters the spendable balance / input selection.
   */
  outputs: OwnedOutput[];
  /** Owned type-`03` deposit outputs, with recovered term/interest/unlockHeight. */
  deposits: OwnedDeposit[];
}

/**
 * Detect every owned output of `tx` in a single ECDH scan, splitting them by kind: an
 * ordinary owned output yields an {@link OwnedOutput} (spendable, with a key image),
 * while an owned type-`03` output carrying a `term` yields an {@link OwnedDeposit}
 * (term, keys, in-vout index, interest, unlock height) — and is recorded ONLY in
 * `deposits`, never in `outputs`. This mirrors the legacy `TransactionsExplorer.parse`,
 * which keeps deposits in a separate collection and excludes type-`03` from the
 * spendable balance / input selection.
 *
 * {@link scanTransactionOutputs} is the back-compatible projection that returns only the
 * spendable `outputs`; use this when the caller also needs deposits.
 */
export function scanTransactionOutputsAndDeposits(
  tx: RawTransaction,
  keys: ScanKeys,
): ScannedOutputs {
  validateScanKeys(keys);
  if (!Array.isArray(tx.vout) || tx.vout.length === 0) {
    return { outputs: [], deposits: [] };
  }

  const txPublicKey = extractTransactionPublicKey(tx.extra);
  if (txPublicKey === null) {
    return { outputs: [], deposits: [] };
  }

  // Fast path: one WASM scan rules out the (overwhelmingly common) not-ours tx.
  const vouts = tx.vout.map((out) => ({
    type: out.target.type,
    key: out.target.data.key,
    keys: out.target.data.keys,
  }));
  if (!ccxTransactions.scanReceiveOutputs(txPublicKey, keys.view.sec, keys.spend.pub, vouts)) {
    return { outputs: [], deposits: [] };
  }

  const derivation = generateKeyDerivation(txPublicKey, keys.view.sec);
  const owned: OwnedOutput[] = [];
  const deposits: OwnedDeposit[] = [];
  const txHash = typeof tx.hash === "string" ? tx.hash : "";
  const blockHeight = typeof tx.height === "number" ? tx.height : 0;

  for (let outputIndex = 0; outputIndex < tx.vout.length; outputIndex++) {
    const output = tx.vout[outputIndex];
    if (output === undefined) continue;

    // The derivation index is the output's position in `vout` (legacy convention).
    const derivedKey = derivePublicKey(derivation, outputIndex, keys.spend.pub) as Hex;
    const { owned: isMine, publicKey } = matchOutputTarget(output, derivedKey);
    if (!isMine) continue;

    const globalIndex =
      Array.isArray(tx.outputIndexes) && typeof tx.outputIndexes[outputIndex] === "number"
        ? (tx.outputIndexes[outputIndex] as number)
        : outputIndex;

    // A type-`03` output carrying a `term` is a DEPOSIT: it is recorded in `deposits`
    // ONLY — never in `owned` — so locked principal stays out of the spendable balance
    // and can never be selected as a normal `input_to_key` spend. This mirrors the
    // legacy `availableAmount`/`formatWalletOutsForTx` which skip `type === "03"`. The
    // derived `publicKey` is the one-time deposit key (`keys[0]`); a deposit is never
    // key-imaged here (it is spent via the dedicated withdraw single-signature path).
    if (
      output.target.type === "03" &&
      Array.isArray(output.target.data.keys) &&
      typeof output.target.data.term === "number"
    ) {
      deposits.push(
        scanDepositOutput({
          amount: output.amount,
          term: output.target.data.term,
          keys: output.target.data.keys,
          publicKey,
          txPublicKey,
          outputIndex,
          globalIndex,
          blockHeight,
          txHash,
        }),
      );
      continue;
    }

    const outputSecret = deriveSecretKey(derivation, outputIndex, keys.spend.sec);
    const keyImage = generateKeyImage(publicKey, outputSecret);

    owned.push({
      amount: output.amount,
      globalIndex,
      outputIndex,
      txPublicKey,
      publicKey,
      keyImage,
    });
  }

  return { outputs: owned, deposits };
}

/** Reject malformed scan/build keys early with a clear message (fail-fast at the boundary). */
function validateScanKeys(keys: ScanKeys): void {
  if (!keys?.spend || !keys.view) {
    throw new Error("Scan requires both spend and view key pairs.");
  }
  if (!isHex32(keys.view.sec) || !isHex32(keys.spend.pub) || !isHex32(keys.spend.sec)) {
    throw new Error("Scan keys must be 64-char hex (view.sec, spend.pub, spend.sec).");
  }
}

// ---------------------------------------------------------------------------
// BUILD / SPEND
// ---------------------------------------------------------------------------

/** A spendable wallet output, as produced by {@link scanTransactionOutputs} plus its secret. */
export interface SpendableOutput {
  /** Atomic amount of the output. */
  amount: number;
  /** Global chain index of the output. */
  globalIndex: number;
  /** Position of the output within its source transaction. */
  outputIndex: number;
  /** Source transaction public key (`R`). */
  txPublicKey: Hex;
  /** One-time output public key (`P`). */
  publicKey: Hex;
  /** Key image (used to detect double-spends in selection). */
  keyImage: Hex;
}

/** A single decoy (mix-in) output for a given amount, as returned by `getrandom_outs`. */
export interface DecoyOutput {
  /** Global chain index of the decoy. */
  globalIndex: number;
  /** Decoy output public key. */
  publicKey: Hex;
}

/** Decoys grouped by the amount they can mix with. */
export interface DecoySet {
  /** The atomic amount these decoys correspond to. */
  amount: number;
  /** Candidate decoy outputs for this amount. */
  outs: DecoyOutput[];
}

/** A spend destination: a decoded recipient + atomic amount. */
export interface Destination {
  /** Recipient spend public key (hex). */
  spendPublicKey: Hex;
  /** Recipient view public key (hex). */
  viewPublicKey: Hex;
  /** Atomic amount to send. */
  amount: number;
}

/** Inputs to {@link buildTransaction}. Daemon-derived values are supplied, not fetched. */
export interface BuildTransactionInput {
  /** Spending wallet keys. */
  keys: WalletKeys;
  /** Recipient destinations (excluding change, which is added automatically). */
  destinations: Destination[];
  /** Change address — the sender's own decoded keys. */
  changeKeys: { spendPublicKey: Hex; viewPublicKey: Hex };
  /** All spendable outputs available to the wallet. */
  unspentOutputs: SpendableOutput[];
  /** Decoy outputs (one {@link DecoySet} per selected input amount). */
  decoys: DecoySet[];
  /** Network fee in atomic units. */
  fee: number;
  /** Ring size minus one (number of decoys mixed per real input). */
  mixin: number;
  /** Dust threshold; outputs at or below this are skipped during selection. */
  dustThreshold?: number;
  /**
   * Optional hook to append extra `tx_extra` records (e.g. a message + TTR) AFTER the
   * `"01" + R` tx-public-key record and BEFORE the prefix is hashed/signed, so the
   * records are part of the signed prefix (matching `Cn.ts:2266 → 2321 → 2328`). It
   * receives the freshly generated tx keypair so the caller can key an encrypted
   * message off the tx secret `r`. Return is the hex to append (no leading `0x`); an
   * empty/absent return leaves the default `"01" + R` extra byte-identical.
   */
  buildExtraRecords?: (txKeys: { secretKey: Hex; publicKey: Hex }) => Hex;
}

/** One assembled, signed input (ring member view) of a {@link BuiltTransaction}. */
export interface BuiltInput {
  /** Atomic amount of the real spent output. */
  amount: number;
  /** Key image of the real spent output. */
  keyImage: Hex;
  /** Relative ring offsets (global indexes, abs→rel encoded; ascending real position). */
  keyOffsets: number[];
  /** Ring member public keys, ascending by global index (real output mixed in). */
  ringPublicKeys: Hex[];
  /** Index of the real output within {@link ringPublicKeys}. */
  realIndex: number;
  /** Ring signature (one 128-char hex sig per ring member). */
  signatures: Hex[];
}

/** One assembled output (destination or change) of a {@link BuiltTransaction}. */
export interface BuiltOutput {
  /** Atomic amount of this output. */
  amount: number;
  /** One-time output public key derived for the recipient. */
  publicKey: Hex;
}

/** Result of {@link buildTransaction}: the structured, signed (but not yet serialized) tx. */
export interface BuiltTransaction {
  /** Transaction public key (`R = rG`). */
  txPublicKey: Hex;
  /** Transaction secret key (`r`) — needed to re-derive outputs; keep private. */
  txSecretKey: Hex;
  /** Assembled inputs, sorted by descending key image (consensus rule). */
  inputs: BuiltInput[];
  /** Assembled outputs (destinations + change), in decomposed/sorted order. */
  outputs: BuiltOutput[];
  /** Fee in atomic units. */
  fee: number;
  /** Total spent by selected inputs. */
  inputsAmount: number;
  /** Total sent to destinations (excluding change). */
  sentAmount: number;
  /** Change returned to the sender (0 when inputs match the total exactly). */
  changeAmount: number;
  /**
   * The `tx_extra` field as serialized on chain: `"01" + R` plus any records appended
   * by {@link BuildTransactionInput.buildExtraRecords} (e.g. a message / TTL). Part of
   * the signed prefix.
   */
  extra: Hex;
  /**
   * The real consensus transaction prefix hash the ring signatures were computed
   * over — `cn_fast_hash` of the header-only serialization
   * (lib-js `getTransactionPrefixHash`).
   */
  prefixHash: Hex;
  /** Broadcast-ready transaction blob (full canonical serialization, hex). */
  serialized: Hex;
  /** Transaction hash — `cn_fast_hash` of the full serialized blob. */
  hash: Hex;
}

/** A destination decomposed into a power-of-ten "digit" output for a non-RingCT tx. */
export interface DecomposedDestination {
  spendPublicKey: Hex;
  viewPublicKey: Hex;
  amount: number;
}

/**
 * Decompose each destination amount into CryptoNote power-of-ten digit outputs and
 * sort all resulting outputs ascending by amount (legacy `decompose_tx_destinations`,
 * non-RingCT branch). Zero digits are dropped. Deterministic — fully unit-tested.
 */
export function decomposeDestinations(
  destinations: readonly Destination[],
): DecomposedDestination[] {
  const out: DecomposedDestination[] = [];
  for (const dest of destinations) {
    const digits = cnutils.decompose_amount_into_digits(dest.amount);
    for (const digit of digits) {
      const amount = Number(digit.toString());
      if (amount > 0) {
        out.push({
          spendPublicKey: dest.spendPublicKey,
          viewPublicKey: dest.viewPublicKey,
          amount,
        });
      }
    }
  }
  return out.sort((a, b) => a.amount - b.amount);
}

/**
 * Convert absolute ascending global indexes to relative offsets (legacy
 * `abs_to_rel_offsets`): the first stays absolute, each subsequent becomes the
 * delta from its predecessor. Input must be sorted ascending. Deterministic.
 */
export function absoluteToRelativeOffsets(offsets: readonly number[]): number[] {
  if (offsets.length === 0) return [];
  const result = [offsets[0] as number];
  for (let i = 1; i < offsets.length; i++) {
    result.push((offsets[i] as number) - (offsets[i - 1] as number));
  }
  return result;
}

/** Result of {@link selectInputs}: chosen outputs + their running total. */
export interface InputSelection {
  /** Selected spendable outputs. */
  selected: SpendableOutput[];
  /** Sum of `selected` amounts. */
  total: number;
}

/**
 * Greedily select unspent outputs until they cover `targetAmount` (send + fee),
 * skipping dust. Deterministic given `order` (a 0..1 picker; defaults to ascending
 * so tests are reproducible — the live wallet shuffles). Throws when the wallet's
 * non-dust balance can't cover the target.
 */
export function selectInputs(
  unspentOutputs: readonly SpendableOutput[],
  targetAmount: number,
  dustThreshold = 0,
  order: (length: number) => number = () => 0,
): InputSelection {
  if (!Number.isFinite(targetAmount) || targetAmount < 0) {
    throw new Error("Target amount must be a non-negative finite number.");
  }
  const candidates = unspentOutputs.filter((out) => out.amount > dustThreshold);
  const pool = [...candidates];
  const selected: SpendableOutput[] = [];
  let total = 0;

  while (total < targetAmount && pool.length > 0) {
    const idx = Math.min(Math.floor(order(pool.length) * pool.length), pool.length - 1);
    const [picked] = pool.splice(idx, 1);
    if (picked === undefined) break;
    selected.push(picked);
    total += picked.amount;
  }

  if (total < targetAmount) {
    throw new Error(
      `Insufficient spendable balance: have ${total} (non-dust), need ${targetAmount}.`,
    );
  }
  return { selected, total };
}

/**
 * Assemble one input's ring: insert the real output among `mixin` decoys, sorted
 * ascending by global index, and report the real output's position. Decoys sharing
 * the real output's global index are skipped (legacy `construct_tx` behavior).
 * Deterministic — fully unit-tested.
 */
export function assembleRing(
  real: SpendableOutput,
  decoys: readonly DecoyOutput[],
  mixin: number,
): { ringPublicKeys: Hex[]; keyOffsets: number[]; realIndex: number } {
  const sortedDecoys = [...decoys]
    .filter((d) => d.globalIndex !== real.globalIndex)
    .sort((a, b) => a.globalIndex - b.globalIndex)
    .slice(0, mixin);

  const members = sortedDecoys.map((d) => ({ globalIndex: d.globalIndex, key: d.publicKey }));
  // Insert the real output at the position that keeps the ring sorted ascending.
  let realIndex = members.length;
  for (let i = 0; i < members.length; i++) {
    if (real.globalIndex < (members[i] as { globalIndex: number }).globalIndex) {
      realIndex = i;
      break;
    }
  }
  members.splice(realIndex, 0, { globalIndex: real.globalIndex, key: real.publicKey });

  const ringPublicKeys = members.map((m) => m.key);
  const absoluteOffsets = members.map((m) => m.globalIndex);
  const keyOffsets = absoluteToRelativeOffsets(absoluteOffsets);
  return { ringPublicKeys, keyOffsets, realIndex };
}

/**
 * Derive the per-input ephemeral secret (`x`) and key image for a spendable output,
 * using the spend secret. `x` signs the ring; the key image marks the output spent.
 * Mirrors legacy `generate_key_image_helper`.
 */
export function deriveInputKeyImage(
  output: SpendableOutput,
  keys: WalletKeys,
): { ephemeralSecret: Hex; keyImage: Hex } {
  const derivation = generateKeyDerivation(output.txPublicKey, keys.view.sec);
  const ephemeralSecret = deriveSecretKey(derivation, output.outputIndex, keys.spend.sec);
  const keyImage = generateKeyImage(output.publicKey, ephemeralSecret);
  return { ephemeralSecret, keyImage };
}

/**
 * Build a broadcast-ready signed (non-RingCT) CryptoNote spend transaction.
 *
 * Faithfully ports the legacy `createTx` → `create_transaction` → `construct_tx`
 * flow over the audited lib-js primitives:
 *  1. Validate inputs; compute total = Σ destinations + fee.
 *  2. Select non-dust inputs to cover the total; compute change.
 *  3. Generate the tx keypair `(r, R = rG)`.
 *  4. For each destination + change, derive the one-time output public key
 *     `P_out = derive_public_key(generate_key_derivation(V_dest, r), i, S_dest)`.
 *  5. For each input: derive key image, assemble its decoy ring (key offsets are
 *     RELATIVE — see below), sort inputs by descending key image (consensus).
 *  6. Build the lib-js tx structure and compute the REAL consensus prefix hash via
 *     `transactions.getTransactionPrefixHash` (`cn_fast_hash` of the header-only
 *     serialization).
 *  7. Sign each input's ring over that prefix hash via `crypto.generate_ring_signature`,
 *     attach signatures in vin order, and serialize the canonical blob +
 *     transaction hash via `transactions.serializeTransactionWithHash`.
 *
 * CONSENSUS — RELATIVE key offsets: CryptoNote serializes ring members as relative
 * offsets (first = absolute global index, rest = deltas). {@link assembleRing}
 * already returns offsets in this relative form (it applies
 * {@link absoluteToRelativeOffsets} internally), so they are passed to the
 * serializer verbatim — they must NOT be converted again. This mirrors legacy
 * `Cn.create_transaction`, which calls `abs_to_rel_offsets` once before serializing.
 *
 * The serializer is lib-js's mainnet-proven implementation, so the returned
 * `serialized` blob and `hash` are byte-exact and broadcast-ready. (A live testnet
 * broadcast is not exercised here; the byte-exact serialization via lib-js is the
 * correctness bar.)
 */
export function buildTransaction(input: BuildTransactionInput): BuiltTransaction {
  validateBuildInput(input);

  const fee = input.fee;
  const dustThreshold = input.dustThreshold ?? 0;
  const sentAmount = input.destinations.reduce((sum, d) => sum + d.amount, 0);
  const targetAmount = sentAmount + fee;

  const { selected, total: inputsAmount } = selectInputs(
    input.unspentOutputs,
    targetAmount,
    dustThreshold,
  );
  const changeAmount = inputsAmount - targetAmount;

  // Destinations (+ change as a destination back to the sender) → decomposed digits.
  const allDestinations: Destination[] = [...input.destinations];
  if (changeAmount > 0) {
    allDestinations.push({
      spendPublicKey: input.changeKeys.spendPublicKey,
      viewPublicKey: input.changeKeys.viewPublicKey,
      amount: changeAmount,
    });
  }
  const decomposed = decomposeDestinations(allDestinations);

  // Transaction keypair: r (secret) and R = rG (public, goes in extra on chain).
  const txSecretKey = ccxCrypto.sc_reduce32(randomScalarHex()) as Hex;
  const txPublicKey = ccxCrypto.ge_scalarmult_base(txSecretKey) as Hex;

  // tx_extra = TX_EXTRA_TAG_PUBKEY (0x01) + 32-byte R, then any caller-appended
  // records (message/TTL), keyed off the tx secret. Default (no hook) is byte-
  // identical to the original `"01" + R`.
  const extraRecords = input.buildExtraRecords?.({
    secretKey: txSecretKey,
    publicKey: txPublicKey,
  });
  if (
    extraRecords !== undefined &&
    (extraRecords.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(extraRecords))
  ) {
    // The hook's output is concatenated into the signed prefix — reject a
    // malformed (odd-length / non-hex) return rather than sign corrupt bytes.
    throw new Error("buildExtraRecords must return an even-length hex string.");
  }
  const extra = `01${txPublicKey}${extraRecords ?? ""}` as Hex;

  // Build outputs: one-time public key per (decomposed) destination.
  const outputs: BuiltOutput[] = decomposed.map((dest, outIndex) => {
    const outDerivation = generateKeyDerivation(dest.viewPublicKey, txSecretKey);
    const publicKey = derivePublicKey(outDerivation, outIndex, dest.spendPublicKey) as Hex;
    return { amount: dest.amount, publicKey };
  });

  // Build inputs: key image + decoy ring per selected output.
  const decoyByAmount = new Map<number, DecoyOutput[]>();
  for (const set of input.decoys) {
    decoyByAmount.set(set.amount, set.outs);
  }

  type PreInput = {
    amount: number;
    keyImage: Hex;
    ephemeralSecret: Hex;
    keyOffsets: number[];
    ringPublicKeys: Hex[];
    realIndex: number;
  };

  const preInputs: PreInput[] = selected.map((out) => {
    const { ephemeralSecret, keyImage } = deriveInputKeyImage(out, input.keys);
    const decoys = decoyByAmount.get(out.amount) ?? [];
    const { ringPublicKeys, keyOffsets, realIndex } = assembleRing(out, decoys, input.mixin);
    return { amount: out.amount, keyImage, ephemeralSecret, keyOffsets, ringPublicKeys, realIndex };
  });

  // Consensus orders inputs by descending key image.
  preInputs.sort((a, b) => (a.keyImage < b.keyImage ? 1 : a.keyImage > b.keyImage ? -1 : 0));

  // Assemble the lib-js tx structure for the REAL consensus prefix hash. The vin
  // key_offsets are passed VERBATIM: assembleRing already produced them in relative
  // form (first = absolute global index, rest = deltas), exactly what the serializer
  // encodes — converting again would corrupt the ring (legacy converts once, here).
  const struct: TxStruct = {
    version: 1,
    unlock_time: 0,
    vin: preInputs.map((pre) => ({
      type: "input_to_key",
      amount: pre.amount,
      key_offsets: pre.keyOffsets,
      k_image: pre.keyImage,
    })),
    vout: outputs.map((out) => ({
      amount: out.amount,
      target: { type: "txout_to_key", data: { key: out.publicKey } },
    })),
    // tx_extra: TX_EXTRA_TAG_PUBKEY (0x01) + the 32-byte tx public key R, plus any
    // caller-appended records (message/TTL) — part of the signed prefix.
    extra,
    signatures: [],
  };

  // Real consensus prefix hash = cn_fast_hash of the header-only serialization.
  const prefixHash = ccxTransactions.getTransactionPrefixHash(struct) as Hex;

  const inputs: BuiltInput[] = preInputs.map((pre) => {
    const signatures = ccxCrypto.generate_ring_signature(
      prefixHash,
      pre.keyImage,
      pre.ringPublicKeys,
      pre.ephemeralSecret,
      pre.realIndex,
    ) as Hex[];
    return {
      amount: pre.amount,
      keyImage: pre.keyImage,
      keyOffsets: pre.keyOffsets,
      ringPublicKeys: pre.ringPublicKeys,
      realIndex: pre.realIndex,
      signatures,
    };
  });

  // Attach signatures in vin order (== preInputs order), then serialize the
  // canonical broadcast blob + tx hash via lib-js's mainnet-proven serializer.
  const signedStruct: TxStruct = {
    ...struct,
    signatures: inputs.map((inp) => inp.signatures),
  };
  const { raw, hash } = ccxTransactions.serializeTransactionWithHash(signedStruct);

  return {
    txPublicKey,
    txSecretKey,
    inputs,
    outputs,
    fee,
    inputsAmount,
    sentAmount,
    changeAmount,
    extra,
    prefixHash,
    serialized: raw as Hex,
    hash: hash as Hex,
  };
}

/**
 * A type-`02` ring input — ordinary spend (`input_to_key`).
 */
type TxStructRingInput = {
  type: "input_to_key";
  amount: number;
  key_offsets: number[];
  k_image: Hex;
};

/**
 * A type-`03` deposit-withdraw input (`input_to_deposit_key`). The serializer
 * forces `required_signatures = 1` and reads `amount` (principal), `outputIndex`
 * (the deposit's global output index) and `term`; `signatures: 1` mirrors the
 * legacy struct but is not consulted by the serializer. No ring / no key image.
 */
type TxStructDepositInput = {
  type: "input_to_deposit_key";
  amount: number;
  term: number;
  outputIndex: number;
  signatures: 1;
};

/**
 * A type-`02` output (`txout_to_key`) — ordinary destination / change.
 */
type TxStructKeyOutput = {
  amount: number;
  target: { type: "txout_to_key"; data: { key: Hex } };
};

/**
 * A type-`03` deposit output (`txout_to_deposit_key`). Carries the single
 * one-time deposit key, `required_signatures: 1`, and the lock `term` (encoded
 * with `encode_varint_term`).
 */
type TxStructDepositOutput = {
  amount: number;
  target: {
    type: "txout_to_deposit_key";
    data: { keys: Hex[]; required_signatures: 1; term: number };
  };
};

/**
 * lib-js transaction structure consumed by the serializer (`transactions.*`).
 * Version 1 regular spends use {@link TxStructRingInput}/{@link TxStructKeyOutput};
 * version-2 deposit (lock) and withdraw (unlock) txs additionally use the type-`03`
 * deposit input/output shapes — matching the legacy `Cn.construct_tx` vin/vout union.
 */
interface TxStruct {
  version: number;
  unlock_time: number;
  vin: Array<TxStructRingInput | TxStructDepositInput>;
  vout: Array<TxStructKeyOutput | TxStructDepositOutput>;
  extra: Hex;
  signatures: Hex[][];
}

// ---------------------------------------------------------------------------
// DEPOSITS — type-03 deposit (lock) + withdraw (unlock) builders
// ---------------------------------------------------------------------------

/** Inputs to {@link buildDepositTransaction}. */
export interface BuildDepositTransactionInput {
  /** Spending wallet keys (the deposit + change go to this same wallet). */
  keys: WalletKeys;
  /** Deposit principal, atomic units (locked to a single type-`03` output). */
  amount: number;
  /** Lock term in blocks (`months * 21900`). */
  termBlocks: number;
  /** The sender's OWN decoded keys — recipient of both the deposit and the change. */
  ownKeys: { spendPublicKey: Hex; viewPublicKey: Hex };
  /** All spendable (type-`02`) outputs available to the wallet. */
  unspentOutputs: SpendableOutput[];
  /** Decoy outputs (one {@link DecoySet} per selected input amount). */
  decoys: DecoySet[];
  /** Network fee in atomic units (1000 = `coinFee`). */
  fee: number;
  /** Ring size minus one (decoys mixed per real type-`02` input). */
  mixin: number;
  /** Dust threshold; outputs at or below this are skipped during selection. */
  dustThreshold?: number;
}

/**
 * Build a broadcast-ready, signed deposit (lock) transaction — version `2`,
 * `unlock_time = 0`, one type-`03` `txout_to_deposit_key` output to the sender's OWN
 * address as `vout[0]` (NOT decomposed), optional type-`02` change, and ordinary
 * type-`02` ring inputs signed with normal ring signatures.
 *
 * Faithfully ports the deposit branch of `Cn.construct_tx` (`Cn.ts:2227-2257`):
 *  - Select non-dust type-`02` inputs to cover `amount + fee`; change = inputs − amount − fee.
 *  - Deposit output one-time key (own-address change-path derivation, out_index 0):
 *    `derive_public_key(generate_key_derivation(ownView, r), 0, ownSpend)`.
 *  - The deposit output is `vout[0]`; the change one-time key is derived at the NEXT
 *    out_index (1) — change is NOT decomposed alongside the deposit (a single change
 *    output, matching the legacy deposit path which only decomposes `dsts.slice(1)`,
 *    and here we hold exactly one change destination).
 *  - Sign each type-`02` input over the version-2 prefix hash with
 *    `generate_ring_signature` (unchanged from a regular spend).
 *  - Serialize via lib-js's mainnet-proven serializer.
 */
export function buildDepositTransaction(input: BuildDepositTransactionInput): BuiltTransaction {
  validateDepositInput(input);

  const { amount, fee, termBlocks } = input;
  const dustThreshold = input.dustThreshold ?? 0;
  const targetAmount = amount + fee;

  const { selected, total: inputsAmount } = selectInputs(
    input.unspentOutputs,
    targetAmount,
    dustThreshold,
  );
  const changeAmount = inputsAmount - targetAmount;

  // Transaction keypair: r (secret) and R = rG (public, goes in extra on chain).
  const txSecretKey = ccxCrypto.sc_reduce32(randomScalarHex()) as Hex;
  const txPublicKey = ccxCrypto.ge_scalarmult_base(txSecretKey) as Hex;
  const extra = `01${txPublicKey}` as Hex;

  // The deposit + change both go to the sender's own address, so the output derivation
  // is the change-path derivation D = generate_key_derivation(ownView, r) (Cn.ts:2214).
  const outDerivation = generateKeyDerivation(input.ownKeys.viewPublicKey, txSecretKey);

  // vout[0]: the type-03 deposit output (out_index 0). NOT decomposed.
  const depositKey = derivePublicKey(outDerivation, 0, input.ownKeys.spendPublicKey) as Hex;
  const outputs: BuiltOutput[] = [{ amount, publicKey: depositKey }];

  // vout[1]: change as an ordinary type-02 output at the NEXT out_index (Cn.ts:2241-2255).
  if (changeAmount > 0) {
    const changeKey = derivePublicKey(outDerivation, 1, input.ownKeys.spendPublicKey) as Hex;
    outputs.push({ amount: changeAmount, publicKey: changeKey });
  }

  // Build inputs: key image + decoy ring per selected (type-02) output.
  const decoyByAmount = new Map<number, DecoyOutput[]>();
  for (const set of input.decoys) {
    decoyByAmount.set(set.amount, set.outs);
  }

  type PreInput = {
    amount: number;
    keyImage: Hex;
    ephemeralSecret: Hex;
    keyOffsets: number[];
    ringPublicKeys: Hex[];
    realIndex: number;
  };

  const preInputs: PreInput[] = selected.map((out) => {
    const { ephemeralSecret, keyImage } = deriveInputKeyImage(out, input.keys);
    const decoys = decoyByAmount.get(out.amount) ?? [];
    const { ringPublicKeys, keyOffsets, realIndex } = assembleRing(out, decoys, input.mixin);
    return { amount: out.amount, keyImage, ephemeralSecret, keyOffsets, ringPublicKeys, realIndex };
  });

  // Consensus orders inputs by descending key image.
  preInputs.sort((a, b) => (a.keyImage < b.keyImage ? 1 : a.keyImage > b.keyImage ? -1 : 0));

  // version 2, unlock_time 0; vout[0] is the type-03 deposit output.
  const struct: TxStruct = {
    version: DEPOSIT_TX_VERSION,
    unlock_time: 0,
    vin: preInputs.map((pre) => ({
      type: "input_to_key",
      amount: pre.amount,
      key_offsets: pre.keyOffsets,
      k_image: pre.keyImage,
    })),
    vout: [
      {
        amount,
        target: {
          type: "txout_to_deposit_key",
          data: { keys: [depositKey], required_signatures: 1, term: termBlocks },
        },
      },
      ...outputs.slice(1).map((out) => ({
        amount: out.amount,
        target: { type: "txout_to_key" as const, data: { key: out.publicKey } },
      })),
    ],
    extra,
    signatures: [],
  };

  const prefixHash = ccxTransactions.getTransactionPrefixHash(struct) as Hex;

  const inputs: BuiltInput[] = preInputs.map((pre) => {
    const signatures = ccxCrypto.generate_ring_signature(
      prefixHash,
      pre.keyImage,
      pre.ringPublicKeys,
      pre.ephemeralSecret,
      pre.realIndex,
    ) as Hex[];
    return {
      amount: pre.amount,
      keyImage: pre.keyImage,
      keyOffsets: pre.keyOffsets,
      ringPublicKeys: pre.ringPublicKeys,
      realIndex: pre.realIndex,
      signatures,
    };
  });

  const signedStruct: TxStruct = {
    ...struct,
    signatures: inputs.map((inp) => inp.signatures),
  };
  const { raw, hash } = ccxTransactions.serializeTransactionWithHash(signedStruct);

  return {
    txPublicKey,
    txSecretKey,
    inputs,
    outputs,
    fee,
    inputsAmount,
    sentAmount: amount,
    changeAmount,
    extra,
    prefixHash,
    serialized: raw as Hex,
    hash: hash as Hex,
  };
}

/** Inputs to {@link buildWithdrawTransaction}. */
export interface BuildWithdrawTransactionInput {
  /** Wallet keys that own the deposit (needed to re-derive the ephemeral signing pair). */
  keys: WalletKeys;
  /** The owned deposit being withdrawn (from scan / wallet state). */
  deposit: OwnedDeposit;
  /** The sender's OWN decoded keys — the single redeem output goes back to self. */
  ownKeys: { spendPublicKey: Hex; viewPublicKey: Hex };
  /**
   * Withdraw fee in atomic units. Defaults to {@link DEPOSIT_SMALL_WITHDRAW_FEE} (10,
   * the legacy `config.depositSmallWithdrawFee`) — the only value the legacy wallet
   * ever uses. Overridable, but a wrong value silently burns the difference, so the
   * default is the safe choice and callers should rarely set it.
   */
  withdrawFee?: number;
}

/**
 * Build a broadcast-ready, signed withdraw (unlock) transaction — version `2`,
 * `unlock_time = 0`, exactly ONE type-`03` `input_to_deposit_key` input (no ring, no
 * decoys, mixin 0), and ONE type-`02` output to the sender's own address for
 * `principal + interest − withdrawFee`. Signed with a SINGLE `generate_signature`
 * (NOT a ring signature) over the prefix hash, verified before attaching.
 *
 * Faithfully ports `Cn.construct_tx` withdraw branches (`Cn.ts:2125-2134` vin,
 * `Cn.ts:2363-2421` single-sig) + `TransactionsExplorer.createWithdrawTx`
 * (`:1179-1231`):
 *  - vin[0] = `{ input_to_deposit_key, amount: deposit.amount (PRINCIPAL), term,
 *    outputIndex: deposit.globalIndex, signatures: 1 }` — inputs are NOT key-imaged
 *    or sorted for a withdraw.
 *  - vout[0] = type-`02` to self for `deposit.amount + deposit.interest − withdrawFee`.
 *  - Re-derive the ephemeral pair from the deposit's SOURCE tx:
 *    `D = generate_key_derivation(deposit.txPublicKey, view.sec)`,
 *    `ephPub = derive_public_key(D, deposit.outputIndex, spend.pub)`,
 *    `ephSec = derive_secret_key(D, deposit.outputIndex, spend.sec)`,
 *    `sig = generate_signature(prefixHash, ephPub, ephSec)`; verify with
 *    `check_signature`; attach `signatures = [[sig]]` (exactly one).
 *
 * The deposit's stored `interest` is re-derived from `(amount, term, blockHeight)` and
 * MUST equal the stored value — guards against tampered state setting a wrong (real-
 * money) withdrawal amount.
 */
export function buildWithdrawTransaction(input: BuildWithdrawTransactionInput): BuiltTransaction {
  validateWithdrawInput(input);

  const { deposit } = input;
  // Default to the legacy `depositSmallWithdrawFee` (10); only an explicit override differs.
  const withdrawFee = input.withdrawFee ?? DEPOSIT_SMALL_WITHDRAW_FEE;

  // Re-derive interest from first principles; refuse to sign a tampered amount.
  const interest = recomputeDepositInterest(deposit);
  if (interest !== deposit.interest) {
    throw new Error(
      `Deposit interest mismatch: stored ${deposit.interest}, recomputed ${interest}.`,
    );
  }

  // Re-derive the one-time deposit key and assert it is genuinely ours before spending.
  const expectedKey = deriveDepositOneTimeKey(deposit, input.keys);
  if (expectedKey !== deposit.publicKey) {
    throw new Error("Deposit is not spendable by these keys (one-time key mismatch).");
  }

  const redeemAmount = deposit.amount + interest - withdrawFee;
  if (!Number.isSafeInteger(redeemAmount) || redeemAmount <= 0) {
    throw new Error("Withdraw amount (principal + interest − fee) must be a positive integer.");
  }

  // Transaction keypair: r (secret) and R = rG (public, goes in extra on chain).
  const txSecretKey = ccxCrypto.sc_reduce32(randomScalarHex()) as Hex;
  const txPublicKey = ccxCrypto.ge_scalarmult_base(txSecretKey) as Hex;
  const extra = `01${txPublicKey}` as Hex;

  // The single redeem output goes back to self (own-address change-path derivation).
  const outDerivation = generateKeyDerivation(input.ownKeys.viewPublicKey, txSecretKey);
  const outKey = derivePublicKey(outDerivation, 0, input.ownKeys.spendPublicKey) as Hex;
  const outputs: BuiltOutput[] = [{ amount: redeemAmount, publicKey: outKey }];

  // version 2, unlock_time 0; single type-03 input (amount = PRINCIPAL), single type-02 output.
  const struct: TxStruct = {
    version: DEPOSIT_TX_VERSION,
    unlock_time: 0,
    vin: [
      {
        type: "input_to_deposit_key",
        amount: deposit.amount,
        term: deposit.term,
        outputIndex: deposit.globalIndex,
        signatures: 1,
      },
    ],
    vout: [{ amount: redeemAmount, target: { type: "txout_to_key", data: { key: outKey } } }],
    extra,
    signatures: [],
  };

  const prefixHash = ccxTransactions.getTransactionPrefixHash(struct) as Hex;

  // Single signature with the ephemeral pair re-derived from the deposit's SOURCE tx.
  const derivation = generateKeyDerivation(deposit.txPublicKey, input.keys.view.sec);
  const ephemeralPublicKey = derivePublicKey(
    derivation,
    deposit.outputIndex,
    input.keys.spend.pub,
  ) as Hex;
  const ephemeralSecretKey = deriveSecretKey(
    derivation,
    deposit.outputIndex,
    input.keys.spend.sec,
  ) as Hex;
  const signature = generateSignature(prefixHash, ephemeralPublicKey, ephemeralSecretKey);
  if (!checkSignature(prefixHash, ephemeralPublicKey, signature)) {
    throw new Error("Withdraw signature verification failed.");
  }

  const signedStruct: TxStruct = { ...struct, signatures: [[signature]] };
  const { raw, hash } = ccxTransactions.serializeTransactionWithHash(signedStruct);

  // The single type-03 input is reported as a BuiltInput with no ring/key image.
  const builtInput: BuiltInput = {
    amount: deposit.amount,
    keyImage: "",
    keyOffsets: [],
    ringPublicKeys: [deposit.publicKey],
    realIndex: 0,
    signatures: [signature],
  };

  return {
    txPublicKey,
    txSecretKey,
    inputs: [builtInput],
    outputs,
    fee: withdrawFee,
    inputsAmount: deposit.amount,
    sentAmount: redeemAmount,
    changeAmount: 0,
    extra,
    prefixHash,
    serialized: raw as Hex,
    hash: hash as Hex,
  };
}

/**
 * Validate deposit-build inputs at the boundary; fail fast with clear messages.
 *
 * Enforces the legacy banking constraints (`createDepositOperation` `:665-685`):
 *  - amount ≥ `depositMinAmountCoin * m_coin` (1 CCX = 1e6 atomic), a safe integer;
 *  - termBlocks is a whole-month multiple in 1..12 months — `term % 21900 === 0` and
 *    `21900 ≤ termBlocks ≤ 262800` (the only terms the V3 interest path accepts).
 */
function validateDepositInput(input: BuildDepositTransactionInput): void {
  validateScanKeys(input.keys);
  if (!isHex32(input.ownKeys.spendPublicKey) || !isHex32(input.ownKeys.viewPublicKey)) {
    throw new Error("Own keys must be 64-char hex.");
  }
  // Money fields use Number.isSafeInteger so an unsafe value never reaches the serializer.
  if (!Number.isSafeInteger(input.amount) || input.amount < DEPOSIT_MIN_AMOUNT_ATOMIC) {
    throw new Error(
      `Deposit amount must be a safe integer ≥ ${DEPOSIT_MIN_AMOUNT_ATOMIC} atomic (1 CCX).`,
    );
  }
  if (
    !Number.isSafeInteger(input.termBlocks) ||
    input.termBlocks % DEPOSIT_MIN_TERM_BLOCK !== 0 ||
    input.termBlocks < DEPOSIT_MIN_TERM_BLOCK ||
    input.termBlocks > DEPOSIT_MAX_TERM_BLOCK
  ) {
    throw new Error(
      `Deposit term must be a whole-month multiple of ${DEPOSIT_MIN_TERM_BLOCK} blocks, ` +
        `1..${DEPOSIT_MAX_TERM_BLOCK / DEPOSIT_MIN_TERM_BLOCK} months ` +
        `(${DEPOSIT_MIN_TERM_BLOCK}..${DEPOSIT_MAX_TERM_BLOCK} blocks).`,
    );
  }
  if (!Number.isSafeInteger(input.fee) || input.fee < 0) {
    throw new Error("Fee must be a non-negative safe integer (atomic units).");
  }
  if (!Number.isInteger(input.mixin) || input.mixin < 0) {
    throw new Error("Mixin must be a non-negative integer.");
  }
  if (!Array.isArray(input.unspentOutputs) || input.unspentOutputs.length === 0) {
    throw new Error("At least one unspent output is required.");
  }
}

/** Validate withdraw-build inputs at the boundary; fail fast with clear messages. */
function validateWithdrawInput(input: BuildWithdrawTransactionInput): void {
  validateScanKeys(input.keys);
  if (!isHex32(input.ownKeys.spendPublicKey) || !isHex32(input.ownKeys.viewPublicKey)) {
    throw new Error("Own keys must be 64-char hex.");
  }
  const d = input.deposit;
  // Money fields use Number.isSafeInteger: atomic amounts must stay exactly representable
  // (the CCX supply is < 2^53, but never let an unsafe value reach the consensus serializer).
  if (
    !d ||
    !Number.isSafeInteger(d.amount) ||
    d.amount <= 0 ||
    !Number.isSafeInteger(d.term) ||
    d.term <= 0 ||
    !Number.isSafeInteger(d.globalIndex) ||
    d.globalIndex < 0 ||
    !Number.isSafeInteger(d.outputIndex) ||
    d.outputIndex < 0 ||
    !isHex32(d.txPublicKey) ||
    !isHex32(d.publicKey) ||
    !Number.isSafeInteger(d.interest) ||
    d.interest < 0
  ) {
    throw new Error("Withdraw requires a well-formed owned deposit.");
  }
  if (
    input.withdrawFee !== undefined &&
    (!Number.isSafeInteger(input.withdrawFee) || input.withdrawFee < 0)
  ) {
    throw new Error("Withdraw fee must be a non-negative safe integer (atomic units).");
  }
}

/** Validate build inputs at the boundary; fail fast with clear messages. */
function validateBuildInput(input: BuildTransactionInput): void {
  validateScanKeys(input.keys);
  if (!Array.isArray(input.destinations) || input.destinations.length === 0) {
    throw new Error("At least one destination is required.");
  }
  for (const dest of input.destinations) {
    if (!isHex32(dest.spendPublicKey) || !isHex32(dest.viewPublicKey)) {
      throw new Error("Destination keys must be 64-char hex.");
    }
    if (!Number.isInteger(dest.amount) || dest.amount <= 0) {
      throw new Error("Destination amount must be a positive integer (atomic units).");
    }
  }
  if (!isHex32(input.changeKeys.spendPublicKey) || !isHex32(input.changeKeys.viewPublicKey)) {
    throw new Error("Change keys must be 64-char hex.");
  }
  if (!Number.isInteger(input.fee) || input.fee < 0) {
    throw new Error("Fee must be a non-negative integer (atomic units).");
  }
  if (!Number.isInteger(input.mixin) || input.mixin < 0) {
    throw new Error("Mixin must be a non-negative integer.");
  }
  if (!Array.isArray(input.unspentOutputs) || input.unspentOutputs.length === 0) {
    throw new Error("At least one unspent output is required.");
  }
}

/** 32 bytes of CSPRNG entropy as hex (Web Crypto; Node 20+ and browsers). */
function randomScalarHex(): Hex {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex as Hex;
}

// ---------------------------------------------------------------------------
// MESSAGE TRANSACTIONS — tx_extra framing, TTL, scan-time extraction
// ---------------------------------------------------------------------------

const MSB = 0x80;
const REST = 0x7f;
const TWO_POWER_SEVEN = 2 ** 7;

/**
 * Decode a single LEB128-style varint from `buf` starting at `offset`, returning the
 * decoded number. Ported verbatim from the legacy `Varint.decode` (`Varint.ts:53-73`)
 * so TTL values decode exactly as the wallet decodes them. Throws on an unterminated
 * varint.
 */
function decodeVarint(buf: ArrayLike<number>, offset = 0): number {
  let res = 0;
  let shift = 1;
  let counter = offset;
  let b: number;
  const l = TWO_POWER_SEVEN ** (buf.length - offset < 8 ? (buf.length - offset) * 7 : 49);

  do {
    if (shift > l || counter >= buf.length) {
      // Past the buffer end (unterminated) or beyond the safe magnitude bound.
      throw new RangeError("Could not decode varint (unterminated or too large)");
    }
    b = buf[counter++] as number;
    res += (b & REST) * shift;
    shift = shift * TWO_POWER_SEVEN;
  } while (b >= MSB);

  return res;
}

/** A hex string's byte length (two hex chars per byte). */
function hexByteLength(hex: Hex): number {
  return hex.length / 2;
}

/** One byte (00–ff) as two lowercase hex chars. */
function byteToHex(value: number): Hex {
  return `0${value.toString(16)}`.slice(-2) as Hex;
}

/**
 * Encode a `0x04` message record: `"04" + 1-byte-len + ciphertext`. The single-byte
 * length field caps the ciphertext at {@link MAX_CIPHERTEXT_BYTES} (255) bytes —
 * anything larger would frame a corrupt, undecryptable record on-chain, so throw
 * (matching `Cn.ts:2302-2304`).
 */
export function encodeMessageExtra(ciphertextHex: Hex): Hex {
  const byteLength = hexByteLength(ciphertextHex);
  if (!Number.isInteger(byteLength)) {
    throw new Error("Ciphertext hex must have an even length.");
  }
  if (byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new Error(
      `Encrypted message too long: ${byteLength} bytes (max ${MAX_CIPHERTEXT_BYTES}).`,
    );
  }
  return `${byteToHex(TX_EXTRA_MESSAGE_TAG)}${byteToHex(byteLength)}${ciphertextHex}` as Hex;
}

/**
 * Encode a `0x05` TTL record: `"05" + varint(byteLenOfValueVarint) + varint(ttlUnixSeconds)`.
 * The TTL value is an absolute Unix expiry timestamp in seconds (not a duration).
 * Mirrors `Cn.ts:2329-2331`. Throws for a non-positive/invalid TTL (use `0`/omit for
 * "no TTL" — `encodeTtlExtra` is only called when a TTL applies).
 */
export function encodeTtlExtra(ttlUnixSeconds: number): Hex {
  if (!Number.isInteger(ttlUnixSeconds) || ttlUnixSeconds <= 0) {
    throw new Error("TTL must be a positive integer Unix timestamp (seconds).");
  }
  const ttlStr = cnutils.encode_varint(ttlUnixSeconds) as Hex;
  const ttlSize = cnutils.encode_varint(hexByteLength(ttlStr)) as Hex;
  return `${byteToHex(TX_EXTRA_TTL)}${ttlSize}${ttlStr}` as Hex;
}

/** A parsed `0x04` message + `0x05` TTL pair pulled out of a tx `extra`. */
export interface ScannedMessage {
  /** Raw `0x04` record payload (the encrypted message), as hex. */
  ciphertextHex: Hex;
  /** Absolute Unix expiry seconds from the `0x05` record, or `0` when there is none. */
  ttlUnixSeconds: number;
}

/**
 * Walk a tx `extra` hex and pull out the `0x04` encrypted-message payload and the
 * `0x05` TTL, returning `null` when no message record is present. The walk mirrors the
 * legacy `TransactionsExplorer.parseExtra` (`:129-179`): `0x01` is a fixed 32-byte
 * pubkey with no size byte; `0x02`/`0x03`/`0x04`/`0x05`/`0xde` carry a size byte; `0x00`
 * is padding (terminates the walk). TTL is decoded with the ported {@link decodeVarint}.
 */
export function extractMessageFromExtra(extraHex: Hex): ScannedMessage | null {
  if (
    typeof extraHex !== "string" ||
    extraHex.length === 0 ||
    extraHex.length % 2 !== 0 ||
    !/^[0-9a-fA-F]+$/.test(extraHex)
  ) {
    // Reject non-hex / odd-length up front so malformed daemon data can't
    // propagate NaN bytes into the parse (returns null, never throws).
    return null;
  }
  const bytes: number[] = [];
  for (let i = 0; i < extraHex.length; i += 2) {
    bytes.push(Number.parseInt(extraHex.slice(i, i + 2), 16));
  }

  let ciphertextHex: Hex | null = null;
  let ttlUnixSeconds = 0;
  let offset = 0;

  while (offset < bytes.length) {
    const tag = bytes[offset] as number;

    if (tag === TX_EXTRA_TAG_PADDING) {
      // Padding is a zero-run that runs to the end; nothing more to read.
      break;
    }

    let dataSize: number;
    let dataStart: number;
    if (tag === TX_EXTRA_TAG_PUBKEY) {
      dataSize = 32;
      dataStart = offset + 1;
    } else if (
      tag === TX_EXTRA_NONCE ||
      tag === TX_EXTRA_MERGE_MINING_TAG ||
      tag === TX_EXTRA_MESSAGE_TAG ||
      tag === TX_EXTRA_TTL ||
      tag === TX_EXTRA_MYSTERIOUS_MINERGATE_TAG
    ) {
      dataSize = bytes[offset + 1] as number;
      dataStart = offset + 2;
    } else {
      // Unknown tag — stop rather than guess (matches the legacy bail-out).
      break;
    }

    const dataEnd = dataStart + dataSize;
    if (!Number.isInteger(dataSize) || dataEnd > bytes.length) {
      // Truncated/corrupt record — stop the walk.
      break;
    }
    const data = bytes.slice(dataStart, dataEnd);

    if (tag === TX_EXTRA_MESSAGE_TAG) {
      // First message record wins (a CCX message tx carries exactly one).
      if (ciphertextHex === null) {
        ciphertextHex = data.map((byte) => byteToHex(byte)).join("") as Hex;
      }
    } else if (tag === TX_EXTRA_TTL && data.length > 0) {
      // A corrupt TTL varint must not abort scanning — stop the walk and keep
      // whatever was parsed so far rather than throwing.
      try {
        ttlUnixSeconds = decodeVarint(data);
      } catch {
        break;
      }
    }

    offset = dataEnd;
  }

  if (ciphertextHex === null) return null;
  return { ciphertextHex, ttlUnixSeconds };
}

/** Inputs to {@link buildMessageTransaction}. */
export interface BuildMessageTransactionInput {
  /** Spending wallet keys (the tx message key is derived from the generated tx secret). */
  keys: WalletKeys;
  /** Message recipient (also the `MESSAGE_TX_AMOUNT_ATOMIC` self-output destination). */
  recipient: { spendPublicKey: Hex; viewPublicKey: Hex };
  /** Message body, ≤{@link MAX_MESSAGE_BODY_BYTES} (251) UTF-8 bytes (validated). */
  body: string;
  /** Change address — the sender's own decoded keys. */
  changeKeys: { spendPublicKey: Hex; viewPublicKey: Hex };
  /** All spendable outputs available to the wallet. */
  unspentOutputs: SpendableOutput[];
  /** Decoy outputs (one {@link DecoySet} per selected input amount). */
  decoys: DecoySet[];
  /** Network fee in atomic units (folded into change when `ttlUnixSeconds > 0`). */
  fee: number;
  /** Ring size minus one (decoys mixed per real input). */
  mixin: number;
  /** Absolute Unix expiry seconds; `0`/undefined = no TTL (a mined message). */
  ttlUnixSeconds?: number;
  /** Remote-node fee destination, appended only when there is no TTL. */
  nodeFee?: { spendPublicKey: Hex; viewPublicKey: Hex; amount: number } | null;
  /** Recipient self-output amount; defaults to {@link MESSAGE_TX_AMOUNT_ATOMIC} (100). */
  messageAmount?: number;
  /** Dust threshold; outputs at or below this are skipped during selection. */
  dustThreshold?: number;
}

/**
 * Build a broadcast-ready message-bearing transaction.
 *
 * A message tx is an ordinary CryptoNote spend with three conventions
 * (`messages.md` §1, `wallet-operations.ts:477-617`):
 *  - the recipient gets a tiny fixed self-output (`messageAmount`, default
 *    {@link MESSAGE_TX_AMOUNT_ATOMIC} = 100 atomic) so their wallet scans + owns it;
 *  - the encrypted body rides `tx_extra` as a `0x04` record, keyed off the tx's OWN
 *    secret `r` via `deriveMessageKey(recipient.spendPublicKey, r)` — so the key is the
 *    same one the recipient recovers from `(R, theirSpendSecret)`; the record is part
 *    of the signed prefix;
 *  - TTL (`ttlUnixSeconds > 0`) makes it a mempool-only message: a `0x05` TTL record is
 *    appended, NO node-fee destination is added, and the fee is folded into change
 *    (built with `fee: 0`) so the output total alone covers inputs — mirroring
 *    `Cn.ts:2334-2337` and `TransactionsExplorer.ts:1061-1063`.
 *
 * Reuses {@link buildTransaction}'s selection/ring/sign machinery via the
 * `buildExtraRecords` hook; only the destinations, fee rule, and extra records differ.
 */
export function buildMessageTransaction(input: BuildMessageTransactionInput): BuiltTransaction {
  const bodyByteLength = new TextEncoder().encode(input.body).length;
  if (bodyByteLength > MAX_MESSAGE_BODY_BYTES) {
    throw new Error(
      `Message body too long: ${bodyByteLength} UTF-8 bytes (max ${MAX_MESSAGE_BODY_BYTES}).`,
    );
  }

  const ttlUnixSeconds = input.ttlUnixSeconds ?? 0;
  const hasTtl = ttlUnixSeconds > 0;
  const messageAmount = input.messageAmount ?? MESSAGE_TX_AMOUNT_ATOMIC;

  // Recipient self-output marks the tx as a message. A node-fee destination is added
  // only for a non-TTL (mined) message — a TTL message carries no node fee.
  const destinations: Destination[] = [
    {
      spendPublicKey: input.recipient.spendPublicKey,
      viewPublicKey: input.recipient.viewPublicKey,
      amount: messageAmount,
    },
  ];
  if (!hasTtl && input.nodeFee) {
    destinations.push({
      spendPublicKey: input.nodeFee.spendPublicKey,
      viewPublicKey: input.nodeFee.viewPublicKey,
      amount: input.nodeFee.amount,
    });
  }

  // TTL message: the fee is folded into change. buildTransaction's change math is
  // `inputs − (Σ destinations + fee)`, so building with `fee: 0` leaves the would-be
  // fee in change and relaxes the balance check to outputs ≤ inputs (Cn.ts:2334-2337,
  // TransactionsExplorer.ts:1061-1063). The reported `fee` on the result is preserved.
  const buildFee = hasTtl ? 0 : input.fee;

  const built = buildTransaction({
    keys: input.keys,
    destinations,
    changeKeys: input.changeKeys,
    unspentOutputs: input.unspentOutputs,
    decoys: input.decoys,
    fee: buildFee,
    mixin: input.mixin,
    dustThreshold: input.dustThreshold,
    buildExtraRecords: ({ secretKey }) => {
      const key = deriveMessageKey(input.recipient.spendPublicKey, secretKey);
      const ciphertextHex = encryptMessage(input.body, key, 0);
      const messageRecord = encodeMessageExtra(ciphertextHex);
      return (hasTtl ? `${messageRecord}${encodeTtlExtra(ttlUnixSeconds)}` : messageRecord) as Hex;
    },
  });

  // Report the fee that was actually signed: 0 for a TTL message (folded into
  // change, so sent+change+fee === inputs holds) or input.fee otherwise. Do NOT
  // override with input.fee for TTL — that would break the accounting invariant.
  return built;
}

/**
 * Scan + decrypt a message-bearing transaction in one call.
 *
 * Extracts the `0x04`/`0x05` records ({@link extractMessageFromExtra}), derives the
 * message key from the tx public key `R` (from the `0x01` record) and the recipient's
 * SPEND secret (`deriveMessageKey(R, keys.spend.sec)`), and decrypts the body. Owned
 * outputs come from {@link scanTransactionOutputs}. Returns `null` when the tx carries
 * no message record. `body` is `null` when the tx is a message but cannot be decrypted
 * (wrong recipient, or a view-only key set with no usable spend secret).
 */
export function readMessageFromTransaction(
  tx: RawTransaction,
  keys: WalletKeys,
): { body: string | null; ttlUnixSeconds: number; owned: OwnedOutput[] } | null {
  const message = extractMessageFromExtra(tx.extra);
  if (message === null) return null;

  const txPublicKey = extractTransactionPublicKey(tx.extra);
  const owned = scanTransactionOutputs(tx, keys);

  let body: string | null = null;
  if (txPublicKey !== null && isHex32(keys.spend?.sec)) {
    try {
      const key = deriveMessageKey(txPublicKey, keys.spend.sec);
      body = decryptMessage(message.ciphertextHex, key, 0);
    } catch {
      // Malformed / wrongly-keyed message record — surface as no body rather than
      // crashing the scan (matches legacy TransactionsExplorer.ts:766 try/catch).
      body = null;
    }
  }

  return { body, ttlUnixSeconds: message.ttlUnixSeconds, owned };
}
