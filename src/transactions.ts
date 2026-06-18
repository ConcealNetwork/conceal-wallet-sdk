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
  ccxCrypto,
  cnutils,
  derivePublicKey,
  deriveSecretKey,
  generateKeyDerivation,
  generateKeyImage,
} from "./crypto";
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
  validateScanKeys(keys);
  if (!Array.isArray(tx.vout) || tx.vout.length === 0) {
    return [];
  }

  const txPublicKey = extractTransactionPublicKey(tx.extra);
  if (txPublicKey === null) {
    return [];
  }

  // Fast path: one WASM scan rules out the (overwhelmingly common) not-ours tx.
  const vouts = tx.vout.map((out) => ({
    type: out.target.type,
    key: out.target.data.key,
    keys: out.target.data.keys,
  }));
  if (!ccxTransactions.scanReceiveOutputs(txPublicKey, keys.view.sec, keys.spend.pub, vouts)) {
    return [];
  }

  const derivation = generateKeyDerivation(txPublicKey, keys.view.sec);
  const owned: OwnedOutput[] = [];

  for (let outputIndex = 0; outputIndex < tx.vout.length; outputIndex++) {
    const output = tx.vout[outputIndex];
    if (output === undefined) continue;

    // The derivation index is the output's position in `vout` (legacy convention).
    const derivedKey = derivePublicKey(derivation, outputIndex, keys.spend.pub) as Hex;
    const { owned: isMine, publicKey } = matchOutputTarget(output, derivedKey);
    if (!isMine) continue;

    const outputSecret = deriveSecretKey(derivation, outputIndex, keys.spend.sec);
    const keyImage = generateKeyImage(publicKey, outputSecret);

    const globalIndex =
      Array.isArray(tx.outputIndexes) && typeof tx.outputIndexes[outputIndex] === "number"
        ? (tx.outputIndexes[outputIndex] as number)
        : outputIndex;

    owned.push({
      amount: output.amount,
      globalIndex,
      outputIndex,
      txPublicKey,
      publicKey,
      keyImage,
    });
  }

  return owned;
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
    // tx_extra: TX_EXTRA_TAG_PUBKEY (0x01) followed by the 32-byte tx public key R.
    extra: `01${txPublicKey}`,
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
    prefixHash,
    serialized: raw as Hex,
    hash: hash as Hex,
  };
}

/** lib-js transaction structure consumed by the serializer (`transactions.*`). */
interface TxStruct {
  version: number;
  unlock_time: number;
  vin: Array<{ type: "input_to_key"; amount: number; key_offsets: number[]; k_image: Hex }>;
  vout: Array<{ amount: number; target: { type: "txout_to_key"; data: { key: Hex } } }>;
  extra: Hex;
  signatures: Hex[][];
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

