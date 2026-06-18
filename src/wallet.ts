/**
 * Pure wallet STATE — the in-memory model of a CCX wallet's scanned history,
 * owned outputs, and balance. Modeled on the legacy `conceal-web-wallet`
 * `Wallet` (owned outputs + key-image-based spend tracking + transaction
 * history), but reduced to a small, fully-typed, side-effect-free core: no
 * network, no storage, no timers. The {@link ./sync} layer drives this model
 * from daemon data and persists it.
 *
 * Every mutating helper here is a pure function that returns a NEW
 * {@link WalletState}; inputs are never mutated. Balance is the sum of unspent
 * owned outputs (matching the legacy `getOutsCount`/balance model), and a spent
 * output is one whose key image has appeared in some transaction's inputs.
 */
import type { Account } from "./account";
import type { OwnedDeposit } from "./deposits";
import type { OwnedOutput } from "./transactions";

/** Direction of value flow for a {@link WalletTransaction}, from the wallet's view. */
export type TransactionDirection = "in" | "out";

/** One entry in the wallet's transaction history. */
export interface WalletTransaction {
  /** Transaction hash (hex), or a synthetic id when the daemon omitted one. */
  hash: string;
  /** Block height the transaction was mined at (0 when unknown). */
  height: number;
  /** Unix timestamp (seconds) of the block, when known. */
  timestamp?: number;
  /** Net atomic amount this transaction moved for the wallet (always positive). */
  amount: number;
  /** Whether the wallet received (`"in"`) or spent (`"out"`) in this transaction. */
  direction: TransactionDirection;
}

/** The complete, serializable state of a wallet. */
export interface WalletState {
  /** The wallet's encoded ccx7… public address. */
  address: string;
  /** Highest block height that has been fully scanned into this state. */
  scannedHeight: number;
  /** Every output the wallet owns (spent and unspent alike). */
  outputs: OwnedOutput[];
  /** Key images of outputs that have been spent (subset of `outputs` key images). */
  spentKeyImages: string[];
  /** Transaction history (storage order; {@link getTransactions} sorts it). */
  transactions: WalletTransaction[];
  /**
   * Every type-`03` deposit the wallet owns (locked + withdrawn alike). Deposit
   * principal is NOT part of {@link getBalance} spendable — it lives only here until
   * withdrawn (mirrors the legacy `Wallet.deposits` collection).
   */
  deposits: OwnedDeposit[];
  /** Global output indexes of deposits that have been withdrawn (spent). */
  spentDepositIndexes: number[];
}

/**
 * Current on-disk schema version for serialized {@link WalletState}. Bumped to `2`
 * when deposits/banking state (`deposits`, `spentDepositIndexes`) was added; a v1 blob
 * has no deposit fields and is upgraded on read by defaulting them to `[]`.
 */
export const WALLET_STATE_VERSION = 2;

/** Create a fresh, empty {@link WalletState} for `account` (nothing scanned yet). */
export function createWalletState(account: Account): WalletState {
  if (!account?.address || typeof account.address !== "string") {
    throw new Error("createWalletState requires an account with an address.");
  }
  return {
    address: account.address,
    scannedHeight: 0,
    outputs: [],
    spentKeyImages: [],
    transactions: [],
    deposits: [],
    spentDepositIndexes: [],
  };
}

/**
 * Apply one scanned transaction to the wallet state, returning a NEW state:
 *  - add any newly-owned outputs (de-duped by `publicKey` + `keyImage`),
 *  - record any of our outputs' key images that appear in `spentKeyImages` as spent,
 *  - append a {@link WalletTransaction} summarizing the net effect (received vs spent).
 *
 * Height is NOT advanced here — the {@link ./sync} layer owns `scannedHeight`.
 * The input `state`, `ownedOutputs`, and `spentKeyImages` are never mutated.
 */
export function applyScannedTransaction(
  state: WalletState,
  tx: { hash?: string; height?: number; timestamp?: number },
  ownedOutputs: readonly OwnedOutput[],
  spentKeyImages: readonly string[],
): WalletState {
  // 1. Merge newly-owned outputs, de-duped against what we already hold.
  const existingOutputKeys = new Set(state.outputs.map(outputDedupeKey));
  const addedOutputs: OwnedOutput[] = [];
  for (const output of ownedOutputs) {
    const key = outputDedupeKey(output);
    if (!existingOutputKeys.has(key)) {
      existingOutputKeys.add(key);
      addedOutputs.push(output);
    }
  }
  const nextOutputs = addedOutputs.length > 0 ? [...state.outputs, ...addedOutputs] : state.outputs;

  // 2. Detect spends: any of OUR output key images present in this tx's inputs.
  const ourKeyImages = new Set(nextOutputs.map((output) => output.keyImage));
  const alreadySpent = new Set(state.spentKeyImages);
  const newlySpent: string[] = [];
  for (const keyImage of spentKeyImages) {
    if (ourKeyImages.has(keyImage) && !alreadySpent.has(keyImage)) {
      alreadySpent.add(keyImage);
      newlySpent.push(keyImage);
    }
  }
  const nextSpentKeyImages =
    newlySpent.length > 0 ? [...state.spentKeyImages, ...newlySpent] : state.spentKeyImages;

  // 3. Summarize the transaction's net effect for the history list.
  const receivedAmount = addedOutputs.reduce((sum, output) => sum + output.amount, 0);
  const spentAmount = newlySpent.reduce((sum, keyImage) => {
    const output = nextOutputs.find((candidate) => candidate.keyImage === keyImage);
    return sum + (output ? output.amount : 0);
  }, 0);

  let nextTransactions = state.transactions;
  if (receivedAmount > 0 || spentAmount > 0) {
    // Net out (spent) wins as the direction only when it exceeds received.
    const direction: TransactionDirection = spentAmount > receivedAmount ? "out" : "in";
    const amount = Math.abs(receivedAmount - spentAmount) || receivedAmount || spentAmount;
    const entry: WalletTransaction = {
      hash: typeof tx.hash === "string" && tx.hash.length > 0 ? tx.hash : syntheticHash(state),
      height: typeof tx.height === "number" ? tx.height : 0,
      amount,
      direction,
      ...(typeof tx.timestamp === "number" ? { timestamp: tx.timestamp } : {}),
    };
    nextTransactions = [...state.transactions, entry];
  }

  // Nothing changed → return the original reference (cheap, still immutable).
  if (
    nextOutputs === state.outputs &&
    nextSpentKeyImages === state.spentKeyImages &&
    nextTransactions === state.transactions
  ) {
    return state;
  }

  return {
    ...state,
    outputs: nextOutputs,
    spentKeyImages: nextSpentKeyImages,
    transactions: nextTransactions,
  };
}

/** Balance summary: `total` and `spendable` are equal here (no locked-output model yet). */
export interface Balance {
  /** Sum of all unspent owned outputs (atomic units). */
  total: number;
  /** Sum of unspent owned outputs available to spend (atomic units). */
  spendable: number;
}

/** Sum the wallet's unspent owned outputs. */
export function getBalance(state: WalletState): Balance {
  const spent = new Set(state.spentKeyImages);
  const total = state.outputs.reduce(
    (sum, output) => (spent.has(output.keyImage) ? sum : sum + output.amount),
    0,
  );
  return { total, spendable: total };
}

/** The wallet's transaction history, newest first (by height, then storage order). */
export function getTransactions(state: WalletState): WalletTransaction[] {
  return [...state.transactions].sort((a, b) => b.height - a.height);
}

/** The wallet's currently-unspent owned outputs (spendable UTXO set). */
export function getUnspentOutputs(state: WalletState): OwnedOutput[] {
  const spent = new Set(state.spentKeyImages);
  return state.outputs.filter((output) => !spent.has(output.keyImage));
}

// ---------------------------------------------------------------------------
// Deposits / banking
// ---------------------------------------------------------------------------

/**
 * Merge scanned deposits into the wallet state and mark any withdrawn deposits spent,
 * returning a NEW state (inputs are never mutated):
 *  - add newly-owned deposits, de-duped by global output index;
 *  - record `withdrawnGlobalIndexes` (from {@link ../deposits.findWithdrawnDepositIndexes})
 *    as spent in `spentDepositIndexes`.
 *
 * Deposit principal stays OUT of {@link getBalance} spendable — it lives only in
 * `deposits` until a withdraw redeems it (the redeem output then scans in as an
 * ordinary {@link OwnedOutput}). Mirrors the legacy `Wallet.deposits` bookkeeping.
 */
export function applyScannedDeposits(
  state: WalletState,
  ownedDeposits: readonly OwnedDeposit[],
  withdrawnGlobalIndexes: readonly number[] = [],
): WalletState {
  const existingIndexes = new Set(state.deposits.map((d) => d.globalIndex));
  const addedDeposits: OwnedDeposit[] = [];
  for (const deposit of ownedDeposits) {
    if (!existingIndexes.has(deposit.globalIndex)) {
      existingIndexes.add(deposit.globalIndex);
      addedDeposits.push(deposit);
    }
  }
  const nextDeposits =
    addedDeposits.length > 0 ? [...state.deposits, ...addedDeposits] : state.deposits;

  const alreadySpent = new Set(state.spentDepositIndexes);
  const ownedGlobalIndexes = new Set(nextDeposits.map((d) => d.globalIndex));
  const newlySpent: number[] = [];
  for (const globalIndex of withdrawnGlobalIndexes) {
    if (ownedGlobalIndexes.has(globalIndex) && !alreadySpent.has(globalIndex)) {
      alreadySpent.add(globalIndex);
      newlySpent.push(globalIndex);
    }
  }
  const nextSpentDepositIndexes =
    newlySpent.length > 0
      ? [...state.spentDepositIndexes, ...newlySpent]
      : state.spentDepositIndexes;

  if (nextDeposits === state.deposits && nextSpentDepositIndexes === state.spentDepositIndexes) {
    return state;
  }
  return { ...state, deposits: nextDeposits, spentDepositIndexes: nextSpentDepositIndexes };
}

/**
 * Deposits still locked at `height` — `blockHeight + term > height` (strict, matching
 * legacy `Wallet.lockedDeposits`), excluding any already withdrawn.
 */
export function getLockedDeposits(state: WalletState, height: number): OwnedDeposit[] {
  const spent = new Set(state.spentDepositIndexes);
  return state.deposits.filter((d) => !spent.has(d.globalIndex) && d.blockHeight + d.term > height);
}

/**
 * Deposits unlocked and not yet withdrawn at `height` — `blockHeight + term <= height`
 * and not in `spentDepositIndexes` (matching legacy `Wallet.unlockedDeposits`). These
 * are the deposits a withdraw can redeem.
 */
export function getUnlockedDeposits(state: WalletState, height: number): OwnedDeposit[] {
  const spent = new Set(state.spentDepositIndexes);
  return state.deposits.filter(
    (d) => !spent.has(d.globalIndex) && d.blockHeight + d.term <= height,
  );
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/** On-disk envelope for a serialized {@link WalletState}. */
interface SerializedWalletState {
  version: number;
  state: WalletState;
}

/** Serialize a {@link WalletState} to a JSON string for persistence. */
export function serializeWalletState(state: WalletState): string {
  const envelope: SerializedWalletState = { version: WALLET_STATE_VERSION, state };
  return JSON.stringify(envelope);
}

/**
 * Parse + validate a serialized {@link WalletState}. Throws a friendly error on
 * malformed JSON, an unknown version, or a structurally-invalid payload — the SDK
 * never trusts persisted bytes blindly.
 *
 * Backward-compatible across schema versions: a v1 blob (no deposits/banking fields)
 * is upgraded on read by defaulting `deposits` / `spentDepositIndexes` to `[]`. Any
 * version above {@link WALLET_STATE_VERSION} is rejected (the SDK can't understand a
 * newer schema).
 */
export function deserializeWalletState(json: string): WalletState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("Corrupt wallet state: not valid JSON.");
  }
  if (!isRecord(parsed)) {
    throw new Error("Corrupt wallet state: expected a JSON object.");
  }
  if (typeof parsed.version !== "number" || !Number.isInteger(parsed.version)) {
    throw new Error("Corrupt wallet state: version is missing or not an integer.");
  }
  if (parsed.version < 1 || parsed.version > WALLET_STATE_VERSION) {
    throw new Error(
      `Unsupported wallet state version: ${String(parsed.version)} (expected 1..${WALLET_STATE_VERSION}).`,
    );
  }
  return validateWalletState(parsed.state);
}

/** Narrow + validate a candidate state object, throwing on any shape violation. */
function validateWalletState(value: unknown): WalletState {
  if (!isRecord(value)) {
    throw new Error("Corrupt wallet state: state is not an object.");
  }
  if (typeof value.address !== "string") {
    throw new Error("Corrupt wallet state: address is missing or not a string.");
  }
  if (typeof value.scannedHeight !== "number" || !Number.isFinite(value.scannedHeight)) {
    throw new Error("Corrupt wallet state: scannedHeight is missing or not a number.");
  }
  if (!Array.isArray(value.outputs)) {
    throw new Error("Corrupt wallet state: outputs is missing or not an array.");
  }
  if (!Array.isArray(value.spentKeyImages)) {
    throw new Error("Corrupt wallet state: spentKeyImages is missing or not an array.");
  }
  if (!Array.isArray(value.transactions)) {
    throw new Error("Corrupt wallet state: transactions is missing or not an array.");
  }
  // Deposits/banking fields were added in schema v2; a v1 blob omits them entirely, so
  // treat a missing field as the empty default (back-compat upgrade-on-read). A PRESENT
  // field must still be a valid array.
  if (value.deposits !== undefined && !Array.isArray(value.deposits)) {
    throw new Error("Corrupt wallet state: deposits is present but not an array.");
  }
  if (value.spentDepositIndexes !== undefined && !Array.isArray(value.spentDepositIndexes)) {
    throw new Error("Corrupt wallet state: spentDepositIndexes is present but not an array.");
  }
  const outputs = value.outputs.map(validateOwnedOutput);
  const spentKeyImages = value.spentKeyImages.map((keyImage, index) => {
    if (typeof keyImage !== "string") {
      throw new Error(`Corrupt wallet state: spentKeyImages[${index}] is not a string.`);
    }
    return keyImage;
  });
  const transactions = value.transactions.map(validateTransaction);
  const deposits = (value.deposits ?? []).map(validateOwnedDeposit);
  const spentDepositIndexes = (value.spentDepositIndexes ?? []).map((index, i) => {
    if (typeof index !== "number" || !Number.isInteger(index)) {
      throw new Error(`Corrupt wallet state: spentDepositIndexes[${i}] is not an integer.`);
    }
    return index;
  });
  return {
    address: value.address,
    scannedHeight: value.scannedHeight,
    outputs,
    spentKeyImages,
    transactions,
    deposits,
    spentDepositIndexes,
  };
}

/** Validate one persisted owned output. */
function validateOwnedOutput(value: unknown, index: number): OwnedOutput {
  if (!isRecord(value)) {
    throw new Error(`Corrupt wallet state: outputs[${index}] is not an object.`);
  }
  const { amount, globalIndex, outputIndex, txPublicKey, publicKey, keyImage } = value;
  if (
    typeof amount !== "number" ||
    typeof globalIndex !== "number" ||
    typeof outputIndex !== "number" ||
    typeof txPublicKey !== "string" ||
    typeof publicKey !== "string" ||
    typeof keyImage !== "string"
  ) {
    throw new Error(`Corrupt wallet state: outputs[${index}] has invalid fields.`);
  }
  return { amount, globalIndex, outputIndex, txPublicKey, publicKey, keyImage };
}

/** Validate one persisted owned deposit. */
function validateOwnedDeposit(value: unknown, index: number): OwnedDeposit {
  if (!isRecord(value)) {
    throw new Error(`Corrupt wallet state: deposits[${index}] is not an object.`);
  }
  const {
    amount,
    globalIndex,
    outputIndex,
    txPublicKey,
    publicKey,
    keys,
    term,
    blockHeight,
    txHash,
    interest,
    unlockHeight,
  } = value;
  if (
    typeof amount !== "number" ||
    typeof globalIndex !== "number" ||
    typeof outputIndex !== "number" ||
    typeof txPublicKey !== "string" ||
    typeof publicKey !== "string" ||
    !Array.isArray(keys) ||
    keys.some((k) => typeof k !== "string") ||
    typeof term !== "number" ||
    typeof blockHeight !== "number" ||
    typeof txHash !== "string" ||
    typeof interest !== "number" ||
    typeof unlockHeight !== "number"
  ) {
    throw new Error(`Corrupt wallet state: deposits[${index}] has invalid fields.`);
  }
  return {
    amount,
    globalIndex,
    outputIndex,
    txPublicKey,
    publicKey,
    keys: keys as string[],
    term,
    blockHeight,
    txHash,
    interest,
    unlockHeight,
  };
}

/** Validate one persisted transaction-history entry. */
function validateTransaction(value: unknown, index: number): WalletTransaction {
  if (!isRecord(value)) {
    throw new Error(`Corrupt wallet state: transactions[${index}] is not an object.`);
  }
  const { hash, height, amount, direction, timestamp } = value;
  if (
    typeof hash !== "string" ||
    typeof height !== "number" ||
    typeof amount !== "number" ||
    (direction !== "in" && direction !== "out")
  ) {
    throw new Error(`Corrupt wallet state: transactions[${index}] has invalid fields.`);
  }
  return {
    hash,
    height,
    amount,
    direction,
    ...(typeof timestamp === "number" ? { timestamp } : {}),
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** De-dupe key for an owned output: stable across re-scans of the same chain output. */
function outputDedupeKey(output: OwnedOutput): string {
  return `${output.publicKey}:${output.keyImage}`;
}

/** A stable-but-synthetic hash when the daemon omits one (history needs a key). */
function syntheticHash(state: WalletState): string {
  return `local-${state.transactions.length}`;
}
