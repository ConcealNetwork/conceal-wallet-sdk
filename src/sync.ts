// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Wallet SYNC orchestration — drives a {@link WalletState} forward from daemon
 * data, persisting to a {@link StorageAdapter} as it goes.
 *
 * A modern, dependency-injected reduction of the legacy `conceal-web-wallet`
 * `WalletWatchdog` sync loop: walk the chain in batches from the wallet's last
 * scanned height to the network tip, scan each transaction's outputs for the
 * account, detect spends by matching our outputs' key images against each
 * transaction's input key images, fold the result into wallet state, and
 * persist. Nothing here reaches for globals or timers by default — the daemon,
 * storage, and (optionally) the polling interval are all supplied by the caller.
 */
import type { Account } from "./account";
import type { StorageAdapter } from "./adapters";
import type { DaemonClient, DaemonRawTransaction } from "./daemon";
import { findWithdrawnDepRefs, isWithdrawShape, type RawDepositInput } from "./deposits";
import {
  type RawTransaction,
  type RawTransactionOutput,
  scanTransactionOutputsAndDeposits,
} from "./transactions";
import { canonVinType, canonVoutType, parseDaemonNum } from "./tx-shape";
import {
  applyScannedDeposits,
  applyScannedTransaction,
  createWalletState,
  deserializeWalletState,
  serializeWalletState,
  type WalletState,
} from "./wallet";

/** Default number of blocks fetched per {@link createWalletSync} sync batch. */
export const DEFAULT_BATCH_SIZE = 100;

/** Default storage key the wallet state is persisted under. */
export const DEFAULT_STORAGE_KEY = "conceal-wallet-state";

/** Configuration for {@link createWalletSync}. */
export interface SyncOptions {
  /** Typed daemon client used to fetch height + block data. */
  daemon: DaemonClient;
  /** The account whose keys scan blocks and whose address seeds fresh state. */
  account: Account;
  /** Optional persistence; when omitted, state lives only in memory. */
  storage?: StorageAdapter;
  /** Storage key for the serialized state. Defaults to {@link DEFAULT_STORAGE_KEY}. */
  storageKey?: string;
  /** Blocks fetched per batch. Defaults to {@link DEFAULT_BATCH_SIZE}. */
  batchSize?: number;
  /** Called with the new state after each sync that advances height. */
  onUpdate?: (state: WalletState) => void;
}

/** The handle returned by {@link createWalletSync}. */
export interface WalletSync {
  /** The current in-memory wallet state (always a live reference to the latest). */
  getState(): WalletState;
  /** Run one full catch-up sync to the network tip; resolves with the new state. */
  syncOnce(): Promise<WalletState>;
  /** Begin polling `syncOnce` every `intervalMs`; overlapping runs are skipped. */
  start(intervalMs: number): void;
  /** Stop the polling started by {@link start}. */
  stop(): void;
  /** Hydrate state from storage (or create fresh state when absent/empty). */
  load(): Promise<void>;
  /** Persist the current state to storage (no-op when no storage was provided). */
  save(): Promise<void>;
}

/**
 * Create a wallet-sync controller around a daemon + account (+ optional storage).
 * Pure orchestration: no timers run until {@link WalletSync.start} is called, and
 * no network I/O happens until {@link WalletSync.syncOnce} (or `start`) runs.
 */
export function createWalletSync(opts: SyncOptions): WalletSync {
  if (!opts?.daemon) {
    throw new Error("createWalletSync requires a daemon client.");
  }
  if (!opts.account) {
    throw new Error("createWalletSync requires an account.");
  }

  const { daemon, account, storage, onUpdate } = opts;
  const storageKey = opts.storageKey ?? DEFAULT_STORAGE_KEY;
  const batchSize =
    typeof opts.batchSize === "number" && opts.batchSize > 0
      ? Math.floor(opts.batchSize)
      : DEFAULT_BATCH_SIZE;

  let state: WalletState = createWalletState(account);
  let intervalId: ReturnType<typeof setInterval> | null = null;
  let inFlight = false;

  function getState(): WalletState {
    return state;
  }

  async function load(): Promise<void> {
    if (!storage) {
      state = createWalletState(account);
      return;
    }
    const raw = await storage.getItem(storageKey);
    if (raw === null || raw.length === 0) {
      state = createWalletState(account);
      return;
    }
    const restored = deserializeWalletState(raw);
    // Guard against loading another wallet's state into this account.
    if (restored.address !== account.address) {
      throw new Error("Stored wallet state belongs to a different address.");
    }
    state = restored;
  }

  async function save(): Promise<void> {
    if (!storage) return;
    await storage.setItem(storageKey, serializeWalletState(state));
  }

  /** Fetch + fold one inclusive block batch `[startBlock, endBlock]` into state. */
  async function syncBatch(startBlock: number, endBlock: number): Promise<void> {
    // `getWalletSyncData`'s range is HALF-OPEN `[start, end)` — the daemon EXCLUDES the upper
    // bound. Request `endBlock + 1` so this covers the INCLUSIVE batch `[startBlock, endBlock]`.
    // Passing `endBlock` (the prior behavior) silently dropped block `endBlock` at EVERY batch
    // boundary (100, 200, 300, …) — a tx mined into a boundary block was never scanned, so its
    // funds never appeared in the balance. `endBlock + 1` past the chain tip is safely clamped.
    const rawTransactions = await daemon.getWalletSyncData(startBlock, endBlock + 1);
    for (const rawTx of rawTransactions) {
      const scanTx = toScanTransaction(rawTx);
      if (scanTx === null) continue;

      // One ECDH scan recovers both spendable outputs and any owned deposits.
      const { outputs: ownedOutputs, deposits: ownedDeposits } = scanTransactionOutputsAndDeposits(
        scanTx,
        account.keys,
      );
      const inputKeyImages = extractInputKeyImages(rawTx.transaction);

      // A type-03 withdraw input spends a deposit by its GLOBAL output index; match
      // against the deposits we currently own (including any added in this same tx).
      const depositInputs = extractDepositInputs(rawTx.transaction);
      const candidateDeposits =
        ownedDeposits.length > 0 ? [...state.deposits, ...ownedDeposits] : state.deposits;
      const withdrawnRefs =
        depositInputs.length > 0 && isWithdrawShape(rawTx.transaction, depositInputs)
          ? findWithdrawnDepRefs(depositInputs, candidateDeposits, state.spentDepositRefs)
          : [];

      // Skip transactions that touch us in NO way — no owned output, no spent key image,
      // no owned deposit created, and no owned deposit withdrawn. A tx that ONLY creates
      // or withdraws a deposit (no type-02 output, no ring key images) still passes here.
      if (
        ownedOutputs.length === 0 &&
        inputKeyImages.length === 0 &&
        ownedDeposits.length === 0 &&
        withdrawnRefs.length === 0
      ) {
        continue;
      }

      state = applyScannedTransaction(
        state,
        { hash: scanTx.hash, height: scanTx.height, timestamp: rawTx.timestamp },
        ownedOutputs,
        inputKeyImages,
        {
          ownedDeposits,
          depositInputs,
          rawTransaction: rawTx.transaction,
          fee: rawTx.fee,
        },
      );

      // Add owned deposits and mark any withdrawn deposit spent (mirrors the legacy
      // `Wallet.deposits` bookkeeping; principal stays out of spendable balance).
      if (ownedDeposits.length > 0 || withdrawnRefs.length > 0) {
        state = applyScannedDeposits(state, ownedDeposits, withdrawnRefs);
      }
    }
  }

  async function syncOnce(): Promise<WalletState> {
    const height = await daemon.getHeight();
    const startState = state;
    let nextScannedHeight = state.scannedHeight;

    // Walk forward in batches until we reach the tip.
    while (nextScannedHeight < height) {
      const startBlock = nextScannedHeight + 1;
      const endBlock = Math.min(startBlock + batchSize - 1, height);
      await syncBatch(startBlock, endBlock);
      nextScannedHeight = endBlock;
      state = { ...state, scannedHeight: nextScannedHeight };
    }

    if (state !== startState) {
      await save();
      onUpdate?.(state);
    }
    return state;
  }

  function start(intervalMs: number): void {
    if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
      throw new Error("start(intervalMs) requires a positive interval in milliseconds.");
    }
    if (intervalId !== null) return; // already running
    intervalId = setInterval(() => {
      if (inFlight) return; // guard against overlapping runs
      inFlight = true;
      syncOnce()
        .catch(() => {
          // Swallow per-tick failures; the next tick retries. Callers that need
          // visibility into errors should call syncOnce() directly.
        })
        .finally(() => {
          inFlight = false;
        });
    }, intervalMs);
  }

  function stop(): void {
    if (intervalId !== null) {
      clearInterval(intervalId);
      intervalId = null;
    }
  }

  return { getState, syncOnce, start, stop, load, save };
}

// ---------------------------------------------------------------------------
// Daemon → scan bridge
// ---------------------------------------------------------------------------

/**
 * Convert a {@link DaemonRawTransaction} into the {@link RawTransaction} shape the
 * scanner expects, pulling `extra` + `vout` off the opaque daemon transaction and
 * attaching the block-level `outputIndexes`, `hash`, and `height`. Returns `null`
 * when the transaction has no usable `extra`/`vout` (e.g. a malformed slot).
 */
export function toScanTransaction(rawTx: DaemonRawTransaction): RawTransaction | null {
  const inner = rawTx.transaction;
  if (!isRecord(inner)) return null;

  const extra = normalizeExtra(inner.extra);
  if (extra === null) return null;

  const vout = normalizeVout(inner.vout);
  if (vout === null) return null;

  return {
    extra,
    vout,
    ...(rawTx.outputIndexes.length > 0 ? { outputIndexes: rawTx.outputIndexes } : {}),
    ...(rawTx.hash ? { hash: rawTx.hash } : {}),
    ...(typeof rawTx.height === "number" ? { height: rawTx.height } : {}),
  };
}

/**
 * Extract every input key image from a raw daemon transaction's `vin`. CryptoNote
 * inputs carry the key image either directly (`vin[i].k_image`) or nested under a
 * `value` object (`vin[i].value.k_image`), matching the legacy daemon shapes.
 * Returns lowercase-hex key images; non-key inputs (e.g. coinbase) are skipped.
 *
 * Key images are normalized to lowercase and validated as 64-char hex so a mixed
 * or uppercase `k_image` from any daemon variant still matches the wallet's own
 * lowercase key images (produced by the WASM `generate_key_image`), and a garbage
 * `vin` field cannot poison the spend-detection Set.
 */
const KEY_IMAGE_RE = /^[0-9a-f]{64}$/;

function normalizeKeyImage(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw.length === 0) return undefined;
  const normalized = raw.toLowerCase();
  return KEY_IMAGE_RE.test(normalized) ? normalized : undefined;
}

export function extractInputKeyImages(transaction: unknown): string[] {
  if (!isRecord(transaction)) return [];
  const vin = transaction.vin;
  if (!Array.isArray(vin)) return [];

  const keyImages: string[] = [];
  for (const input of vin) {
    if (!isRecord(input)) continue;
    const direct = normalizeKeyImage(input.k_image);
    if (direct !== undefined) {
      keyImages.push(direct);
      continue;
    }
    const value = input.value;
    if (isRecord(value)) {
      const nested = normalizeKeyImage(value.k_image);
      if (nested !== undefined) keyImages.push(nested);
    }
  }
  return keyImages;
}

/**
 * Extract every type-`03` deposit-spend input (`input_to_deposit_key`) from a raw
 * daemon transaction's `vin`, narrowed to the {@link RawDepositInput} shape needed for
 * withdrawal detection (`type` + `outputIndex` + `term`). CryptoNote inputs may carry
 * the fields directly (`vin[i]`) or nested under `value` (`vin[i].value`), matching the
 * daemon shapes; the type tag may be `"03"` or `"input_to_deposit_key"`. Returns `[]`
 * when the tx has no deposit inputs (the common case for regular spends).
 */
export function extractDepositInputs(transaction: unknown): RawDepositInput[] {
  if (!isRecord(transaction)) return [];
  const vin = transaction.vin;
  if (!Array.isArray(vin)) return [];

  const deposits: RawDepositInput[] = [];
  for (const input of vin) {
    if (!isRecord(input)) continue;
    const source = isRecord(input.value) ? input.value : input;
    const type = canonVinType(input.type ?? source.type);
    if (type !== "input_to_deposit_key") continue;
    const outputIndex = parseDaemonNum(source.outputIndex);
    const term = parseDaemonNum(source.term);
    const amount = parseDaemonNum(source.amount);
    deposits.push({
      type: "input_to_deposit_key",
      ...(outputIndex !== undefined ? { outputIndex } : {}),
      ...(term !== undefined ? { term } : {}),
      ...(amount !== undefined ? { amount } : {}),
    });
  }
  return deposits;
}

/** `extra` may arrive as a hex string or a byte array; normalize to hex or `null`. */
function normalizeExtra(extra: unknown): string | null {
  if (typeof extra === "string") return extra;
  if (Array.isArray(extra)) {
    let hex = "";
    for (const byte of extra) {
      if (typeof byte !== "number" || byte < 0 || byte > 255) return null;
      hex += byte.toString(16).padStart(2, "0");
    }
    return hex;
  }
  return null;
}

/** Validate the daemon `vout` array into the scanner's output shape, or `null`. */
function normalizeVout(vout: unknown): RawTransactionOutput[] | null {
  if (!Array.isArray(vout)) return null;
  const outputs: RawTransactionOutput[] = [];
  for (const out of vout) {
    if (!isRecord(out)) continue;
    const target = out.target;
    if (!isRecord(target)) continue;
    const canonType = canonVoutType(target.type);
    const data = target.data;
    if (canonType === null || !isRecord(data)) continue;

    const amount = parseDaemonNum(out.amount) ?? 0;
    const term = parseDaemonNum(data.term);
    const requiredSignatures = parseDaemonNum(data.required_signatures);

    outputs.push({
      amount,
      target: {
        type: canonType,
        data: {
          ...(typeof data.key === "string" ? { key: data.key } : {}),
          ...(Array.isArray(data.keys)
            ? { keys: data.keys.filter((k): k is string => typeof k === "string") }
            : {}),
          ...(term !== undefined ? { term } : {}),
          ...(requiredSignatures !== undefined ? { required_signatures: requiredSignatures } : {}),
        },
      },
    });
  }
  return outputs;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
