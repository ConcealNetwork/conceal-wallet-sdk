// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Durable outbound transaction queue — a crash-safe relay buffer between tx
 * construction ({@link ./transactions.buildTransaction}) and broadcast
 * ({@link ./daemon.DaemonClient.sendRawTransaction}).
 *
 * Each built spend is persisted (one JSON entry per tx, keyed by its hash so
 * re-enqueue is idempotent and there are no random ids) and then drained in
 * timestamp order against the daemon. Rejections (the chain refuses the tx —
 * double-spend / already-spent key image) fail the entry permanently; transient
 * errors are retried on subsequent drains until an optional attempt cap fires.
 *
 * While an entry is `pending` or `broadcast` it RESERVES its input key images —
 * the host feeds {@link reservedKeyImages} into input selection so a queued
 * output is never re-spent (the enqueue-time check here is only a backstop).
 *
 * Mirrors the {@link ./sync.createWalletSync} lifecycle: pure orchestration, no
 * timers until {@link start}, no I/O until {@link drainOnce} (or `start`) runs.
 */
import { createNamespacedStorage, type StorageAdapter } from "./adapters";
import type { DaemonClient } from "./daemon";
import type { BuiltTransaction } from "./transactions";
import type { Hex } from "./types";

/** Namespace prefix the queue's keys live under in the supplied storage. */
export const OUTBOUND_QUEUE_NAMESPACE = "outbox";

/** Lifecycle state of a queued broadcast. */
export type OutboundQueueState = "pending" | "broadcast" | "failed";

/** Why a queued broadcast transitioned to `"failed"`. */
export type OutboundQueueFailReason = "rejected" | "expired" | "conflict";

/** One persisted queue entry: a built transaction awaiting (or done) broadcast. */
export interface OutboundQueueEntry {
  /** Queue id — equal to {@link hash}; stable, deterministic (no random ids). */
  id: Hex;
  /** Transaction hash (hex); the broadcast blob's canonical id on chain. */
  hash: Hex;
  /** Broadcast-ready serialized transaction blob (hex). */
  serialized: Hex;
  /** Key images of the tx's inputs, used to reserve outputs against re-spend. */
  keyImages: Hex[];
  /** Wall-clock ms (per the injected clock) when the entry was enqueued. */
  enqueuedAt: number;
  /** Don't broadcast before this ms timestamp (per the injected clock). */
  notBefore?: number;
  /** Optional human-readable label for the entry (e.g. "send to Alice"). */
  label?: string;
  /** Absolute unix-seconds deadline; once passed the entry expires (fails). */
  ttlUnixSeconds?: number;
  /** Current lifecycle state. */
  state: OutboundQueueState;
  /** Number of transient-error attempts so far (resets on success). */
  attempts: number;
  /** Last error message from a failed/attempted broadcast, if any. */
  lastError?: string;
  /** Present once `state === "failed"`, describing why. */
  failedReason?: OutboundQueueFailReason;
}

/** Per-entry outcome of a {@link OutboundQueue.drainOnce} pass. */
export interface OutboundQueueResult {
  /** Id of the entry this result describes. */
  id: Hex;
  /** Hash of the entry this result describes. */
  hash: Hex;
  /** Resulting lifecycle state after this drain pass. */
  state: OutboundQueueState;
  /** Error message when the broadcast failed or could not complete. */
  error?: string;
}

/** Per-enqueue overrides supplied to {@link OutboundQueue.enqueue}. */
export interface EnqueueOptions {
  /** Don't broadcast before this ms timestamp (per the injected clock). */
  notBefore?: number;
  /** Optional human-readable label for the entry. */
  label?: string;
  /** Absolute unix-seconds deadline; once passed the entry expires (fails). */
  ttlUnixSeconds?: number;
}

/** Configuration for {@link createOutboundQueue}. */
export interface OutboundQueueOptions {
  /** Persistence (namespaced under {@link OUTBOUND_QUEUE_NAMESPACE}). */
  storage: StorageAdapter;
  /** Daemon client (or stub) used to broadcast. */
  daemon: Pick<DaemonClient, "sendRawTransaction">;
  /** Injected clock (ms); defaults to `Date.now`. Useful for deterministic tests. */
  clock?: () => number;
  /** Cap on transient-error attempts; once hit the entry fails as `"rejected"`. */
  maxAttempts?: number;
  /** Age cap (ms); an entry older than this on a drain expires (fails). */
  maxAgeMs?: number;
}

/** The handle returned by {@link createOutboundQueue}. */
export interface OutboundQueue {
  /**
   * Persist a built transaction for broadcast. Idempotent on hash (re-enqueue of
   * the same tx returns the existing id). Throws when any input key image is
   * already reserved by a non-failed entry (backstop double-spend guard).
   */
  enqueue(built: BuiltTransaction, opts?: EnqueueOptions): Promise<Hex>;
  /** Every key image held by a `pending`/`broadcast` entry (feed into selection). */
  reservedKeyImages(): Promise<Set<Hex>>;
  /**
   * Broadcast all due `pending` entries in ascending enqueue order, handling
   * expiry, rejection, and transient retries. A failure never stops the rest of
   * the drain. Returns one result per processed (due or expired) entry.
   */
  drainOnce(): Promise<OutboundQueueResult[]>;
  /** Begin polling {@link drainOnce} every `intervalMs`; overlapping runs skipped. */
  start(intervalMs: number): void;
  /** Stop the polling started by {@link start}. */
  stop(): void;
  /** All entries (parse-safe; malformed values are ignored). */
  list(): Promise<OutboundQueueEntry[]>;
  /**
   * Remove a PENDING entry (frees its reserved inputs). Returns `false` when the
   * entry is absent or not pending (an already-broadcast tx cannot be cancelled).
   */
  cancel(id: string): Promise<boolean>;
  /** Delete any entry outright (the app calls this once a broadcast has mined). */
  remove(id: string): Promise<void>;
}

/**
 * Create an outbound queue controller around a storage adapter + daemon client.
 * Pure orchestration: nothing is read or written until a method is called.
 */
export function createOutboundQueue(opts: OutboundQueueOptions): OutboundQueue {
  if (!opts?.storage) {
    throw new Error("createOutboundQueue requires a storage adapter.");
  }
  if (!opts?.daemon) {
    throw new Error("createOutboundQueue requires a daemon client.");
  }

  const storage = createNamespacedStorage(opts.storage, OUTBOUND_QUEUE_NAMESPACE);
  const daemon = opts.daemon;
  const clock = opts.clock ?? (() => Date.now());
  const maxAttempts = opts.maxAttempts;
  const maxAgeMs = opts.maxAgeMs;

  let intervalId: ReturnType<typeof setInterval> | null = null;
  let inFlight = false;

  /** Load + parse every entry under the namespace (malformed values skipped). */
  async function loadAll(): Promise<OutboundQueueEntry[]> {
    const keys = await storage.keys();
    const entries: OutboundQueueEntry[] = [];
    for (const key of keys) {
      const raw = await storage.getItem(key);
      if (raw === null) continue;
      const entry = parseEntry(raw);
      if (entry !== null) entries.push(entry);
    }
    return entries;
  }

  /** Persist (overwrite) an entry under its id. */
  async function persist(entry: OutboundQueueEntry): Promise<void> {
    await storage.setItem(entry.id, JSON.stringify(entry));
  }

  async function enqueue(built: BuiltTransaction, callOpts?: EnqueueOptions): Promise<Hex> {
    const keyImages = built.inputs.map((input) => input.keyImage);

    // Dedupe FIRST: re-enqueuing the same (hash) tx is a no-op idempotent return,
    // not a double-reserve throw — so the reservation backstop never fires on a
    // legitimate retry of the exact same built tx.
    const existingRaw = await storage.getItem(built.hash);
    if (existingRaw !== null) {
      const existing = parseEntry(existingRaw);
      if (existing !== null) {
        return existing.id;
      }
    }

    // Backstop double-spend prevention: refuse to queue a tx whose inputs are
    // already reserved by a pending|broadcast entry. The real prevention is the
    // host feeding reservedKeyImages() into input selection; this guards a miss.
    if (keyImages.length > 0) {
      const reserved = await reservedKeyImages();
      for (const ki of keyImages) {
        if (reserved.has(ki)) {
          throw new Error("Outbound queue: input already reserved by a pending transaction.");
        }
      }
    }

    const entry: OutboundQueueEntry = {
      id: built.hash,
      hash: built.hash,
      serialized: built.serialized,
      keyImages,
      enqueuedAt: clock(),
      ...(callOpts?.notBefore !== undefined ? { notBefore: callOpts.notBefore } : {}),
      ...(callOpts?.label !== undefined ? { label: callOpts.label } : {}),
      ...(callOpts?.ttlUnixSeconds !== undefined
        ? { ttlUnixSeconds: callOpts.ttlUnixSeconds }
        : {}),
      state: "pending",
      attempts: 0,
    };
    await persist(entry);
    return entry.id;
  }

  async function reservedKeyImages(): Promise<Set<Hex>> {
    const entries = await loadAll();
    const reserved = new Set<Hex>();
    for (const entry of entries) {
      if (entry.state === "pending" || entry.state === "broadcast") {
        for (const ki of entry.keyImages) {
          reserved.add(ki);
        }
      }
    }
    return reserved;
  }

  async function drainOnce(): Promise<OutboundQueueResult[]> {
    const now = clock();
    const entries = await loadAll();

    // Only due pending entries are candidates; sort ASC by enqueue time so the
    // oldest spend relays first (predictable ordering for double-spend races).
    const candidates = entries
      .filter((e) => e.state === "pending" && (e.notBefore === undefined || e.notBefore <= now))
      .sort((a, b) => a.enqueuedAt - b.enqueuedAt);

    const results: OutboundQueueResult[] = [];

    for (const entry of candidates) {
      // Expiry: age-based (maxAgeMs) OR absolute deadline (ttlUnixSeconds). Fail
      // the entry without ever broadcasting; an expired spend's inputs are freed.
      const expiredByAge = maxAgeMs !== undefined && now - entry.enqueuedAt > maxAgeMs;
      const expiredByTtl =
        entry.ttlUnixSeconds !== undefined &&
        entry.ttlUnixSeconds > 0 &&
        now / 1000 >= entry.ttlUnixSeconds;
      if (expiredByAge || expiredByTtl) {
        await persist({ ...entry, state: "failed", failedReason: "expired" });
        results.push({ id: entry.id, hash: entry.hash, state: "failed" });
        continue;
      }

      let result: OutboundQueueResult;
      try {
        await daemon.sendRawTransaction(entry.serialized);
        // Keep the entry — it still reserves its inputs until the tx mines; the
        // host prunes via remove() once it confirms.
        await persist({ ...entry, state: "broadcast" });
        result = { id: entry.id, hash: entry.hash, state: "broadcast" };
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        if (isRejection(error)) {
          // The chain rejected the tx outright (double-spend / bad signature) —
          // retrying is pointless. A spent/double-spend hint is a "conflict".
          const reason: OutboundQueueFailReason = /spent|double/i.test(message)
            ? "conflict"
            : "rejected";
          await persist({ ...entry, state: "failed", failedReason: reason, lastError: message });
          result = { id: entry.id, hash: entry.hash, state: "failed", error: message };
        } else {
          // Transient (network/HTTP/timeout) — retry on the next drain, unless
          // the attempt cap fires, in which case fail as "rejected".
          const attempts = entry.attempts + 1;
          const failed = maxAttempts !== undefined && attempts >= maxAttempts;
          await persist({
            ...entry,
            attempts,
            lastError: message,
            ...(failed ? { state: "failed", failedReason: "rejected" } : {}),
          });
          result = {
            id: entry.id,
            hash: entry.hash,
            state: failed ? "failed" : "pending",
            error: message,
          };
        }
      }
      results.push(result);
    }

    return results;
  }

  function start(intervalMs: number): void {
    if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
      throw new Error("start(intervalMs) requires a positive interval in milliseconds.");
    }
    if (intervalId !== null) return; // already running
    intervalId = setInterval(() => {
      if (inFlight) return; // guard against overlapping runs
      inFlight = true;
      drainOnce()
        .catch(() => {
          // Swallow per-tick failures; the next tick retries. Callers that need
          // visibility into errors should call drainOnce() directly.
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

  async function list(): Promise<OutboundQueueEntry[]> {
    return loadAll();
  }

  async function cancel(id: string): Promise<boolean> {
    const raw = await storage.getItem(id);
    if (raw === null) return false;
    const entry = parseEntry(raw);
    if (entry === null || entry.state !== "pending") return false;
    await storage.removeItem(id);
    return true;
  }

  async function remove(id: string): Promise<void> {
    await storage.removeItem(id);
  }

  return { enqueue, reservedKeyImages, drainOnce, start, stop, list, cancel, remove };
}

/**
 * True when the daemon REJECTED the tx (its message matches the sentinel thrown
 * by `DaemonClient.sendRawTransaction` on a non-OK status). A network/HTTP
 * failure throws a structurally different error and is treated as transient.
 */
function isRejection(error: unknown): boolean {
  return error instanceof Error && error.message.startsWith("Failed to send raw transaction");
}

/** Narrow an unknown JSON value to a valid {@link OutboundQueueFailReason}. */
function asFailReason(value: unknown): OutboundQueueFailReason | undefined {
  if (value === "rejected" || value === "expired" || value === "conflict") {
    return value;
  }
  return undefined;
}

/**
 * Parse a stored JSON blob into a typed entry, or `null` when malformed (so
 * `list`/`loadAll` silently skip corrupt values rather than throw partway). Only
 * the fields actually written by {@link persist} are honored.
 */
function parseEntry(raw: string): OutboundQueueEntry | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;

  const state = parsed.state;
  if (state !== "pending" && state !== "broadcast" && state !== "failed") {
    return null;
  }
  if (
    typeof parsed.id !== "string" ||
    typeof parsed.hash !== "string" ||
    typeof parsed.serialized !== "string" ||
    !Array.isArray(parsed.keyImages) ||
    typeof parsed.enqueuedAt !== "number" ||
    typeof parsed.attempts !== "number"
  ) {
    return null;
  }

  const failedReason = asFailReason(parsed.failedReason);
  return {
    id: parsed.id,
    hash: parsed.hash,
    serialized: parsed.serialized,
    keyImages: parsed.keyImages.filter((k): k is Hex => typeof k === "string"),
    enqueuedAt: parsed.enqueuedAt,
    state,
    attempts: parsed.attempts,
    ...(typeof parsed.notBefore === "number" ? { notBefore: parsed.notBefore } : {}),
    ...(typeof parsed.label === "string" ? { label: parsed.label } : {}),
    ...(typeof parsed.ttlUnixSeconds === "number" ? { ttlUnixSeconds: parsed.ttlUnixSeconds } : {}),
    ...(typeof parsed.lastError === "string" ? { lastError: parsed.lastError } : {}),
    ...(failedReason !== undefined ? { failedReason } : {}),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
