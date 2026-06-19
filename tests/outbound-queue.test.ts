import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMemoryStorage, type StorageAdapter } from "../src/adapters";
import {
  createOutboundQueue,
  OUTBOUND_QUEUE_NAMESPACE,
  type OutboundQueue,
  type OutboundQueueEntry,
} from "../src/outbound-queue";
import type { BuiltTransaction } from "../src/transactions";

// --- helpers --------------------------------------------------------------

const K1 = "aa".repeat(32);
const K2 = "bb".repeat(32);

/** Build a minimal but well-typed BuiltTransaction for queue inputs. */
function builtTx(opts: {
  hash: string;
  serialized?: string;
  keyImages?: string[];
}): BuiltTransaction {
  const keyImages = opts.keyImages ?? [];
  return {
    txPublicKey: "00".repeat(32),
    txSecretKey: "00".repeat(32),
    inputs: keyImages.map((keyImage) => ({
      amount: 1,
      keyImage,
      keyOffsets: [0],
      ringPublicKeys: ["00".repeat(32)],
      realIndex: 0,
      signatures: ["00".repeat(64)],
    })),
    outputs: [],
    fee: 10,
    inputsAmount: 0,
    sentAmount: 0,
    changeAmount: 0,
    extra: `01${"00".repeat(32)}`,
    prefixHash: "00".repeat(32),
    serialized: opts.serialized ?? opts.hash,
    hash: opts.hash,
  };
}

/** A fake daemon whose `sendRawTransaction` is a vitest mock. Inferred so the
 * mock's callable signature matches `Pick<DaemonClient, "sendRawTransaction">`. */
function fakeDaemon() {
  return {
    sendRawTransaction: vi.fn(
      (_txHex: string): Promise<{ status: string }> => Promise.resolve({ status: "OK" }),
    ),
  };
}

type FakeDaemon = ReturnType<typeof fakeDaemon>;

function queue(
  storage: StorageAdapter,
  daemon: FakeDaemon,
  opts: { clock?: () => number; maxAttempts?: number; maxAgeMs?: number } = {},
): OutboundQueue {
  return createOutboundQueue({
    storage,
    daemon,
    ...(opts.clock !== undefined ? { clock: opts.clock } : {}),
    ...(opts.maxAttempts !== undefined ? { maxAttempts: opts.maxAttempts } : {}),
    ...(opts.maxAgeMs !== undefined ? { maxAgeMs: opts.maxAgeMs } : {}),
  });
}

// --- tests ----------------------------------------------------------------

describe("createOutboundQueue — construction", () => {
  it("throws when storage is missing", () => {
    expect(() =>
      createOutboundQueue({
        storage: undefined as unknown as StorageAdapter,
        daemon: fakeDaemon(),
      }),
    ).toThrow(/storage/);
  });

  it("throws when daemon is missing", () => {
    expect(() =>
      createOutboundQueue({
        storage: createMemoryStorage(),
        daemon: undefined as unknown as FakeDaemon,
      }),
    ).toThrow(/daemon/);
  });

  it("namespaces its keys under the outbox prefix", async () => {
    const base = createMemoryStorage();
    const q = queue(base, fakeDaemon(), { clock: () => 1000 });
    await q.enqueue(builtTx({ hash: "ab", keyImages: [K1] }));
    const allKeys = await base.keys();
    expect(allKeys).toEqual([`${OUTBOUND_QUEUE_NAMESPACE}:ab`]);
  });
});

describe("enqueue + reservedKeyImages", () => {
  let now: number;
  let storage: StorageAdapter;
  let daemon: FakeDaemon;
  let q: OutboundQueue;

  beforeEach(() => {
    now = 1_000_000;
    storage = createMemoryStorage();
    daemon = fakeDaemon();
    q = queue(storage, daemon, { clock: () => now });
  });

  it("persists an entry and returns its hash as the id", async () => {
    const id = await q.enqueue(builtTx({ hash: "deadbeef", keyImages: [K1, K2] }));
    expect(id).toBe("deadbeef");

    const entries = await q.list();
    expect(entries).toHaveLength(1);
    const entry = entries[0];
    expect(entry).toMatchObject({
      id: "deadbeef",
      hash: "deadbeef",
      serialized: "deadbeef",
      keyImages: [K1, K2],
      enqueuedAt: 1_000_000,
      state: "pending",
      attempts: 0,
    });
  });

  it("reserves key images of pending entries", async () => {
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1, K2] }));
    expect(await q.reservedKeyImages()).toEqual(new Set([K1, K2]));
  });

  it("reserves key images of broadcast entries (until mined/removed)", async () => {
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    await q.drainOnce();
    expect(await q.reservedKeyImages()).toEqual(new Set([K1]));
  });

  it("does NOT reserve key images of failed entries", async () => {
    daemon.sendRawTransaction.mockRejectedValue(
      new Error("Failed to send raw transaction: FAILED (bad sig)"),
    );
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    await q.drainOnce();
    expect(await q.reservedKeyImages()).toEqual(new Set());
  });

  it("throws when an input key image is already reserved by a pending tx", async () => {
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    await expect(q.enqueue(builtTx({ hash: "tx2", keyImages: [K1] }))).rejects.toThrow(
      "Outbound queue: input already reserved by a pending transaction.",
    );
  });

  it("records the injected clock timestamp at enqueue time", async () => {
    now = 5_000;
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    now = 9_000;
    await q.enqueue(builtTx({ hash: "tx2", keyImages: [K2] }));
    const byId = new Map((await q.list()).map((e) => [e.id, e]));
    expect(byId.get("tx1")?.enqueuedAt).toBe(5_000);
    expect(byId.get("tx2")?.enqueuedAt).toBe(9_000);
  });
});

describe("enqueue — dedupe by hash", () => {
  let storage: StorageAdapter;
  let q: OutboundQueue;

  beforeEach(() => {
    storage = createMemoryStorage();
    q = queue(storage, fakeDaemon(), { clock: () => 1 });
  });

  it("returns the existing id and does not duplicate on re-enqueue of same hash", async () => {
    const tx = builtTx({ hash: "dup", keyImages: [K1] });
    const id1 = await q.enqueue(tx);
    const id2 = await q.enqueue(tx);
    expect(id1).toBe("dup");
    expect(id2).toBe("dup");
    expect(await q.list()).toHaveLength(1);
  });

  it("does not throw when re-enqueuing a tx whose own key images it reserves", async () => {
    const tx = builtTx({ hash: "dup", keyImages: [K1] });
    await q.enqueue(tx);
    await expect(q.enqueue(tx)).resolves.toBe("dup");
  });
});

describe("drainOnce — success path", () => {
  let now: number;
  let storage: StorageAdapter;
  let daemon: FakeDaemon;
  let q: OutboundQueue;

  beforeEach(() => {
    now = 10_000;
    storage = createMemoryStorage();
    daemon = fakeDaemon();
    q = queue(storage, daemon, { clock: () => now });
  });

  it("broadcasts a due pending entry and moves it to broadcast state", async () => {
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    const id = await q.enqueue(builtTx({ hash: "tx1", serialized: "deadbeef", keyImages: [K1] }));

    const results = await q.drainOnce();

    expect(daemon.sendRawTransaction).toHaveBeenCalledWith("deadbeef");
    expect(results).toEqual([{ id, hash: "tx1", state: "broadcast" }]);
    const entry = (await q.list()).find((e) => e.id === id);
    expect(entry?.state).toBe("broadcast");
  });

  it("keeps the broadcast entry reserving its inputs until removed", async () => {
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    const id = await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    await q.drainOnce();

    // Second drain must NOT re-broadcast (no longer pending).
    await q.drainOnce();
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(1);
    expect(await q.reservedKeyImages()).toEqual(new Set([K1]));

    // remove() releases the reservation.
    await q.remove(id);
    expect(await q.reservedKeyImages()).toEqual(new Set());
    expect(await q.list()).toEqual([]);
  });
});

describe("drainOnce — timestamp ordering", () => {
  let now: number;
  let storage: StorageAdapter;
  let daemon: FakeDaemon;
  let q: OutboundQueue;

  beforeEach(() => {
    now = 0;
    storage = createMemoryStorage();
    daemon = fakeDaemon();
    q = queue(storage, daemon, { clock: () => now });
  });

  it("drains candidates in ascending enqueuedAt order regardless of key order", async () => {
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });

    // Enqueue A at t=2000, then B at t=1000 by running the clock backwards
    // (the clock is injected, so this is deterministic).
    now = 2000;
    await q.enqueue(builtTx({ hash: "A", serialized: "sA", keyImages: [K1] }));
    now = 1000;
    await q.enqueue(builtTx({ hash: "B", serialized: "sB", keyImages: [K2] }));

    now = 3000;
    await q.drainOnce();

    // B (enqueuedAt 1000) must precede A (enqueuedAt 2000).
    expect(daemon.sendRawTransaction.mock.calls.map((c) => c[0])).toEqual(["sB", "sA"]);
  });
});

describe("drainOnce — rejection handling", () => {
  let now: number;
  let storage: StorageAdapter;
  let daemon: FakeDaemon;
  let q: OutboundQueue;

  beforeEach(() => {
    now = 1000;
    storage = createMemoryStorage();
    daemon = fakeDaemon();
    q = queue(storage, daemon, { clock: () => now });
  });

  it("marks a double-spend rejection as failed(conflict) and does not retry", async () => {
    const rejection = new Error("Failed to send raw transaction: FAILED (Key image already spent)");
    daemon.sendRawTransaction.mockRejectedValue(rejection);
    const id = await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));

    const results = await q.drainOnce();

    expect(results).toEqual([{ id, hash: "tx1", state: "failed", error: rejection.message }]);
    const entry = (await q.list()).find((e) => e.id === id) as OutboundQueueEntry;
    expect(entry.state).toBe("failed");
    expect(entry.failedReason).toBe("conflict");
    expect(entry.lastError).toBe(rejection.message);
    expect(entry.attempts).toBe(0); // rejections don't consume an attempt

    // A second drain must not retry a failed entry.
    await q.drainOnce();
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(1);
  });

  it("marks a non-conflict rejection as failed(rejected)", async () => {
    daemon.sendRawTransaction.mockRejectedValue(
      new Error("Failed to send raw transaction: REJECTED (bad signature)"),
    );
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    await q.drainOnce();
    const entry = (await q.list())[0] as OutboundQueueEntry;
    expect(entry.state).toBe("failed");
    expect(entry.failedReason).toBe("rejected");
  });

  it("a rejection for one entry does not stop draining the rest", async () => {
    daemon.sendRawTransaction
      .mockRejectedValueOnce(new Error("Failed to send raw transaction: FAILED (spent)"))
      .mockResolvedValueOnce({ status: "OK" });

    now = 1;
    await q.enqueue(builtTx({ hash: "bad", keyImages: [K1] }));
    now = 2;
    await q.enqueue(builtTx({ hash: "good", keyImages: [K2] }));

    const results = await q.drainOnce();
    expect(results.map((r) => r.state)).toEqual(["failed", "broadcast"]);
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(2);
  });
});

describe("drainOnce — transient errors and maxAttempts", () => {
  let now: number;
  let storage: StorageAdapter;
  let daemon: FakeDaemon;
  let q: OutboundQueue;

  beforeEach(() => {
    now = 1000;
    storage = createMemoryStorage();
    daemon = fakeDaemon();
  });

  it("retries a transient (non-rejection) error, keeping state pending", async () => {
    q = queue(storage, daemon, { clock: () => now, maxAttempts: 3 });
    daemon.sendRawTransaction.mockRejectedValue(new Error("Daemon request failed: network down"));
    const id = await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));

    const r1 = await q.drainOnce();
    expect(r1).toEqual([
      { id, hash: "tx1", state: "pending", error: "Daemon request failed: network down" },
    ]);
    let entry = (await q.list())[0] as OutboundQueueEntry;
    expect(entry.state).toBe("pending");
    expect(entry.attempts).toBe(1);
    expect(entry.failedReason).toBeUndefined();

    const r2 = await q.drainOnce();
    expect(r2[0]?.state).toBe("pending");
    entry = (await q.list())[0] as OutboundQueueEntry;
    expect(entry.attempts).toBe(2);
    expect(entry.state).toBe("pending");
  });

  it("fails as rejected once maxAttempts is reached", async () => {
    q = queue(storage, daemon, { clock: () => now, maxAttempts: 2 });
    daemon.sendRawTransaction.mockRejectedValue(new Error("timeout"));
    const id = await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));

    await q.drainOnce(); // attempts=1, pending
    const r2 = await q.drainOnce(); // attempts=2 >= 2 → failed

    expect(r2).toEqual([{ id, hash: "tx1", state: "failed", error: "timeout" }]);
    const entry = (await q.list())[0] as OutboundQueueEntry;
    expect(entry.state).toBe("failed");
    expect(entry.failedReason).toBe("rejected");
    expect(entry.attempts).toBe(2);

    // No further retries once failed.
    await q.drainOnce();
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(2);
  });

  it("retries indefinitely when maxAttempts is unset", async () => {
    q = queue(storage, daemon, { clock: () => now });
    daemon.sendRawTransaction.mockRejectedValue(new Error("flaky"));
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));

    for (let i = 0; i < 5; i++) {
      await q.drainOnce();
    }
    const entry = (await q.list())[0] as OutboundQueueEntry;
    expect(entry.state).toBe("pending");
    expect(entry.attempts).toBe(5);
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(5);

    // Eventually succeeds.
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    const results = await q.drainOnce();
    expect(results[0]?.state).toBe("broadcast");
  });
});

describe("drainOnce — notBefore gating", () => {
  let now: number;
  let storage: StorageAdapter;
  let daemon: FakeDaemon;
  let q: OutboundQueue;

  beforeEach(() => {
    now = 0;
    storage = createMemoryStorage();
    daemon = fakeDaemon();
    q = queue(storage, daemon, { clock: () => now });
  });

  it("does not broadcast before notBefore, then broadcasts once due", async () => {
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }), { notBefore: 10_000 });

    now = 5_000;
    let results = await q.drainOnce();
    expect(results).toEqual([]);
    expect(daemon.sendRawTransaction).not.toHaveBeenCalled();

    now = 10_000;
    results = await q.drainOnce();
    expect(results[0]?.state).toBe("broadcast");
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(1);
  });
});

describe("drainOnce — expiry", () => {
  let now: number;
  let storage: StorageAdapter;
  let daemon: FakeDaemon;

  beforeEach(() => {
    now = 0;
    storage = createMemoryStorage();
    daemon = fakeDaemon();
  });

  it("fails as expired when the entry is older than maxAgeMs", async () => {
    const q = queue(storage, daemon, { clock: () => now, maxAgeMs: 1_000 });
    now = 5_000;
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));

    now = 7_000; // age = 2000 > 1000
    const results = await q.drainOnce();

    expect(results).toEqual([{ id: "tx1", hash: "tx1", state: "failed" }]);
    expect(daemon.sendRawTransaction).not.toHaveBeenCalled();
    const entry = (await q.list())[0] as OutboundQueueEntry;
    expect(entry.state).toBe("failed");
    expect(entry.failedReason).toBe("expired");
  });

  it("fails as expired once ttlUnixSeconds is in the past", async () => {
    const q = queue(storage, daemon, { clock: () => now });
    now = 0;
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }), { ttlUnixSeconds: 10 });

    now = 5_000; // 5s < 10s — still valid, but no broadcast (mock not set); throw → transient
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    await q.drainOnce();
    let entry = (await q.list())[0] as OutboundQueueEntry;
    expect(entry.state).toBe("broadcast"); // not expired yet

    // Fresh entry with ttl already past.
    now = 0;
    await q.remove("tx1");
    await q.enqueue(builtTx({ hash: "tx2", keyImages: [K2] }), { ttlUnixSeconds: 10 });
    now = 15_000; // 15s >= 10s → expired
    const results = await q.drainOnce();
    expect(results[0]?.state).toBe("failed");
    entry = (await q.list()).find((e) => e.id === "tx2") as OutboundQueueEntry;
    expect(entry.failedReason).toBe("expired");
    expect(daemon.sendRawTransaction).not.toHaveBeenCalledWith(expect.stringContaining("tx2"));
  });

  it("does not expire when maxAgeMs is unset and the entry is old", async () => {
    const q = queue(storage, daemon, { clock: () => now });
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    now = 1_000;
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    now = 1_000_000_000;
    const results = await q.drainOnce();
    expect(results[0]?.state).toBe("broadcast");
  });
});

describe("cancel + remove", () => {
  let storage: StorageAdapter;
  let daemon: FakeDaemon;
  let q: OutboundQueue;

  beforeEach(() => {
    storage = createMemoryStorage();
    daemon = fakeDaemon();
    q = queue(storage, daemon, { clock: () => 1 });
  });

  it("cancel removes a pending entry and frees its inputs; returns false otherwise", async () => {
    const id = await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    expect(await q.reservedKeyImages()).toEqual(new Set([K1]));

    expect(await q.cancel(id)).toBe(true);
    expect(await q.list()).toEqual([]);
    expect(await q.reservedKeyImages()).toEqual(new Set());

    // Already gone.
    expect(await q.cancel(id)).toBe(false);
    // Unknown id.
    expect(await q.cancel("nope")).toBe(false);
  });

  it("cancel returns false for a broadcast entry (cannot un-broadcast)", async () => {
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    const id = await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    await q.drainOnce();
    expect(await q.cancel(id)).toBe(false);
    expect(await q.list()).toHaveLength(1);
  });

  it("cancel returns false for a failed entry", async () => {
    daemon.sendRawTransaction.mockRejectedValue(
      new Error("Failed to send raw transaction: FAILED (spent)"),
    );
    const id = await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    await q.drainOnce();
    expect(await q.cancel(id)).toBe(false);
  });

  it("remove deletes any entry (pending, broadcast, or failed)", async () => {
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    const id = await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));
    await q.drainOnce();
    expect(await q.list()).toHaveLength(1);

    await q.remove(id);
    expect(await q.list()).toEqual([]);
    // remove is idempotent / no-op for unknown ids.
    await expect(q.remove("ghost")).resolves.toBeUndefined();
  });
});

describe("list — parse safety", () => {
  let storage: StorageAdapter;

  beforeEach(() => {
    storage = createMemoryStorage();
  });

  it("ignores malformed entries and returns only valid ones", async () => {
    const daemon = fakeDaemon();
    const q = queue(storage, daemon, { clock: () => 5 });
    // One valid entry via the queue, plus raw garbage under the namespace.
    await q.enqueue(builtTx({ hash: "good", keyImages: [K1] }));
    const base = storage; // createMemoryStorage IS the base here (no extra wrap)
    await base.setItem(`${OUTBOUND_QUEUE_NAMESPACE}:broken`, "{not json");
    await base.setItem(
      `${OUTBOUND_QUEUE_NAMESPACE}:wrongshape`,
      JSON.stringify({ id: "x", hash: "x" }),
    );

    const entries = await q.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.id).toBe("good");
  });
});

describe("start / stop polling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("polls drainOnce on an interval and stops cleanly", async () => {
    const daemon = fakeDaemon();
    daemon.sendRawTransaction.mockResolvedValue({ status: "OK" });
    const q = queue(createMemoryStorage(), daemon, { clock: () => 1 });
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));

    q.start(100);
    // First tick broadcasts the one pending entry.
    await vi.advanceTimersByTimeAsync(100);
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(1);

    // Nothing left to broadcast.
    await vi.advanceTimersByTimeAsync(200);
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(1);

    q.stop();
    await vi.advanceTimersByTimeAsync(500);
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(1);
  });

  it("start rejects a non-positive interval and is a no-op when already running", () => {
    const q = queue(createMemoryStorage(), fakeDaemon(), { clock: () => 1 });
    expect(() => q.start(0)).toThrow(/positive interval/);
    expect(() => q.start(-5)).toThrow(/positive interval/);
    expect(() => q.start(Number.NaN)).toThrow(/positive interval/);

    q.start(100);
    q.start(100); // already running — second call is a no-op (no throw)
    q.stop();
  });

  it("skips overlapping drain runs", async () => {
    const daemon = fakeDaemon();
    // Never resolves — keeps the first drain in-flight across the next tick.
    daemon.sendRawTransaction.mockImplementation(() => new Promise(() => {}));
    const q = queue(createMemoryStorage(), daemon, { clock: () => 1 });
    await q.enqueue(builtTx({ hash: "tx1", keyImages: [K1] }));

    q.start(100);
    await vi.advanceTimersByTimeAsync(100);
    await vi.advanceTimersByTimeAsync(200);
    // Only one in-flight call despite multiple ticks.
    expect(daemon.sendRawTransaction).toHaveBeenCalledTimes(1);
    q.stop();
  });
});
