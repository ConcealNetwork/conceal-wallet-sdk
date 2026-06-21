import { crypto as ccxCrypto } from "conceal-lib-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Account } from "../src/account";
import { createMemoryStorage } from "../src/adapters";
import type { DaemonClient, DaemonRawTransaction } from "../src/daemon";
import { calculateDepositInterest } from "../src/deposits";
import {
  createWalletSync,
  DEFAULT_STORAGE_KEY,
  extractDepositInputs,
  extractInputKeyImages,
  toScanTransaction,
} from "../src/sync";
import { scanTransactionOutputs } from "../src/transactions";
import {
  deserializeWalletState,
  getBalance,
  getTransactions,
  getUnlockedDeposits,
} from "../src/wallet";

// --- helpers --------------------------------------------------------------

type Created = ReturnType<typeof ccxCrypto.create_address>;

function created(seedByte: string): Created {
  return ccxCrypto.create_address(ccxCrypto.sc_reduce32(seedByte.repeat(32)));
}

function accountOf(c: Created): Account {
  return { address: c.public_addr, keys: { spend: c.spend, view: c.view } };
}

function txKeypair(seedByte: string): { sec: string; pub: string } {
  return ccxCrypto.generate_keys(ccxCrypto.sc_reduce32(seedByte.repeat(32)));
}

/**
 * Build a daemon raw-transaction whose inner `transaction` carries a REAL
 * stealth-constructed output owned by `recipient` (so the SDK's own
 * scanTransactionOutputs detects it end-to-end — no scan stubbing). Optionally
 * embeds spend inputs (`vin[].k_image`).
 */
function ownedDaemonTx(
  recipient: Created,
  tx: { sec: string; pub: string },
  amount: number,
  opts: { height: number; globalIndex: number; hash: string; spendKeyImages?: string[] },
): DaemonRawTransaction {
  const senderDerivation = ccxCrypto.generate_key_derivation(recipient.view.pub, tx.sec);
  const ownedKey = ccxCrypto.derive_public_key(senderDerivation, 0, recipient.spend.pub);
  const vin = (opts.spendKeyImages ?? []).map((k_image) => ({ type: "02", k_image }));
  return {
    transaction: {
      extra: `01${tx.pub}`,
      vout: [{ amount, target: { type: "02", data: { key: ownedKey } } }],
      vin,
    },
    timestamp: 1700000000 + opts.height,
    outputIndexes: [opts.globalIndex],
    height: opts.height,
    blockHash: "bb".repeat(32),
    hash: opts.hash,
    fee: 10,
  };
}

/** An unrelated daemon tx with neither owned outputs nor our spends. */
function foreignDaemonTx(height: number): DaemonRawTransaction {
  const tx = txKeypair("ff");
  const stranger = created("99");
  const derivation = ccxCrypto.generate_key_derivation(stranger.view.pub, tx.sec);
  const key = ccxCrypto.derive_public_key(derivation, 0, stranger.spend.pub);
  return {
    transaction: {
      extra: `01${tx.pub}`,
      vout: [{ amount: 7, target: { type: "02", data: { key } } }],
      vin: [],
    },
    timestamp: 1700000000 + height,
    outputIndexes: [9999],
    height,
    blockHash: "cc".repeat(32),
    hash: `cc${height.toString(16).padStart(62, "0")}`,
    fee: 1,
  };
}

/**
 * Mock {@link DaemonClient}: serves a fixed height and a height→transactions map.
 * Each `getWalletSyncData(start, end)` returns the txs whose height ∈ [start, end].
 */
function mockDaemon(
  height: number,
  txsByHeight: Map<number, DaemonRawTransaction[]>,
): DaemonClient & { syncCalls: Array<[number, number]> } {
  const syncCalls: Array<[number, number]> = [];
  return {
    nodeUrl: "https://mock/",
    getHeight: () => Promise.resolve(height),
    getInfo: () =>
      Promise.resolve({
        height,
        difficulty: 0,
        txPoolSize: 0,
        incomingConnections: 0,
        outgoingConnections: 0,
        whitePeerlistSize: 0,
        greyPeerlistSize: 0,
        altBlocksCount: 0,
        startTime: 0,
        version: "",
        status: "OK",
      }),
    getNodeFeeAddress: () => Promise.resolve(""),
    sendRawTransaction: () => Promise.resolve({ status: "OK" }),
    getRandomOuts: () => Promise.resolve([]),
    getTransactionsPool: () => Promise.resolve([]),
    getWalletSyncData: (start: number, end: number) => {
      syncCalls.push([start, end]);
      const out: DaemonRawTransaction[] = [];
      for (let h = start; h <= end; h++) {
        const txs = txsByHeight.get(h);
        if (txs) out.push(...txs);
      }
      return Promise.resolve(out);
    },
    syncCalls,
  };
}

// --- daemon → scan bridge --------------------------------------------------

describe("toScanTransaction", () => {
  it("bridges a daemon tx into the scanner's RawTransaction shape", () => {
    const recipient = created("aa");
    const daemonTx = ownedDaemonTx(recipient, txKeypair("bb"), 100, {
      height: 50,
      globalIndex: 5,
      hash: "ab".repeat(32),
    });
    const scanTx = toScanTransaction(daemonTx);
    expect(scanTx).not.toBeNull();
    if (scanTx === null) return;
    expect(scanTx.extra).toBe((daemonTx.transaction as { extra: string }).extra);
    expect(scanTx.outputIndexes).toEqual([5]);
    expect(scanTx.height).toBe(50);
    // The bridged tx is genuinely scannable end-to-end.
    expect(scanTransactionOutputs(scanTx, accountOf(recipient).keys)).toHaveLength(1);
  });

  it("returns null for a malformed transaction slot", () => {
    expect(toScanTransaction({ transaction: null } as unknown as DaemonRawTransaction)).toBeNull();
    expect(
      toScanTransaction({ transaction: { vout: [] } } as unknown as DaemonRawTransaction),
    ).toBeNull();
  });
});

describe("extractInputKeyImages", () => {
  it("reads key images from direct and nested vin shapes", () => {
    const tx = {
      vin: [
        { type: "02", k_image: "aa".repeat(32) },
        { type: "02", value: { k_image: "bb".repeat(32) } },
        { type: "ff" }, // coinbase — no key image
      ],
    };
    expect(extractInputKeyImages(tx)).toEqual(["aa".repeat(32), "bb".repeat(32)]);
  });

  it("returns [] for inputs without key images", () => {
    expect(extractInputKeyImages({ vin: [] })).toEqual([]);
    expect(extractInputKeyImages(null)).toEqual([]);
  });
});

describe("extractDepositInputs", () => {
  it("reads type-03 deposit inputs from direct and nested vin shapes", () => {
    const tx = {
      vin: [
        { type: "02", k_image: "aa".repeat(32) }, // ring input — ignored
        { type: "input_to_deposit_key", outputIndex: 42, term: 21900 },
        { type: "03", value: { outputIndex: 9, term: 5040 } },
      ],
    };
    expect(extractDepositInputs(tx)).toEqual([
      { type: "input_to_deposit_key", outputIndex: 42, term: 21900 },
      { type: "input_to_deposit_key", outputIndex: 9, term: 5040 },
    ]);
  });

  it("returns [] when there are no deposit inputs", () => {
    expect(extractDepositInputs({ vin: [{ type: "02", k_image: "aa".repeat(32) }] })).toEqual([]);
    expect(extractDepositInputs(null)).toEqual([]);
  });
});

// --- syncOnce --------------------------------------------------------------

describe("createWalletSync.syncOnce", () => {
  const recipient = created("aa");

  it("detects an owned output end-to-end: advances height, increases balance, persists, fires onUpdate", async () => {
    const amount = 4_200_000;
    const ownedTx = ownedDaemonTx(recipient, txKeypair("bb"), amount, {
      height: 5,
      globalIndex: 77,
      hash: "ab".repeat(32),
    });
    const daemon = mockDaemon(
      10,
      new Map([
        [3, [foreignDaemonTx(3)]],
        [5, [ownedTx]],
      ]),
    );
    const storage = createMemoryStorage();
    const updates: number[] = [];
    const sync = createWalletSync({
      daemon,
      account: accountOf(recipient),
      storage,
      onUpdate: (s) => updates.push(getBalance(s).total),
    });

    await sync.load();
    expect(getBalance(sync.getState()).total).toBe(0);

    const state = await sync.syncOnce();

    // height advanced to the network tip.
    expect(state.scannedHeight).toBe(10);
    // balance reflects the owned output — proving the scan detected it.
    expect(getBalance(state).total).toBe(amount);
    expect(state.outputs).toHaveLength(1);
    expect(state.outputs[0]?.globalIndex).toBe(77);

    // history records the receive.
    const history = getTransactions(state);
    expect(history).toHaveLength(1);
    expect(history[0]?.direction).toBe("in");
    expect(history[0]?.amount).toBe(amount);

    // onUpdate fired with the new balance.
    expect(updates).toEqual([amount]);

    // state persisted to memory storage and is restorable.
    const raw = await storage.getItem(DEFAULT_STORAGE_KEY);
    expect(raw).not.toBeNull();
    const persisted = deserializeWalletState(raw as string);
    expect(getBalance(persisted).total).toBe(amount);
    expect(persisted.scannedHeight).toBe(10);
  });

  it("detects a later spend of the owned output end-to-end", async () => {
    const tx = txKeypair("bb");
    const ownedTx = ownedDaemonTx(recipient, tx, 1_000_000, {
      height: 5,
      globalIndex: 12,
      hash: "ab".repeat(32),
    });
    // Recover the owned output's real key image via the SDK scanner.
    const ownedScanTx = toScanTransaction(ownedTx);
    expect(ownedScanTx).not.toBeNull();
    if (ownedScanTx === null) return;
    const scanned = scanTransactionOutputs(ownedScanTx, accountOf(recipient).keys);
    const keyImage = scanned[0]?.keyImage as string;

    const spendTx: DaemonRawTransaction = {
      transaction: { extra: "020100", vout: [], vin: [{ type: "02", k_image: keyImage }] },
      timestamp: 1700000200,
      outputIndexes: [],
      height: 8,
      blockHash: "dd".repeat(32),
      hash: "ef".repeat(32),
      fee: 5,
    };

    const daemon = mockDaemon(
      10,
      new Map([
        [5, [ownedTx]],
        [8, [spendTx]],
      ]),
    );
    const sync = createWalletSync({ daemon, account: accountOf(recipient) });

    await sync.load();
    const state = await sync.syncOnce();

    expect(state.scannedHeight).toBe(10);
    expect(getBalance(state)).toEqual({ total: 0, spendable: 0 });
    expect(state.spentKeyImages).toContain(keyImage);
    expect(getTransactions(state).some((t) => t.direction === "out")).toBe(true);
  });

  it("fetches in batches respecting batchSize", async () => {
    const daemon = mockDaemon(250, new Map());
    const sync = createWalletSync({ daemon, account: accountOf(recipient), batchSize: 100 });
    await sync.load();
    const state = await sync.syncOnce();
    expect(state.scannedHeight).toBe(250);
    expect(daemon.syncCalls).toEqual([
      [1, 100],
      [101, 200],
      [201, 250],
    ]);
  });

  it("is a no-op (no save, no onUpdate) when already at the tip", async () => {
    const daemon = mockDaemon(0, new Map());
    const storage = createMemoryStorage();
    const onUpdate = vi.fn();
    const sync = createWalletSync({ daemon, account: accountOf(recipient), storage, onUpdate });
    await sync.load();
    await sync.syncOnce();
    expect(onUpdate).not.toHaveBeenCalled();
    expect(await storage.getItem(DEFAULT_STORAGE_KEY)).toBeNull();
  });
});

// --- load / save persistence ----------------------------------------------

describe("createWalletSync.load / save", () => {
  const recipient = created("aa");

  it("hydrates persisted state on load", async () => {
    const ownedTx = ownedDaemonTx(recipient, txKeypair("bb"), 333, {
      height: 2,
      globalIndex: 1,
      hash: "ab".repeat(32),
    });
    const storage = createMemoryStorage();

    // First sync populates + persists.
    const first = createWalletSync({
      daemon: mockDaemon(5, new Map([[2, [ownedTx]]])),
      account: accountOf(recipient),
      storage,
    });
    await first.load();
    await first.syncOnce();

    // A fresh controller over the same storage rehydrates.
    const second = createWalletSync({
      daemon: mockDaemon(5, new Map()),
      account: accountOf(recipient),
      storage,
    });
    await second.load();
    expect(getBalance(second.getState()).total).toBe(333);
    expect(second.getState().scannedHeight).toBe(5);
  });

  it("starts fresh when storage is empty", async () => {
    const sync = createWalletSync({
      daemon: mockDaemon(0, new Map()),
      account: accountOf(recipient),
      storage: createMemoryStorage(),
    });
    await sync.load();
    expect(getBalance(sync.getState()).total).toBe(0);
    expect(sync.getState().scannedHeight).toBe(0);
  });

  it("rejects loading another address's state", async () => {
    const storage = createMemoryStorage();
    const other = createWalletSync({
      daemon: mockDaemon(0, new Map()),
      account: accountOf(created("5a")),
      storage,
    });
    await other.load();
    await other.save();

    const sync = createWalletSync({
      daemon: mockDaemon(0, new Map()),
      account: accountOf(recipient),
      storage,
    });
    await expect(sync.load()).rejects.toThrow(/different address/i);
  });
});

// --- start / stop scheduling ----------------------------------------------

describe("createWalletSync.start / stop", () => {
  const recipient = created("aa");

  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("schedules syncOnce on an interval and stop() clears it", async () => {
    const daemon = mockDaemon(0, new Map());
    const heightSpy = vi.spyOn(daemon, "getHeight");
    const sync = createWalletSync({ daemon, account: accountOf(recipient) });

    sync.start(1000);
    await vi.advanceTimersByTimeAsync(1000);
    await vi.advanceTimersByTimeAsync(1000);
    expect(heightSpy.mock.calls.length).toBe(2);

    sync.stop();
    await vi.advanceTimersByTimeAsync(5000);
    expect(heightSpy.mock.calls.length).toBe(2); // no further ticks after stop
  });

  it("does not start a second interval if already running", async () => {
    const daemon = mockDaemon(0, new Map());
    const heightSpy = vi.spyOn(daemon, "getHeight");
    const sync = createWalletSync({ daemon, account: accountOf(recipient) });
    sync.start(1000);
    sync.start(1000); // ignored
    await vi.advanceTimersByTimeAsync(1000);
    expect(heightSpy.mock.calls.length).toBe(1);
    sync.stop();
  });

  it("guards against overlapping runs", async () => {
    // A daemon whose getHeight never resolves keeps a run in-flight, so the next
    // tick must be skipped rather than starting a concurrent run.
    let resolveHeight: ((h: number) => void) | undefined;
    const daemon = mockDaemon(0, new Map());
    const heightSpy = vi.spyOn(daemon, "getHeight").mockImplementation(
      () =>
        new Promise<number>((resolve) => {
          resolveHeight = resolve;
        }),
    );

    const sync = createWalletSync({ daemon, account: accountOf(recipient) });
    sync.start(500);
    await vi.advanceTimersByTimeAsync(500); // tick 1 starts, hangs in getHeight
    await vi.advanceTimersByTimeAsync(500); // tick 2 must be skipped (inFlight)
    await vi.advanceTimersByTimeAsync(500); // tick 3 must be skipped too
    expect(heightSpy.mock.calls.length).toBe(1);

    resolveHeight?.(0); // let the first run finish
    sync.stop();
  });

  it("rejects a non-positive interval", () => {
    const sync = createWalletSync({
      daemon: mockDaemon(0, new Map()),
      account: accountOf(recipient),
    });
    expect(() => sync.start(0)).toThrow(/positive interval/i);
  });
});

// --- deposits flow end-to-end ----------------------------------------------

/**
 * A daemon tx whose single type-03 output is a deposit genuinely owned by `recipient`
 * (stealth-constructed so the SDK scans it for real). Carries no spendable type-02
 * output and no key images — it must still flow into state via the deposit path.
 */
function ownedDepositDaemonTx(
  recipient: Created,
  tx: { sec: string; pub: string },
  amount: number,
  term: number,
  opts: { height: number; globalIndex: number; hash: string },
): DaemonRawTransaction {
  const derivation = ccxCrypto.generate_key_derivation(recipient.view.pub, tx.sec);
  const depositKey = ccxCrypto.derive_public_key(derivation, 0, recipient.spend.pub);
  return {
    transaction: {
      extra: `01${tx.pub}`,
      vout: [
        {
          amount,
          target: { type: "03", data: { keys: [depositKey], required_signatures: 1, term } },
        },
      ],
      vin: [],
    },
    timestamp: 1700000000 + opts.height,
    outputIndexes: [opts.globalIndex],
    height: opts.height,
    blockHash: "dd".repeat(32),
    hash: opts.hash,
    fee: 1000,
  };
}

/** A daemon tx that withdraws a deposit: single type-03 input by its global index. */
function withdrawDaemonTx(
  depositGlobalIndex: number,
  term: number,
  opts: { height: number; hash: string },
): DaemonRawTransaction {
  const tx = txKeypair("e1");
  return {
    transaction: {
      extra: `01${tx.pub}`,
      // The redeem output goes to the owner, but for this test we only need the type-03
      // input to be detected as a withdrawal of our deposit (no owned vout required).
      vout: [{ amount: 1, target: { type: "02", data: { key: "00".repeat(32) } } }],
      vin: [{ type: "input_to_deposit_key", outputIndex: depositGlobalIndex, term }],
    },
    timestamp: 1700000000 + opts.height,
    outputIndexes: [],
    height: opts.height,
    blockHash: "ee".repeat(32),
    hash: opts.hash,
    fee: 10,
  };
}

describe("createWalletSync.syncOnce — deposits", () => {
  const recipient = created("aa");

  it("a deposit tx then a withdraw tx flow into state.deposits / spentDepositIndexes", async () => {
    const amount = 1e10; // 10000 CCX
    const term = 21900; // 1 month
    const depositHeight = 413401; // > depositHeightV3
    const depositGlobalIndex = 6060;

    const depositTx = ownedDepositDaemonTx(recipient, txKeypair("d1"), amount, term, {
      height: depositHeight,
      globalIndex: depositGlobalIndex,
      hash: "a0".repeat(32),
    });
    const withdrawTx = withdrawDaemonTx(depositGlobalIndex, term, {
      height: depositHeight + term + 1,
      hash: "a1".repeat(32),
    });

    // Phase 1: sync up to the deposit only — it must land in state.deposits.
    const daemon1 = mockDaemon(depositHeight, new Map([[depositHeight, [depositTx]]]));
    const sync = createWalletSync({
      daemon: daemon1,
      account: accountOf(recipient),
      batchSize: 1_000_000,
    });
    let state = await sync.syncOnce();
    expect(state.deposits).toHaveLength(1);
    expect(state.deposits[0]?.amount).toBe(amount);
    expect(state.deposits[0]?.term).toBe(term);
    expect(state.deposits[0]?.globalIndex).toBe(depositGlobalIndex);
    expect(state.deposits[0]?.interest).toBe(
      calculateDepositInterest({ amount, term, lockHeight: depositHeight }),
    );
    expect(state.spentDepositIndexes).toEqual([]);
    // Deposit principal is NOT spendable balance.
    expect(getBalance(state).spendable).toBe(0);
    // Unlocked at/after blockHeight + term.
    expect(getUnlockedDeposits(state, depositHeight + term)).toHaveLength(1);

    // Phase 2: the daemon now also serves the withdraw tx; the next sync marks it spent.
    daemon1.getHeight = () => Promise.resolve(withdrawTx.height as number);
    (daemon1 as { getWalletSyncData: DaemonClient["getWalletSyncData"] }).getWalletSyncData = (
      start: number,
      end: number,
    ) => {
      const out: DaemonRawTransaction[] = [];
      if (
        withdrawTx.height !== undefined &&
        withdrawTx.height >= start &&
        withdrawTx.height <= end
      ) {
        out.push(withdrawTx);
      }
      return Promise.resolve(out);
    };
    state = await sync.syncOnce();
    expect(state.spentDepositIndexes).toEqual([depositGlobalIndex]);
    expect(getUnlockedDeposits(state, withdrawTx.height as number)).toHaveLength(0);
  });

  it("a deposit-only tx (no type-02 output, no key images) is still applied", async () => {
    const amount = 1e10;
    const term = 21900;
    const height = 413402;
    const depositTx = ownedDepositDaemonTx(recipient, txKeypair("d2"), amount, term, {
      height,
      globalIndex: 7070,
      hash: "b0".repeat(32),
    });
    const daemon = mockDaemon(height, new Map([[height, [depositTx]]]));
    const sync = createWalletSync({
      daemon,
      account: accountOf(recipient),
      batchSize: 1_000_000,
    });
    const state = await sync.syncOnce();
    expect(state.deposits).toHaveLength(1);
    expect(state.deposits[0]?.globalIndex).toBe(7070);
  });
});
