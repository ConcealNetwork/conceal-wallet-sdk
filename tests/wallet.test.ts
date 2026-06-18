import { crypto as ccxCrypto } from "conceal-lib-js";
import { describe, expect, it } from "vitest";
import type { Account } from "../src/account";
import { type RawTransaction, type ScanKeys, scanTransactionOutputs } from "../src/transactions";
import {
  applyScannedTransaction,
  createWalletState,
  deserializeWalletState,
  getBalance,
  getTransactions,
  getUnspentOutputs,
  serializeWalletState,
  WALLET_STATE_VERSION,
} from "../src/wallet";

// --- helpers --------------------------------------------------------------

type Created = ReturnType<typeof ccxCrypto.create_address>;

function created(seedByte: string): Created {
  return ccxCrypto.create_address(ccxCrypto.sc_reduce32(seedByte.repeat(32)));
}

/** A minimal {@link Account} from a lib-js created address. */
function accountOf(c: Created): Account {
  return { address: c.public_addr, keys: { spend: c.spend, view: c.view } };
}

function keysOf(c: Created): ScanKeys {
  return { spend: c.spend, view: c.view };
}

function txKeypair(seedByte: string): { sec: string; pub: string } {
  return ccxCrypto.generate_keys(ccxCrypto.sc_reduce32(seedByte.repeat(32)));
}

/**
 * Craft a real raw transaction with one owned type-"02" output to `recipient`,
 * using the standard CryptoNote stealth-address construction so the scanner
 * genuinely detects it (mirrors transactions.test.ts).
 */
function craftReceiveTx(
  recipient: Created,
  tx: { sec: string; pub: string },
  amount: number,
  globalIndex: number,
): RawTransaction {
  const senderDerivation = ccxCrypto.generate_key_derivation(recipient.view.pub, tx.sec);
  const ownedKey = ccxCrypto.derive_public_key(senderDerivation, 0, recipient.spend.pub);
  return {
    extra: `01${tx.pub}`,
    vout: [{ amount, target: { type: "02", data: { key: ownedKey } } }],
    outputIndexes: [globalIndex],
    hash: `aa${globalIndex.toString(16).padStart(62, "0")}`,
    height: 1000 + globalIndex,
  };
}

/** Scan a crafted receive tx and return the single owned output (asserts presence). */
function ownedOutputFrom(
  recipient: Created,
  tx: { sec: string; pub: string },
  amount: number,
  gi: number,
) {
  const raw = craftReceiveTx(recipient, tx, amount, gi);
  const [out] = scanTransactionOutputs(raw, keysOf(recipient));
  if (!out) throw new Error("test setup: expected an owned output");
  return { raw, out };
}

// --- tests ----------------------------------------------------------------

describe("createWalletState", () => {
  it("creates empty state bound to the account address", () => {
    const wallet = created("aa");
    const state = createWalletState(accountOf(wallet));
    expect(state.address).toBe(wallet.public_addr);
    expect(state.scannedHeight).toBe(0);
    expect(state.outputs).toEqual([]);
    expect(state.spentKeyImages).toEqual([]);
    expect(state.transactions).toEqual([]);
  });

  it("throws without an address", () => {
    // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid input.
    expect(() => createWalletState({} as any)).toThrow(/address/i);
  });
});

describe("applyScannedTransaction — receives", () => {
  const recipient = created("aa");
  const tx = txKeypair("bb");

  it("adds owned outputs and reflects them in the balance", () => {
    const { raw, out } = ownedOutputFrom(recipient, tx, 1_500_000, 7);
    const state = applyScannedTransaction(
      createWalletState(accountOf(recipient)),
      { hash: raw.hash, height: raw.height, timestamp: 1700000000 },
      [out],
      [],
    );

    expect(state.outputs).toHaveLength(1);
    expect(getBalance(state)).toEqual({ total: 1_500_000, spendable: 1_500_000 });
    expect(getUnspentOutputs(state)).toHaveLength(1);

    const history = getTransactions(state);
    expect(history).toHaveLength(1);
    expect(history[0]?.direction).toBe("in");
    expect(history[0]?.amount).toBe(1_500_000);
    expect(history[0]?.timestamp).toBe(1700000000);
  });

  it("does not mutate the input state (immutability)", () => {
    const before = createWalletState(accountOf(recipient));
    const { raw, out } = ownedOutputFrom(recipient, tx, 999, 1);
    const after = applyScannedTransaction(
      before,
      { hash: raw.hash, height: raw.height },
      [out],
      [],
    );
    expect(before.outputs).toHaveLength(0);
    expect(after).not.toBe(before);
    expect(after.outputs).toHaveLength(1);
  });

  it("de-dupes outputs re-scanned across batches", () => {
    const { raw, out } = ownedOutputFrom(recipient, tx, 42, 5);
    let state = createWalletState(accountOf(recipient));
    state = applyScannedTransaction(state, { hash: raw.hash, height: raw.height }, [out], []);
    state = applyScannedTransaction(state, { hash: raw.hash, height: raw.height }, [out], []);
    expect(state.outputs).toHaveLength(1);
    expect(getBalance(state).total).toBe(42);
  });

  it("sums multiple owned outputs", () => {
    let state = createWalletState(accountOf(recipient));
    const a = ownedOutputFrom(recipient, txKeypair("c1"), 100, 10);
    const b = ownedOutputFrom(recipient, txKeypair("c2"), 250, 11);
    state = applyScannedTransaction(state, { hash: a.raw.hash, height: a.raw.height }, [a.out], []);
    state = applyScannedTransaction(state, { hash: b.raw.hash, height: b.raw.height }, [b.out], []);
    expect(getBalance(state).total).toBe(350);
    expect(getTransactions(state)).toHaveLength(2);
  });
});

describe("applyScannedTransaction — spends", () => {
  const recipient = created("aa");
  const tx = txKeypair("bb");

  it("marks an output spent when its key image appears in tx inputs", () => {
    const { raw, out } = ownedOutputFrom(recipient, tx, 2_000_000, 20);
    let state = applyScannedTransaction(
      createWalletState(accountOf(recipient)),
      { hash: raw.hash, height: raw.height },
      [out],
      [],
    );
    expect(getBalance(state).total).toBe(2_000_000);

    // A later transaction spends it: its key image shows up among the inputs.
    state = applyScannedTransaction(
      state,
      { hash: "ff".repeat(32), height: 2000 },
      [],
      [out.keyImage],
    );

    expect(state.spentKeyImages).toContain(out.keyImage);
    expect(getBalance(state)).toEqual({ total: 0, spendable: 0 });
    expect(getUnspentOutputs(state)).toHaveLength(0);

    const spendEntry = getTransactions(state).find((t) => t.direction === "out");
    expect(spendEntry).toBeDefined();
    expect(spendEntry?.amount).toBe(2_000_000);
  });

  it("reduces spendable when one of several outputs is spent", () => {
    let state = createWalletState(accountOf(recipient));
    const a = ownedOutputFrom(recipient, txKeypair("d1"), 1000, 30);
    const b = ownedOutputFrom(recipient, txKeypair("d2"), 4000, 31);
    state = applyScannedTransaction(state, { hash: a.raw.hash, height: a.raw.height }, [a.out], []);
    state = applyScannedTransaction(state, { hash: b.raw.hash, height: b.raw.height }, [b.out], []);
    expect(getBalance(state).spendable).toBe(5000);

    state = applyScannedTransaction(
      state,
      { hash: "ee".repeat(32), height: 9999 },
      [],
      [a.out.keyImage],
    );
    expect(getBalance(state).spendable).toBe(4000);
    expect(getUnspentOutputs(state).map((o) => o.amount)).toEqual([4000]);
  });

  it("ignores foreign key images that we do not own", () => {
    const { raw, out } = ownedOutputFrom(recipient, tx, 500, 40);
    let state = applyScannedTransaction(
      createWalletState(accountOf(recipient)),
      { hash: raw.hash, height: raw.height },
      [out],
      [],
    );
    state = applyScannedTransaction(
      state,
      { hash: "cc".repeat(32), height: 5 },
      [],
      ["11".repeat(32)],
    );
    expect(state.spentKeyImages).toHaveLength(0);
    expect(getBalance(state).total).toBe(500);
  });

  it("is idempotent when the same spend is scanned twice", () => {
    const { raw, out } = ownedOutputFrom(recipient, tx, 700, 50);
    let state = applyScannedTransaction(
      createWalletState(accountOf(recipient)),
      { hash: raw.hash, height: raw.height },
      [out],
      [],
    );
    state = applyScannedTransaction(
      state,
      { hash: "ab".repeat(32), height: 6 },
      [],
      [out.keyImage],
    );
    const afterFirst = state;
    state = applyScannedTransaction(
      state,
      { hash: "ab".repeat(32), height: 6 },
      [],
      [out.keyImage],
    );
    expect(state.spentKeyImages).toHaveLength(1);
    expect(state).toBe(afterFirst); // no change → same reference
  });
});

describe("getTransactions", () => {
  it("returns history newest-first by height", () => {
    const recipient = created("aa");
    let state = createWalletState(accountOf(recipient));
    const a = ownedOutputFrom(recipient, txKeypair("f1"), 1, 60); // height 1060
    const b = ownedOutputFrom(recipient, txKeypair("f2"), 1, 61); // height 1061
    state = applyScannedTransaction(state, { hash: a.raw.hash, height: a.raw.height }, [a.out], []);
    state = applyScannedTransaction(state, { hash: b.raw.hash, height: b.raw.height }, [b.out], []);
    const heights = getTransactions(state).map((t) => t.height);
    expect(heights).toEqual([1061, 1060]);
  });
});

describe("serialize / deserialize", () => {
  const recipient = created("aa");

  function populatedState() {
    const { raw, out } = ownedOutputFrom(recipient, txKeypair("bb"), 3_210_000, 70);
    let state = applyScannedTransaction(
      createWalletState(accountOf(recipient)),
      { hash: raw.hash, height: raw.height, timestamp: 1700001234 },
      [out],
      [],
    );
    state = { ...state, scannedHeight: 12345 };
    return { state, out };
  }

  it("round-trips a populated state", () => {
    const { state } = populatedState();
    const restored = deserializeWalletState(serializeWalletState(state));
    expect(restored).toEqual(state);
    expect(getBalance(restored).total).toBe(3_210_000);
  });

  it("round-trips state with a spend recorded", () => {
    const { state, out } = populatedState();
    const spent = applyScannedTransaction(
      state,
      { hash: "dd".repeat(32), height: 99999 },
      [],
      [out.keyImage],
    );
    const restored = deserializeWalletState(serializeWalletState(spent));
    expect(restored).toEqual(spent);
    expect(getBalance(restored)).toEqual({ total: 0, spendable: 0 });
  });

  it("embeds the schema version", () => {
    const { state } = populatedState();
    const parsed = JSON.parse(serializeWalletState(state));
    expect(parsed.version).toBe(WALLET_STATE_VERSION);
  });

  it("throws on non-JSON input", () => {
    expect(() => deserializeWalletState("not json {")).toThrow(/not valid JSON/i);
  });

  it("throws on an unknown version", () => {
    const bad = JSON.stringify({ version: 999, state: {} });
    expect(() => deserializeWalletState(bad)).toThrow(/version/i);
  });

  it("throws on a structurally corrupt state", () => {
    const bad = JSON.stringify({
      version: WALLET_STATE_VERSION,
      state: {
        address: "ccx7",
        scannedHeight: 0,
        outputs: "nope",
        spentKeyImages: [],
        transactions: [],
      },
    });
    expect(() => deserializeWalletState(bad)).toThrow(/outputs/i);
  });

  it("throws when an output has invalid fields", () => {
    const bad = JSON.stringify({
      version: WALLET_STATE_VERSION,
      state: {
        address: "ccx7",
        scannedHeight: 0,
        outputs: [{ amount: "lots" }],
        spentKeyImages: [],
        transactions: [],
      },
    });
    expect(() => deserializeWalletState(bad)).toThrow(/outputs\[0\]/i);
  });
});
