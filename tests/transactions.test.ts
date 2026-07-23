import { crypto as ccxCrypto, transactions as ccxTransactions } from "conceal-lib-js";
import { describe, expect, it } from "vitest";
import {
  absoluteToRelativeOffsets,
  assembleRing,
  type BuildTransactionInput,
  buildTransaction,
  decomposeDestinations,
  deriveInputKeyImage,
  extractTransactionPublicKey,
  type RawTransaction,
  type ScanKeys,
  type SpendableOutput,
  scanTransactionOutputs,
  scanTransactionOutputsAndDeposits,
  selectInputs,
} from "../src/transactions";

// --- helpers --------------------------------------------------------------

type Account = ReturnType<typeof ccxCrypto.create_address>;

function account(seedByte: string): Account {
  return ccxCrypto.create_address(ccxCrypto.sc_reduce32(seedByte.repeat(32)));
}

function keysOf(acc: Account): ScanKeys {
  return { spend: acc.spend, view: acc.view };
}

/** Random tx ephemeral keypair `(r, R)`. */
function txKeypair(seedByte: string): { sec: string; pub: string } {
  return ccxCrypto.generate_keys(ccxCrypto.sc_reduce32(seedByte.repeat(32)));
}

/**
 * Craft a raw transaction with a single type-"02" output sent to `recipient`, using
 * the standard CryptoNote stealth-address construction (sender side):
 *   D = generate_key_derivation(recipientViewPub, r)
 *   P = derive_public_key(D, outputIndex, recipientSpendPub)
 */
function craftReceiveTx(
  recipient: Account,
  tx: { sec: string; pub: string },
  amount: number,
  outputIndex: number,
  globalIndex: number,
): RawTransaction {
  const senderDerivation = ccxCrypto.generate_key_derivation(recipient.view.pub, tx.sec);
  // Pad with throwaway outputs so the owned one sits at `outputIndex`.
  const vout: RawTransaction["vout"] = [];
  const outputIndexes: number[] = [];
  for (let i = 0; i < outputIndex; i++) {
    // A foreign output (not derivable by `recipient`).
    vout.push({ amount: 1, target: { type: "02", data: { key: `0${i}`.padEnd(64, "0") } } });
    outputIndexes.push(1000 + i);
  }
  const ownedKey = ccxCrypto.derive_public_key(senderDerivation, outputIndex, recipient.spend.pub);
  vout.push({ amount, target: { type: "02", data: { key: ownedKey } } });
  outputIndexes.push(globalIndex);

  return {
    extra: `01${tx.pub}`, // TX_EXTRA_TAG_PUBKEY (0x01) + 32-byte R
    vout,
    outputIndexes,
    hash: "ab".repeat(32),
    height: 12345,
  };
}

// --- SCAN ------------------------------------------------------------------

describe("extractTransactionPublicKey", () => {
  it("extracts R from a well-formed extra", () => {
    const tx = txKeypair("bb");
    expect(extractTransactionPublicKey(`01${tx.pub}`)).toBe(tx.pub);
  });

  it("returns null when no tx public key is present", () => {
    expect(extractTransactionPublicKey("")).toBeNull();
    expect(extractTransactionPublicKey("020100")).toBeNull(); // nonce-only extra
  });
});

describe("scanTransactionOutputs — receive detection", () => {
  const recipient = account("aa");
  const tx = txKeypair("bb");

  it("detects an owned output with the right amount + global index", () => {
    const amount = 1230000;
    const rawTx = craftReceiveTx(recipient, tx, amount, 0, 7777);

    const owned = scanTransactionOutputs(rawTx, keysOf(recipient));
    expect(owned).toHaveLength(1);
    const [out] = owned;
    expect(out?.amount).toBe(amount);
    expect(out?.globalIndex).toBe(7777);
    expect(out?.outputIndex).toBe(0);
    expect(out?.txPublicKey).toBe(tx.pub);
    expect(out?.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(out?.keyImage).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces a key image that validates against a ring signature (proves spendability)", () => {
    const rawTx = craftReceiveTx(recipient, tx, 500000, 0, 42);
    const [out] = scanTransactionOutputs(rawTx, keysOf(recipient));
    expect(out).toBeDefined();
    if (!out) return;

    // The ephemeral secret x satisfies ge_scalarmult_base(x) === P, and signing a
    // ring containing P with x must verify under the recovered key image.
    const { ephemeralSecret, keyImage } = deriveInputKeyImage(
      {
        amount: out.amount,
        globalIndex: out.globalIndex,
        outputIndex: out.outputIndex,
        txPublicKey: out.txPublicKey,
        publicKey: out.publicKey,
        keyImage: out.keyImage,
      },
      keysOf(recipient),
    );
    expect(keyImage).toBe(out.keyImage);
    expect(ccxCrypto.ge_scalarmult_base(ephemeralSecret)).toBe(out.publicKey);

    const ring = [out.publicKey, account("cc").spend.pub, account("dd").spend.pub];
    const prefixHash = ccxCrypto.cn_fast_hash("deadbeef");
    const sigs = ccxCrypto.generate_ring_signature(prefixHash, keyImage, ring, ephemeralSecret, 0);
    expect(ccxCrypto.check_ring_signature(prefixHash, keyImage, ring, sigs)).toBe(true);
  });

  it("does NOT detect an output that belongs to a different account", () => {
    const rawTx = craftReceiveTx(recipient, tx, 999, 0, 1);
    const stranger = account("ee");
    expect(scanTransactionOutputs(rawTx, keysOf(stranger))).toHaveLength(0);
  });

  it("finds the owned output among several foreign ones (non-zero output index)", () => {
    const rawTx = craftReceiveTx(recipient, tx, 250000, 3, 9001);
    const owned = scanTransactionOutputs(rawTx, keysOf(recipient));
    expect(owned).toHaveLength(1);
    expect(owned[0]?.outputIndex).toBe(3);
    expect(owned[0]?.globalIndex).toBe(9001);
    expect(owned[0]?.amount).toBe(250000);
  });

  it("detects multiple owned outputs in one transaction", () => {
    // Two owned outputs (indexes 0 and 1) to the same recipient.
    const senderDerivation = ccxCrypto.generate_key_derivation(recipient.view.pub, tx.sec);
    const k0 = ccxCrypto.derive_public_key(senderDerivation, 0, recipient.spend.pub);
    const k1 = ccxCrypto.derive_public_key(senderDerivation, 1, recipient.spend.pub);
    const rawTx: RawTransaction = {
      extra: `01${tx.pub}`,
      vout: [
        { amount: 100, target: { type: "02", data: { key: k0 } } },
        { amount: 200, target: { type: "02", data: { key: k1 } } },
      ],
      outputIndexes: [11, 22],
    };
    const owned = scanTransactionOutputs(rawTx, keysOf(recipient));
    expect(owned).toHaveLength(2);
    expect(owned.map((o) => o.amount).sort((a, b) => a - b)).toEqual([100, 200]);
    expect(owned.map((o) => o.globalIndex).sort((a, b) => a - b)).toEqual([11, 22]);
  });

  it("a type-03 deposit output is recovered as a deposit, NOT a spendable output", () => {
    const senderDerivation = ccxCrypto.generate_key_derivation(recipient.view.pub, tx.sec);
    const ownedKey = ccxCrypto.derive_public_key(senderDerivation, 0, recipient.spend.pub);
    const rawTx: RawTransaction = {
      extra: `01${tx.pub}`,
      vout: [
        {
          amount: 8000000,
          target: { type: "03", data: { keys: [ownedKey], term: 5040, required_signatures: 1 } },
        },
      ],
      outputIndexes: [314],
    };
    // Spendable scan EXCLUDES the type-03 deposit (legacy `availableAmount` skips type 03).
    const owned = scanTransactionOutputs(rawTx, keysOf(recipient));
    expect(owned).toHaveLength(0);
    // It is recovered as an OwnedDeposit instead.
    const { outputs, deposits } = scanTransactionOutputsAndDeposits(rawTx, keysOf(recipient));
    expect(outputs).toHaveLength(0);
    expect(deposits).toHaveLength(1);
    expect(deposits[0]?.amount).toBe(8000000);
    expect(deposits[0]?.publicKey).toBe(ownedKey);
    expect(deposits[0]?.globalIndex).toBe(314);
    expect(deposits[0]?.term).toBe(5040);
  });

  it("falls back to in-tx index when the tx carries no global indexes", () => {
    const rawTx = craftReceiveTx(recipient, tx, 1, 0, 555);
    const noIdx: RawTransaction = { extra: rawTx.extra, vout: rawTx.vout };
    const owned = scanTransactionOutputs(noIdx, keysOf(recipient));
    expect(owned[0]?.globalIndex).toBe(0); // == outputIndex
  });

  it("returns [] for a tx with no tx public key or no outputs", () => {
    expect(scanTransactionOutputs({ extra: "", vout: [] }, keysOf(recipient))).toHaveLength(0);
    expect(
      scanTransactionOutputs({ extra: `01${tx.pub}`, vout: [] }, keysOf(recipient)),
    ).toHaveLength(0);
  });

  it("throws on malformed keys", () => {
    const rawTx = craftReceiveTx(recipient, tx, 1, 0, 1);
    expect(() =>
      scanTransactionOutputs(rawTx, { spend: { sec: "x", pub: "y" }, view: recipient.view }),
    ).toThrow();
  });

  it("agrees with lib-js scanReceiveOutputs on ownership", () => {
    const rawTx = craftReceiveTx(recipient, tx, 42, 0, 1);
    const vouts = rawTx.vout.map((o) => ({
      type: o.target.type,
      key: o.target.data.key,
      keys: o.target.data.keys,
    }));
    const libOwned = ccxTransactions.scanReceiveOutputs(
      tx.pub,
      recipient.view.sec,
      recipient.spend.pub,
      vouts,
    );
    expect(libOwned).toBe(true);
    expect(scanTransactionOutputs(rawTx, keysOf(recipient)).length).toBeGreaterThan(0);
  });
});

// --- BUILD helpers (deterministic math) ------------------------------------

describe("decomposeDestinations", () => {
  const dest = (amount: number) => ({
    spendPublicKey: "11".repeat(32),
    viewPublicKey: "22".repeat(32),
    amount,
  });

  it("decomposes an amount into power-of-ten digits and sorts ascending", () => {
    const out = decomposeDestinations([dest(1230045)]);
    expect(out.map((o) => o.amount)).toEqual([5, 40, 30000, 200000, 1000000]);
  });

  it("drops zero digits and merges multiple destinations", () => {
    const out = decomposeDestinations([dest(100), dest(20)]);
    expect(out.map((o) => o.amount).sort((a, b) => a - b)).toEqual([20, 100]);
  });

  it("returns [] for a zero amount", () => {
    expect(decomposeDestinations([dest(0)])).toEqual([]);
  });
});

describe("absoluteToRelativeOffsets", () => {
  it("keeps the first offset and deltas the rest", () => {
    expect(absoluteToRelativeOffsets([10, 13, 20, 21])).toEqual([10, 3, 7, 1]);
  });
  it("handles empty + single", () => {
    expect(absoluteToRelativeOffsets([])).toEqual([]);
    expect(absoluteToRelativeOffsets([99])).toEqual([99]);
  });
});

describe("selectInputs", () => {
  const out = (amount: number, gi: number): SpendableOutput => ({
    amount,
    globalIndex: gi,
    outputIndex: 0,
    txPublicKey: "aa".repeat(32),
    publicKey: "bb".repeat(32),
    keyImage: `${gi}`.padStart(64, "0"),
  });
  /** Deterministic ascending pick (index 0 every time). */
  const asc = () => 0;

  it("selects enough non-dust outputs to cover the target", () => {
    const sel = selectInputs([out(100, 1), out(200, 2), out(300, 3)], 250, 0, asc);
    expect(sel.total).toBeGreaterThanOrEqual(250);
    expect(sel.selected.length).toBeGreaterThan(0);
  });

  it("skips dust outputs", () => {
    const sel = selectInputs([out(5, 1), out(1000, 2)], 100, 10, asc);
    expect(sel.selected.every((o) => o.amount > 10)).toBe(true);
    expect(sel.total).toBe(1000);
  });

  it("throws when the non-dust balance can't cover the target", () => {
    expect(() => selectInputs([out(50, 1)], 1000, 0, asc)).toThrow(/insufficient/i);
  });

  it("is deterministic with an ascending picker", () => {
    const outs = [out(100, 1), out(200, 2), out(300, 3)];
    const a = selectInputs(outs, 250, 0, asc);
    const b = selectInputs(outs, 250, 0, asc);
    expect(a.selected.map((o) => o.globalIndex)).toEqual(b.selected.map((o) => o.globalIndex));
  });

  it("skips non-pretty (un-mixable) outputs during selection", () => {
    // 12345 alone would cover 5000, but is not pretty → must use the pretty pool.
    const sel = selectInputs([out(12345, 1), out(1000, 2), out(4000, 3)], 5000, 0, asc);
    expect(sel.selected.every((o) => o.amount !== 12345)).toBe(true);
    expect(sel.total).toBeGreaterThanOrEqual(5000);
  });

  it("throws when only non-pretty outputs could cover the target", () => {
    expect(() => selectInputs([out(12345, 1), out(99999, 2)], 1000, 0, asc)).toThrow(
      /non-pretty, un-mixable/,
    );
  });
});

describe("assembleRing", () => {
  const real: SpendableOutput = {
    amount: 100,
    globalIndex: 50,
    outputIndex: 0,
    txPublicKey: "aa".repeat(32),
    publicKey: "ff".repeat(32),
    keyImage: "00".repeat(32),
  };
  const decoy = (gi: number): { globalIndex: number; publicKey: string } => ({
    globalIndex: gi,
    publicKey: `${gi}`.padStart(64, "0"),
  });

  it("inserts the real output at the sorted position and reports realIndex", () => {
    const { ringPublicKeys, keyOffsets, realIndex } = assembleRing(
      real,
      [decoy(10), decoy(90), decoy(30)],
      3,
    );
    // sorted decoys 10,30,90; real 50 → ring 10,30,50,90; realIndex 2.
    expect(realIndex).toBe(2);
    expect(ringPublicKeys[realIndex]).toBe(real.publicKey);
    // abs indexes 10,30,50,90 → relative offsets.
    expect(keyOffsets).toEqual([10, 20, 20, 40]);
  });

  it("respects the mixin cap and skips a decoy colliding with the real index", () => {
    const { ringPublicKeys } = assembleRing(real, [decoy(50), decoy(10), decoy(20), decoy(30)], 2);
    // decoy at gi 50 collides → skipped; cap 2 → ring = 2 decoys + real = 3.
    expect(ringPublicKeys).toHaveLength(3);
  });

  it("with zero decoys produces a 1-member ring (real only)", () => {
    const { ringPublicKeys, realIndex, keyOffsets } = assembleRing(real, [], 0);
    expect(ringPublicKeys).toEqual([real.publicKey]);
    expect(realIndex).toBe(0);
    expect(keyOffsets).toEqual([50]);
  });
});

// --- BUILD full round-trip -------------------------------------------------

describe("buildTransaction", () => {
  const sender = account("a1");
  const recipient = account("b2");

  // A spendable output the sender genuinely owns (so key images verify).
  function ownedSpendable(tx: { sec: string; pub: string }, amount: number, gi: number) {
    const raw = craftReceiveTx(sender, tx, amount, 0, gi);
    const [out] = scanTransactionOutputs(raw, keysOf(sender));
    if (!out) throw new Error("setup: failed to craft owned spendable");
    const spendable: SpendableOutput = {
      amount: out.amount,
      globalIndex: out.globalIndex,
      outputIndex: out.outputIndex,
      txPublicKey: out.txPublicKey,
      publicKey: out.publicKey,
      keyImage: out.keyImage,
    };
    return spendable;
  }

  function baseInput(): BuildTransactionInput {
    const utxo = ownedSpendable(txKeypair("c3"), 5000000, 100);
    const decoyKey = (n: number) => account(`d${n}`).spend.pub;
    return {
      keys: keysOf(sender),
      destinations: [
        { spendPublicKey: recipient.spend.pub, viewPublicKey: recipient.view.pub, amount: 1000000 },
      ],
      changeKeys: { spendPublicKey: sender.spend.pub, viewPublicKey: sender.view.pub },
      unspentOutputs: [utxo],
      decoys: [
        {
          amount: 5000000,
          outs: [
            { globalIndex: 200, publicKey: decoyKey(1) },
            { globalIndex: 300, publicKey: decoyKey(2) },
          ],
        },
      ],
      fee: 10000,
      mixin: 2,
    };
  }

  it("assembles inputs, outputs, fee, and correct change math", () => {
    const built = buildTransaction(baseInput());
    expect(built.inputsAmount).toBe(5000000);
    expect(built.sentAmount).toBe(1000000);
    expect(built.fee).toBe(10000);
    expect(built.changeAmount).toBe(5000000 - 1000000 - 10000);
    // sent (1,000,000) + change (3,990,000) decomposed into digit outputs.
    const outTotal = built.outputs.reduce((s, o) => s + o.amount, 0);
    expect(outTotal).toBe(built.sentAmount + built.changeAmount);
    expect(built.inputs).toHaveLength(1);
    expect(built.txPublicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(built.txSecretKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it("folds a nodeFee destination into ascending type-02 output order with change", () => {
    // Pretty UTXO; change includes a digit smaller than the 10000 node fee so a
    // glued append would fingerprint the fee — joint decompose must sort them.
    const utxo = ownedSpendable(txKeypair("c9"), 2_000_000, 101);
    const operator = account("fe");
    const built = buildTransaction({
      keys: keysOf(sender),
      destinations: [
        {
          spendPublicKey: recipient.spend.pub,
          viewPublicKey: recipient.view.pub,
          amount: 1_000_000,
        },
        {
          spendPublicKey: operator.spend.pub,
          viewPublicKey: operator.view.pub,
          amount: 10_000,
        },
      ],
      changeKeys: { spendPublicKey: sender.spend.pub, viewPublicKey: sender.view.pub },
      unspentOutputs: [utxo],
      decoys: [],
      fee: 1000,
      mixin: 0,
    });
    // inputs 2_000_000 − sent 1_010_000 − fee 1000 = change 989_000 → … + 9000 + …
    expect(built.changeAmount).toBe(989_000);
    const amounts = built.outputs.map((o) => o.amount);
    expect(amounts).toEqual([...amounts].sort((a, b) => a - b));
    expect(amounts).toContain(10_000);
    expect(amounts.indexOf(9000)).toBeLessThan(amounts.indexOf(10_000));
  });

  it("default extra is byte-identical to 01 + R (no hook)", () => {
    const built = buildTransaction(baseInput());
    expect(built.extra).toBe(`01${built.txPublicKey}`);
    // And it is the extra fed to the serializer.
    expect(structOf(built).extra).toBe(built.extra);
  });

  it("derives R = rG and unique one-time output keys", () => {
    const built = buildTransaction(baseInput());
    expect(ccxCrypto.ge_scalarmult_base(built.txSecretKey)).toBe(built.txPublicKey);
    const keys = built.outputs.map((o) => o.publicKey);
    expect(new Set(keys).size).toBe(keys.length);
    for (const k of keys) expect(k).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces a ring signature per input that verifies over the prefix hash", () => {
    const built = buildTransaction(baseInput());
    for (const input of built.inputs) {
      expect(input.signatures).toHaveLength(input.ringPublicKeys.length);
      const ok = ccxCrypto.check_ring_signature(
        built.prefixHash,
        input.keyImage,
        input.ringPublicKeys,
        input.signatures,
      );
      expect(ok).toBe(true);
      // The real output's key sits at realIndex.
      expect(input.ringPublicKeys[input.realIndex]).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("recipient can detect the output built for them (scan ↔ build interop)", () => {
    const built = buildTransaction(baseInput());
    // Reconstruct the recipient's view: derivation from R + their view secret.
    const derivation = ccxCrypto.generate_key_derivation(built.txPublicKey, recipient.view.sec);
    // The first decomposed output that the recipient owns should match by derive_public_key.
    const recipientKeys = built.outputs.filter((o, i) => {
      const derived = ccxCrypto.derive_public_key(derivation, i, recipient.spend.pub);
      return derived === o.publicKey;
    });
    expect(recipientKeys.length).toBeGreaterThan(0);
    const recipientTotal = recipientKeys.reduce((s, o) => s + o.amount, 0);
    expect(recipientTotal).toBe(built.sentAmount);
  });

  it("orders inputs by descending key image", () => {
    // Two owned UTXOs → two inputs that must be sorted by descending key image.
    const utxo1 = ownedSpendable(txKeypair("c3"), 3000000, 100);
    const utxo2 = ownedSpendable(txKeypair("c4"), 4000000, 101);
    const input = baseInput();
    const built = buildTransaction({
      ...input,
      unspentOutputs: [utxo1, utxo2],
      decoys: [
        { amount: 3000000, outs: [{ globalIndex: 500, publicKey: account("e1").spend.pub }] },
        { amount: 4000000, outs: [{ globalIndex: 600, publicKey: account("e2").spend.pub }] },
      ],
      destinations: [
        { spendPublicKey: recipient.spend.pub, viewPublicKey: recipient.view.pub, amount: 5000000 },
      ],
    });
    expect(built.inputs.length).toBe(2);
    const imgs = built.inputs.map((i) => i.keyImage);
    const sorted = [...imgs].sort((a, b) => (a < b ? 1 : a > b ? -1 : 0));
    expect(imgs).toEqual(sorted);
  });

  // Rebuild the lib-js tx struct from a BuiltTransaction exactly as buildTransaction
  // does (vin in input order with RELATIVE key offsets, vout, extra = 01 || R), so
  // tests can assert against lib-js's serializer directly.
  function structOf(built: ReturnType<typeof buildTransaction>) {
    return {
      version: 1,
      unlock_time: 0,
      vin: built.inputs.map((i) => ({
        type: "input_to_key" as const,
        amount: i.amount,
        key_offsets: i.keyOffsets,
        k_image: i.keyImage,
      })),
      vout: built.outputs.map((o) => ({
        amount: o.amount,
        target: { type: "txout_to_key" as const, data: { key: o.publicKey } },
      })),
      extra: `01${built.txPublicKey}`,
      signatures: built.inputs.map((i) => i.signatures),
    };
  }

  it("prefixHash equals lib-js getTransactionPrefixHash of the assembled struct", () => {
    const built = buildTransaction(baseInput());
    const struct = structOf(built);
    expect(built.prefixHash).toBe(ccxTransactions.getTransactionPrefixHash(struct));
    // And the prefix hash is cn_fast_hash of the header-only serialization.
    const headerOnly = ccxTransactions.serializeTransaction(struct, true);
    expect(ccxCrypto.cn_fast_hash(headerOnly)).toBe(built.prefixHash);
  });

  it("returns a broadcast-ready serialized blob + tx hash (valid hex, round-trips)", () => {
    const built = buildTransaction(baseInput());
    // serialized is non-empty lowercase hex; hash is a 32-byte hex.
    expect(built.serialized).toMatch(/^[0-9a-f]+$/);
    expect(built.serialized.length % 2).toBe(0);
    expect(built.hash).toMatch(/^[0-9a-f]{64}$/);

    // The serialized blob matches lib-js's full serialization, and its header-only
    // re-derivation yields the same prefixHash.
    const struct = structOf(built);
    const { raw, hash } = ccxTransactions.serializeTransactionWithHash(struct);
    expect(built.serialized).toBe(raw);
    expect(built.hash).toBe(hash);
    expect(ccxCrypto.cn_fast_hash(ccxTransactions.serializeTransaction(struct, true))).toBe(
      built.prefixHash,
    );
  });

  it("serializes vin key_offsets in RELATIVE form (first absolute, rest small deltas)", () => {
    // Real UTXO at global index 100; decoys at 200 and 300 → sorted ring 100,200,300.
    // Relative offsets: [100, 100, 100] (first = absolute, rest = deltas).
    const built = buildTransaction(baseInput());
    expect(built.inputs).toHaveLength(1);
    const input = built.inputs[0];
    expect(input).toBeDefined();
    if (!input) return;

    const offsets = input.keyOffsets;
    expect(offsets.length).toBeGreaterThan(1);
    // First offset is the absolute global index of the smallest ring member (>= 100,
    // the real output's global index, since the real output is the smallest here).
    expect(offsets[0]).toBe(100);
    // Subsequent offsets are deltas (here 200-100, 300-200) — strictly smaller than
    // the absolute first when the ring members are densely spaced.
    expect(offsets.slice(1)).toEqual([100, 100]);
    // Recovering absolutes by cumulative sum yields a strictly ascending sequence.
    const absolutes = offsets.reduce<number[]>((acc, off, idx) => {
      acc.push(idx === 0 ? off : (acc[idx - 1] as number) + off);
      return acc;
    }, []);
    expect(absolutes).toEqual([100, 200, 300]);
    for (let i = 1; i < absolutes.length; i++) {
      expect(absolutes[i] as number).toBeGreaterThan(absolutes[i - 1] as number);
    }
    // The struct fed to the serializer carries exactly these relative offsets.
    expect(structOf(built).vin[0]?.key_offsets).toEqual(offsets);
  });

  it("validates inputs and throws on bad arguments", () => {
    const good = baseInput();
    expect(() => buildTransaction({ ...good, destinations: [] })).toThrow(/destination/i);
    expect(() => buildTransaction({ ...good, fee: -1 })).toThrow(/fee/i);
    expect(() =>
      buildTransaction({
        ...good,
        destinations: [{ spendPublicKey: "x", viewPublicKey: "y", amount: 1 }],
      }),
    ).toThrow(/64-char hex/i);
    const [firstUtxo] = good.unspentOutputs;
    expect(firstUtxo).toBeDefined();
    if (firstUtxo) {
      expect(() =>
        buildTransaction({ ...good, unspentOutputs: [{ ...firstUtxo, amount: 1 }] }),
      ).toThrow(/insufficient/i);
    }
  });
});
