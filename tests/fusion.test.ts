import { crypto as ccxCrypto } from "conceal-lib-js";
import { describe, expect, it } from "vitest";
import {
  type BuildFusionTransactionInput,
  buildFusionTransaction,
  DEFAULT_MIXIN,
  DUST_THRESHOLD,
  FUSION_TX_MAX_SIZE,
  FUSION_TX_MIN_INPUT_COUNT,
  getApproximateMaximumInputCount,
  getApproximateTransactionSize,
  isAmountApplicableInFusionInput,
  isOptimizationNeeded,
  MAX_FUSION_OUTPUTS,
  MINIMUM_FEE_V2,
  OPTIMIZE_OUTPUTS,
  OPTIMIZE_THRESHOLD,
  PRETTY_AMOUNTS,
  selectFusionInputs,
  UPGRADE_HEIGHT_V4,
} from "../src/fusion";
import type { ScanKeys } from "../src/transactions";
import {
  type RawTransaction,
  type SpendableOutput,
  scanTransactionOutputs,
} from "../src/transactions";

// --- helpers (mirroring tests/transactions.test.ts) ------------------------

type Account = ReturnType<typeof ccxCrypto.create_address>;

function account(seedByte: string): Account {
  return ccxCrypto.create_address(ccxCrypto.sc_reduce32(seedByte.repeat(32)));
}

function keysOf(acc: Account): ScanKeys {
  return { spend: acc.spend, view: acc.view };
}

function txKeypair(seedByte: string): { sec: string; pub: string } {
  return ccxCrypto.generate_keys(ccxCrypto.sc_reduce32(seedByte.repeat(32)));
}

/** A raw tx with a single type-"02" output owned by `recipient` at `outputIndex`/`globalIndex`. */
function craftReceiveTx(
  recipient: Account,
  tx: { sec: string; pub: string },
  amount: number,
  outputIndex: number,
  globalIndex: number,
): RawTransaction {
  const senderDerivation = ccxCrypto.generate_key_derivation(recipient.view.pub, tx.sec);
  const vout: RawTransaction["vout"] = [];
  const outputIndexes: number[] = [];
  for (let i = 0; i < outputIndex; i++) {
    vout.push({ amount: 1, target: { type: "02", data: { key: `0${i}`.padEnd(64, "0") } } });
    outputIndexes.push(1000 + i);
  }
  const ownedKey = ccxCrypto.derive_public_key(senderDerivation, outputIndex, recipient.spend.pub);
  vout.push({ amount, target: { type: "02", data: { key: ownedKey } } });
  outputIndexes.push(globalIndex);
  return {
    extra: `01${tx.pub}`,
    vout,
    outputIndexes,
    hash: "ab".repeat(32),
    height: 12345,
  };
}

/** A plain (non-owned) spendable output — enough for selection / status math. */
function out(amount: number, gi: number): SpendableOutput {
  return {
    amount,
    globalIndex: gi,
    outputIndex: 0,
    txPublicKey: "aa".repeat(32),
    publicKey: "bb".repeat(32),
    keyImage: `${gi}`.padStart(64, "0"),
  };
}

/** A deterministic "shuffle" seam that always picks index 0 (ascending / first bucket). */
const pickFirst = (_n: number) => 0;

const HEIGHT = 1_000_000; // well above UPGRADE_HEIGHT_V4

// --- isAmountApplicableInFusionInput ---------------------------------------

describe("isAmountApplicableInFusionInput", () => {
  const threshold = OPTIMIZE_THRESHOLD; // 900_000_000

  it("accepts pretty amounts and reports the power-of-ten bucket", () => {
    expect(isAmountApplicableInFusionInput(1, threshold, HEIGHT)).toEqual({
      applicable: true,
      amountPowerOfTen: 0,
    });
    expect(isAmountApplicableInFusionInput(90, threshold, HEIGHT)).toEqual({
      applicable: true,
      amountPowerOfTen: 1,
    });
    expect(isAmountApplicableInFusionInput(100, threshold, HEIGHT)).toEqual({
      applicable: true,
      amountPowerOfTen: 2,
    });
    // 5_000_000 = 5 × 10^6 → PRETTY_AMOUNTS idx 58 → floor(58/9) = 6.
    expect(isAmountApplicableInFusionInput(5_000_000, threshold, HEIGHT)).toEqual({
      applicable: true,
      amountPowerOfTen: 6,
    });
  });

  it("rejects a non-pretty amount (e.g. change like 12345)", () => {
    expect(isAmountApplicableInFusionInput(12345, threshold, HEIGHT)).toEqual({
      applicable: false,
    });
  });

  it("rejects amounts at or above the threshold (strict <)", () => {
    expect(isAmountApplicableInFusionInput(threshold, threshold, HEIGHT).applicable).toBe(false);
    // 1_000_000_000 is pretty but >= threshold (900M).
    expect(isAmountApplicableInFusionInput(1_000_000_000, threshold, HEIGHT).applicable).toBe(
      false,
    );
  });

  it("enforces the below-V4 dust lower bound, dropped at/after V4", () => {
    // amount 1 is pretty but < DUST_THRESHOLD (10) → rejected below V4.
    expect(isAmountApplicableInFusionInput(1, threshold, UPGRADE_HEIGHT_V4 - 1).applicable).toBe(
      false,
    );
    // DUST_THRESHOLD (10) itself is pretty and passes the bound below V4.
    expect(
      isAmountApplicableInFusionInput(DUST_THRESHOLD, threshold, UPGRADE_HEIGHT_V4 - 1).applicable,
    ).toBe(true);
    // At/after V4 the lower bound is dropped, so amount 1 qualifies again.
    expect(isAmountApplicableInFusionInput(1, threshold, UPGRADE_HEIGHT_V4).applicable).toBe(true);
  });

  it("bucket math: each decade of 9 pretty entries shares one power-of-ten", () => {
    // 1..9 → bucket 0; 10..90 → bucket 1; 100..900 → bucket 2.
    for (const a of [1, 2, 3, 4, 5, 6, 7, 8, 9]) {
      expect(isAmountApplicableInFusionInput(a, threshold, HEIGHT).amountPowerOfTen).toBe(0);
    }
    for (const a of [10, 20, 30, 40, 50, 60, 70, 80, 90]) {
      expect(isAmountApplicableInFusionInput(a, threshold, HEIGHT).amountPowerOfTen).toBe(1);
    }
  });
});

// --- size model ------------------------------------------------------------

describe("size model (Currency byte model)", () => {
  it("getApproximateMaximumInputCount(30000, 8, 5) === 65 (the effective cap)", () => {
    expect(
      getApproximateMaximumInputCount(FUSION_TX_MAX_SIZE, MAX_FUSION_OUTPUTS, DEFAULT_MIXIN),
    ).toBe(65);
  });

  it("getApproximateTransactionSize is monotonic and matches the byte formula", () => {
    // header 42 + outputs (n*43) + inputs (n*(112 + mixin*68)).
    expect(getApproximateTransactionSize(12, 1, 5)).toBe(5509);
    expect(getApproximateTransactionSize(13, 1, 5)).toBeGreaterThan(
      getApproximateTransactionSize(12, 1, 5),
    );
  });
});

// --- isOptimizationNeeded --------------------------------------------------

describe("isOptimizationNeeded", () => {
  it("returns false when there are fewer than OPTIMIZE_OUTPUTS unspent outputs", () => {
    const outs = Array.from({ length: OPTIMIZE_OUTPUTS - 1 }, (_, i) => out(100, i));
    const status = isOptimizationNeeded({
      unspentOutputs: outs,
      balance: 1_000_000_000_000,
      blockchainHeight: HEIGHT,
    });
    expect(status).toEqual({ isNeeded: false, unspentOutputs: OPTIMIZE_OUTPUTS - 1 });
  });

  it("returns true with >= 100 unspent and a bucket holding >= 100 ready outs", () => {
    // 120 outputs of a single pretty amount (100, bucket 2), all below the default threshold.
    // The ×10 climb only runs while threshold <= balance, so balance must reach the
    // starting threshold for the readiness scan to fire (matches the legacy gate).
    const outs = Array.from({ length: 120 }, (_, i) => out(100, i));
    const status = isOptimizationNeeded({
      unspentOutputs: outs,
      balance: OPTIMIZE_THRESHOLD,
      blockchainHeight: HEIGHT,
    });
    expect(status.unspentOutputs).toBe(120);
    expect(status.isNeeded).toBe(true);
  });

  it("is NOT needed when no single bucket reaches 100 ready outs", () => {
    // 60 outs of amount 100 (bucket 2) + 60 outs of amount 1000 (bucket 3): neither bucket >= 100.
    // Balance reaches the threshold so the readiness scan DOES run — `isNeeded` is false
    // purely because no bucket has >= OPTIMIZE_OUTPUTS (100) eligible outs.
    const outs = [
      ...Array.from({ length: 60 }, (_, i) => out(100, i)),
      ...Array.from({ length: 60 }, (_, i) => out(1000, 1000 + i)),
    ];
    const status = isOptimizationNeeded({
      unspentOutputs: outs,
      balance: OPTIMIZE_THRESHOLD,
      blockchainHeight: HEIGHT,
    });
    expect(status.unspentOutputs).toBe(120);
    expect(status.isNeeded).toBe(false);
  });

  it("climbs the threshold ×10 to find a ready bucket above the starting threshold", () => {
    // 150 outs of amount 5_000_000_000 (pretty). At the default 900M start threshold they are
    // NOT eligible (>= threshold), but after ×10 climbs to 9_000_000_000 they qualify.
    const amount = 5_000_000_000;
    const outs = Array.from({ length: 150 }, (_, i) => out(amount, i));
    const balance = 150 * amount;
    const status = isOptimizationNeeded({
      unspentOutputs: outs,
      balance,
      blockchainHeight: HEIGHT,
      threshold: OPTIMIZE_THRESHOLD,
    });
    expect(status.isNeeded).toBe(true);
    // With a balance below even the first climbed threshold the loop can't reach them.
    const starved = isOptimizationNeeded({
      unspentOutputs: outs,
      balance: OPTIMIZE_THRESHOLD, // threshold <= balance true once, but amount >= threshold
      blockchainHeight: HEIGHT,
      threshold: OPTIMIZE_THRESHOLD,
    });
    expect(starved.isNeeded).toBe(false);
  });
});

// --- selectFusionInputs ----------------------------------------------------

describe("selectFusionInputs", () => {
  it("picks the right bucket, returns >= 12 ascending outputs", () => {
    // 15 pretty outs in bucket 2 (amount 100..900), plus a few non-qualifying.
    const bucketOuts = Array.from({ length: 15 }, (_, i) => out(100, i));
    const noise = [out(12345, 500), out(1000, 600)]; // non-pretty + different bucket (only 1)
    const result = selectFusionInputs(
      [...noise, ...bucketOuts],
      OPTIMIZE_THRESHOLD,
      HEIGHT,
      FUSION_TX_MIN_INPUT_COUNT,
      undefined,
      pickFirst,
    );
    expect(result).not.toBeNull();
    if (!result) return;
    expect(result.bucketPowerOfTen).toBe(2);
    expect(result.selected.length).toBeGreaterThanOrEqual(FUSION_TX_MIN_INPUT_COUNT);
    // ascending by amount
    const amounts = result.selected.map((o) => o.amount);
    expect([...amounts].sort((a, b) => a - b)).toEqual(amounts);
    expect(result.selected.every((o) => o.amount === 100)).toBe(true);
  });

  it("down-samples to maxInputCount and re-sorts ascending", () => {
    const bucketOuts = Array.from({ length: 30 }, (_, i) => out(100, i));
    const result = selectFusionInputs(
      bucketOuts,
      OPTIMIZE_THRESHOLD,
      HEIGHT,
      FUSION_TX_MIN_INPUT_COUNT,
      20, // maxInputCount
      pickFirst,
    );
    expect(result).not.toBeNull();
    if (!result) return;
    expect(result.selected).toHaveLength(20);
    const amounts = result.selected.map((o) => o.amount);
    expect([...amounts].sort((a, b) => a - b)).toEqual(amounts);
  });

  it("returns null when no bucket has >= minInputCount eligible outs", () => {
    // 11 outs (< 12) in bucket 2.
    const outs = Array.from({ length: 11 }, (_, i) => out(100, i));
    const result = selectFusionInputs(
      outs,
      OPTIMIZE_THRESHOLD,
      HEIGHT,
      FUSION_TX_MIN_INPUT_COUNT,
      undefined,
      pickFirst,
    );
    expect(result).toBeNull();
  });

  it("returns null when there are no eligible outputs at all", () => {
    const outs = Array.from({ length: 20 }, (_, i) => out(12345, i)); // non-pretty
    expect(
      selectFusionInputs(
        outs,
        OPTIMIZE_THRESHOLD,
        HEIGHT,
        FUSION_TX_MIN_INPUT_COUNT,
        undefined,
        pickFirst,
      ),
    ).toBeNull();
  });
});

// --- buildFusionTransaction ------------------------------------------------

describe("buildFusionTransaction", () => {
  const sender = account("a1");

  /** A spendable output the sender genuinely owns (so key images verify). */
  function ownedSpendable(
    tx: { sec: string; pub: string },
    amount: number,
    gi: number,
  ): SpendableOutput {
    const raw = craftReceiveTx(sender, tx, amount, 0, gi);
    const [scanned] = scanTransactionOutputs(raw, keysOf(sender));
    if (!scanned) throw new Error("setup: failed to craft owned spendable");
    return {
      amount: scanned.amount,
      globalIndex: scanned.globalIndex,
      outputIndex: scanned.outputIndex,
      txPublicKey: scanned.txPublicKey,
      publicKey: scanned.publicKey,
      keyImage: scanned.keyImage,
    };
  }

  /** A 2-char hex seed byte for index `i` (sc_reduce32 requires hex input). */
  const hexSeed = (i: number) => (i % 256).toString(16).padStart(2, "0");

  /** N owned pretty-amount inputs all in one bucket (amount 5_000_000), unique decoys per amount. */
  function fixture(count: number): BuildFusionTransactionInput {
    const fusionInputs = Array.from({ length: count }, (_, i) =>
      ownedSpendable(txKeypair(hexSeed(i)), 5_000_000, 100 + i),
    );
    const decoyKey = (n: number) => account(`d${n}`).spend.pub;
    return {
      keys: keysOf(sender),
      selfKeys: { spendPublicKey: sender.spend.pub, viewPublicKey: sender.view.pub },
      fusionInputs,
      decoys: [
        {
          amount: 5_000_000,
          outs: [
            { globalIndex: 9001, publicKey: decoyKey(1) },
            { globalIndex: 9002, publicKey: decoyKey(2) },
            { globalIndex: 9003, publicKey: decoyKey(3) },
            { globalIndex: 9004, publicKey: decoyKey(4) },
            { globalIndex: 9005, publicKey: decoyKey(5) },
          ],
        },
      ],
    };
  }

  it("builds a self-send for Σ inputs − fee, with default fee 1000 and mixin 5", () => {
    const input = fixture(FUSION_TX_MIN_INPUT_COUNT); // 12 inputs
    const built = buildFusionTransaction(input);

    const inputsAmount = 12 * 5_000_000;
    expect(built.inputsAmount).toBe(inputsAmount);
    expect(built.fee).toBe(MINIMUM_FEE_V2); // 1000
    expect(built.sentAmount).toBe(inputsAmount - MINIMUM_FEE_V2);
    // Self-consolidation: no change output, the whole self-send is the "sent" amount.
    expect(built.changeAmount).toBe(0);
    expect(built.inputs).toHaveLength(12);
    // Outputs are the power-of-ten decomposition of the self-send amount → <= 8.
    expect(built.outputs.length).toBeGreaterThan(0);
    expect(built.outputs.length).toBeLessThanOrEqual(MAX_FUSION_OUTPUTS);
    const outTotal = built.outputs.reduce((s, o) => s + o.amount, 0);
    expect(outTotal).toBe(built.sentAmount);
  });

  it("produces a broadcast-ready serialized blob + tx hash (reuses buildTransaction)", () => {
    const built = buildFusionTransaction(fixture(FUSION_TX_MIN_INPUT_COUNT));
    expect(built.serialized).toMatch(/^[0-9a-f]+$/);
    expect(built.serialized.length % 2).toBe(0);
    expect(built.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(built.prefixHash).toMatch(/^[0-9a-f]{64}$/);
    expect(ccxCrypto.ge_scalarmult_base(built.txSecretKey)).toBe(built.txPublicKey);
  });

  it("honors an explicit fee/mixin override", () => {
    const built = buildFusionTransaction({ ...fixture(12), fee: 2000, mixin: 5 });
    expect(built.fee).toBe(2000);
    expect(built.sentAmount).toBe(12 * 5_000_000 - 2000);
  });

  it("stays within the fusion size bound (single output bucket, 12 inputs)", () => {
    const built = buildFusionTransaction(fixture(12));
    const size = getApproximateTransactionSize(
      built.inputs.length,
      built.outputs.length,
      DEFAULT_MIXIN,
    );
    expect(size).toBeLessThanOrEqual(FUSION_TX_MAX_SIZE);
  });

  it("throws 'Nothing to optimize' when fewer than 12 inputs are supplied", () => {
    expect(() => buildFusionTransaction(fixture(11))).toThrow(/Nothing to optimize/);
  });

  it("throws 'Threshold is too low' when the inputs do not exceed the fee", () => {
    // 12 dust-sized inputs whose sum (12) is below the default fee (1000).
    const sender2 = account("f9");
    const inputs = Array.from({ length: 12 }, (_, i) => {
      const raw = craftReceiveTx(
        sender2,
        txKeypair((i % 256).toString(16).padStart(2, "0")),
        1,
        0,
        200 + i,
      );
      const [s] = scanTransactionOutputs(raw, keysOf(sender2));
      if (!s) throw new Error("setup");
      return {
        amount: s.amount,
        globalIndex: s.globalIndex,
        outputIndex: s.outputIndex,
        txPublicKey: s.txPublicKey,
        publicKey: s.publicKey,
        keyImage: s.keyImage,
      } satisfies SpendableOutput;
    });
    expect(() =>
      buildFusionTransaction({
        keys: keysOf(sender2),
        selfKeys: { spendPublicKey: sender2.spend.pub, viewPublicKey: sender2.view.pub },
        fusionInputs: inputs,
        decoys: [{ amount: 1, outs: [] }],
      }),
    ).toThrow(/Threshold is too low/);
  });
});

// --- PRETTY_AMOUNTS port ----------------------------------------------------

describe("PRETTY_AMOUNTS port", () => {
  it("has 9 entries per decade and the membership test matches the legacy", () => {
    // First three decades, byte-for-byte.
    expect(PRETTY_AMOUNTS.slice(0, 9)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(PRETTY_AMOUNTS.slice(9, 18)).toEqual([10, 20, 30, 40, 50, 60, 70, 80, 90]);
    expect(PRETTY_AMOUNTS.slice(18, 27)).toEqual([100, 200, 300, 400, 500, 600, 700, 800, 900]);
    // Legacy membership: findIndex(a => a >= amount) lands exactly on the value.
    const idx = PRETTY_AMOUNTS.findIndex((a) => a >= 5_000_000);
    expect(PRETTY_AMOUNTS[idx]).toBe(5_000_000);
    expect(Math.floor(idx / 9)).toBe(6);
  });
});
