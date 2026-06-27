import { describe, expect, it } from "vitest";
import {
  classifyTransactionKind,
  extractTxKindHints,
  isCoinbaseRawTransaction,
  isFusionShape,
  resolveWalletTransactionKind,
} from "../src/transaction-kind";
import type { WalletTransaction } from "../src/wallet";
import { createWalletState, getDustAmount, getUnspentOutputs } from "../src/wallet";

describe("transaction-kind", () => {
  it("detects coinbase vin shapes", () => {
    expect(isCoinbaseRawTransaction({ vin: [] })).toBe(true);
    expect(isCoinbaseRawTransaction({ vin: [{ gen: [0] }] })).toBe(true);
    expect(isCoinbaseRawTransaction({ vin: [{ type: "ff" }] })).toBe(true);
    expect(isCoinbaseRawTransaction({ vin: [{ k_image: "abc" }] })).toBe(false);
  });

  it("classifies deposit, withdrawal, fusion, and miner", () => {
    expect(
      classifyTransactionKind({
        direction: "out",
        ownedOutputs: [],
        ownedDeposits: [{} as never],
        receivedAmount: 0,
      }),
    ).toBe("deposit");

    expect(
      classifyTransactionKind({
        direction: "in",
        ownedOutputs: [],
        depositInputs: [{ type: "input_to_deposit_key", outputIndex: 1 }],
        receivedAmount: 1_000_000,
      }),
    ).toBe("withdrawal");

    expect(
      classifyTransactionKind({
        direction: "out",
        ownedOutputs: [{ amount: 100 } as never],
        rawTransaction: { vin: Array(20).fill({ type: "02" }), vout: [{}, {}] },
        fee: 1000,
        receivedAmount: 100,
      }),
    ).toBe("fusion");

    expect(
      classifyTransactionKind({
        direction: "in",
        ownedOutputs: [{ amount: 2_000_000 } as never],
        rawTransaction: { vin: [{ gen: [0] }] },
        receivedAmount: 2_000_000,
      }),
    ).toBe("miner");
  });

  it("does not classify message envelopes as miner", () => {
    expect(
      classifyTransactionKind({
        direction: "in",
        ownedOutputs: [{ amount: 100 } as never],
        rawTransaction: { vin: [] },
        receivedAmount: 100,
      }),
    ).toBe("receive");
  });

  it("resolveWalletTransactionKind falls back to direction", () => {
    const tx: WalletTransaction = {
      hash: "h",
      height: 1,
      amount: 100,
      direction: "in",
    };
    expect(resolveWalletTransactionKind(tx)).toBe("receive");
    expect(resolveWalletTransactionKind({ ...tx, kind: "miner" })).toBe("miner");
  });

  it("detects fusion shape like legacy TransactionsExplorer", () => {
    const hints = extractTxKindHints(
      { vin: Array(20).fill({ type: "02" }), vout: [{ target: { type: "02" } }, {}] },
      1000,
    );
    expect(isFusionShape(hints)).toBe(true);
    expect(isFusionShape({ ...hints, hasDepositVin: true })).toBe(false);
  });
});

describe("getDustAmount", () => {
  it("sums unspent outputs below DUST_THRESHOLD", () => {
    const state = {
      ...createWalletState({ address: "ccx7test", keys: {} as never }),
      outputs: [
        {
          amount: 5,
          globalIndex: 1,
          outputIndex: 0,
          txPublicKey: "t",
          publicKey: "p1",
          keyImage: "ki1",
        },
        {
          amount: 9,
          globalIndex: 2,
          outputIndex: 1,
          txPublicKey: "t",
          publicKey: "p2",
          keyImage: "ki2",
        },
        {
          amount: 1000,
          globalIndex: 3,
          outputIndex: 2,
          txPublicKey: "t",
          publicKey: "p3",
          keyImage: "ki3",
        },
      ],
    };
    expect(getDustAmount(state)).toBe(14);
    expect(getUnspentOutputs(state).reduce((s, o) => s + o.amount, 0)).toBe(1014);
  });
});
