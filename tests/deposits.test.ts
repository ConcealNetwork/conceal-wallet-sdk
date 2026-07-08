import { crypto as ccxCrypto, transactions as ccxTransactions } from "conceal-lib-js";
import { describe, expect, it } from "vitest";
import { createAccount } from "../src/account";
import {
  DEPOSIT_MIN_TERM_BLOCK,
  DEPOSIT_SMALL_WITHDRAW_FEE,
  DEPOSIT_TX_FEE,
  DEPOSIT_TX_VERSION,
} from "../src/constants";
import {
  calculateDepositInterest,
  depRef,
  findWithdrawnDepositIndexes,
  findWithdrawnDepRefs,
  isWithdrawShape,
  type OwnedDeposit,
} from "../src/deposits";
import {
  buildDepositTransaction,
  buildWithdrawTransaction,
  type RawTransaction,
  type SpendableOutput,
  scanTransactionOutputsAndDeposits,
} from "../src/transactions";
import {
  applyScannedDeposits,
  createWalletState,
  deserializeWalletState,
  getBalance,
  getLockedDeposits,
  getUnlockedDeposits,
  serializeWalletState,
} from "../src/wallet";

// --- helpers --------------------------------------------------------------

type Created = ReturnType<typeof ccxCrypto.create_address>;

function keysOf(c: Created) {
  return { spend: c.spend, view: c.view };
}

function ownKeysOf(c: Created) {
  return { spendPublicKey: c.spend.pub, viewPublicKey: c.view.pub };
}

/** A spendable type-02 output genuinely owned by `wallet`, derivable from a real tx key. */
function spendableOutput(
  wallet: Created,
  amount: number,
  globalIndex: number,
  seedByte: string,
): SpendableOutput {
  const tx = ccxCrypto.generate_keys(ccxCrypto.sc_reduce32(seedByte.repeat(32)));
  const derivation = ccxCrypto.generate_key_derivation(wallet.view.pub, tx.sec);
  const publicKey = ccxCrypto.derive_public_key(derivation, 0, wallet.spend.pub);
  const ephemeralSecret = ccxCrypto.derive_secret_key(derivation, 0, wallet.spend.sec);
  const keyImage = ccxCrypto.generate_key_image(publicKey, ephemeralSecret);
  return { amount, globalIndex, outputIndex: 0, txPublicKey: tx.pub, publicKey, keyImage };
}

/** Minimal hex-reader for asserting wire-format tags/values (mirrors lib-js test). */
function makeHexReader(hex: string) {
  let pos = 0;
  function readByte(): number {
    const b = Number.parseInt(hex.slice(pos, pos + 2), 16);
    pos += 2;
    return b;
  }
  return {
    readVarint(): number {
      let result = 0;
      let shift = 0;
      let b: number;
      do {
        b = readByte();
        result += (b & 0x7f) * 2 ** shift;
        shift += 7;
      } while (b >= 0x80);
      return result;
    },
    readHex(byteLen: number): string {
      const out = hex.slice(pos, pos + byteLen * 2);
      pos += byteLen * 2;
      return out;
    },
  };
}

// ===========================================================================
// 1. INTEREST — verbatim port; reference values must match EXACTLY
// ===========================================================================

describe("calculateDepositInterest — V3 reference values", () => {
  it("V3 1-month 10000 CCX → 32_500_000 atomic (32.5 CCX)", () => {
    const interest = calculateDepositInterest({
      amount: 1e10, // 10000 CCX atomic
      term: 21900, // 1 month
      lockHeight: 413401, // > depositHeightV3 (413400)
    });
    expect(interest).toBe(32_500_000);
  });

  it("V3 12-month 5000 CCX → 200_000_000 atomic (200 CCX)", () => {
    const interest = calculateDepositInterest({
      amount: 5e9, // 5000 CCX atomic
      term: 262800, // 12 months
      lockHeight: 500000,
    });
    expect(interest).toBe(200_000_000);
  });

  it("V3 tier-2 (>=20000 CCX) uses 0.049 base", () => {
    // 25000 CCX, 1 month: base 0.049, eir = 0.049/12, floor(2.5e10 * 0.049/12)
    const expected = Math.floor(2.5e10 * (0.049 / 12));
    expect(calculateDepositInterest({ amount: 2.5e10, term: 21900, lockHeight: 500000 })).toBe(
      expected,
    );
    expect(expected).toBe(102_083_333);
  });

  it("V3 6-month tier-0 (<10000 CCX) matches the formula", () => {
    // 1000 CCX, 6 months: base 0.029, ear = 0.029 + 5*0.001 = 0.034, eir = (0.034/12)*6
    const expected = Math.floor(1e9 * ((0.029 + 5 * 0.001) / 12) * 6);
    expect(calculateDepositInterest({ amount: 1e9, term: 21900 * 6, lockHeight: 500000 })).toBe(
      expected,
    );
    expect(expected).toBe(17_000_000);
  });

  it("V3 caps months at 12 (term beyond a year clamps the bonus)", () => {
    const twelve = calculateDepositInterest({ amount: 1e9, term: 262800, lockHeight: 500000 });
    const beyond = calculateDepositInterest({
      amount: 1e9,
      term: 262800 + 21900,
      lockHeight: 500000,
    });
    expect(beyond).toBe(twelve);
  });
});

describe("calculateDepositInterest — dispatch + V2/V1", () => {
  it("BLOCK_WITH_MISSING_INTEREST (425799) shifts lockHeight by term", () => {
    // At lockHeight 425799 the calc uses lockHeight+term; term=21900 → 447699 > V3 height → V3.
    const shifted = calculateDepositInterest({ amount: 1e10, term: 21900, lockHeight: 425799 });
    expect(shifted).toBe(32_500_000);
  });

  it("V2 weekly (term % 5040 === 0, not a V3 monthly multiple)", () => {
    // 5040 blocks = 1 week. base 0.0696 + 1*0.0002 = 0.0698; interest = amount*(1*0.0698/100)
    const term = 5040;
    const amount = 1e9;
    const expected = Math.floor(amount * ((1 * (0.0696 + 1 * 0.0002)) / 100));
    expect(calculateDepositInterest({ amount, term, lockHeight: 500000 })).toBe(expected);
  });

  it("V2 quarterly investment (term % 64800 === 0)", () => {
    const term = 64800; // 1 quarter
    const amount = 1e9;
    const mq = 1.4473;
    const termQuarters = 1;
    const m8 = 100.0 * (1.0 + mq / 100.0) ** termQuarters - 100.0;
    const m5 = termQuarters * 0.5;
    const m7 = m8 * (1 + m5 / 100);
    const rate = m7 * 1; // qTier = 1 for <110000 CCX
    const expected = Math.floor(amount * (rate / 100));
    expect(calculateDepositInterest({ amount, term, lockHeight: 500000 })).toBe(expected);
  });

  it("V1 fallback uses the BigInt truncating divide (term not a 5040/21900/64800 multiple)", () => {
    // term=300: 300%5040!=0, 300%21900!=0, 300%64800!=0 → V1.
    const amount = 1e9;
    const term = 300;
    const a = term * 4 - 0;
    const product = BigInt(Math.trunc(amount)) * BigInt(a);
    const base = Number(product / BigInt(100 * 262800));
    expect(calculateDepositInterest({ amount, term, lockHeight: 20000 })).toBe(base);
    // lockHeight <= 12750 applies the 100× early-deposit multiplier.
    expect(calculateDepositInterest({ amount, term, lockHeight: 10000 })).toBe(base * 100);
  });
});

// ===========================================================================
// 2. buildDepositTransaction
// ===========================================================================

describe("buildDepositTransaction", () => {
  const wallet = createAccount();
  // createAccount().keys is `{ spend, view }` — the same shape `spendableOutput` reads.
  const created = { spend: wallet.keys.spend, view: wallet.keys.view } as Created;

  function makeInputs(amount: number): SpendableOutput[] {
    return [spendableOutput(created, amount, 100, "ab")];
  }

  const depositAmount = 1e10; // 10000 CCX
  const term = 21900; // 1 month

  it("emits version 2, a single txout_to_deposit_key vout[0] with the term + one key", () => {
    const built = buildDepositTransaction({
      keys: wallet.keys,
      amount: depositAmount,
      termBlocks: term,
      ownKeys: { spendPublicKey: wallet.keys.spend.pub, viewPublicKey: wallet.keys.view.pub },
      unspentOutputs: makeInputs(depositAmount + DEPOSIT_TX_FEE + 5000),
      decoys: [],
      fee: DEPOSIT_TX_FEE,
      mixin: 0,
    });

    // Walk the serialized prefix and assert the wire format.
    const r = makeHexReader(built.serialized);
    expect(r.readVarint()).toBe(DEPOSIT_TX_VERSION); // version = 2
    expect(r.readVarint()).toBe(0); // unlock_time = 0
    const vinCount = r.readVarint();
    expect(vinCount).toBe(1);
    expect(r.readHex(1)).toBe("02"); // ring input tag
    r.readVarint(); // amount
    const offsetCount = r.readVarint();
    for (let i = 0; i < offsetCount; i++) r.readVarint();
    r.readHex(32); // k_image
    const voutCount = r.readVarint();
    expect(voutCount).toBe(2); // deposit + change
    // vout[0]: deposit output
    expect(r.readVarint()).toBe(depositAmount);
    expect(r.readHex(1)).toBe("03"); // txout_to_deposit_key tag
    expect(r.readVarint()).toBe(1); // keys length
    const depKey = r.readHex(32);
    expect(depKey).toBe(built.outputs[0]?.publicKey);
    expect(r.readVarint()).toBe(1); // required signatures
    expect(r.readVarint()).toBe(term); // term
    // vout[1]: type-02 change
    r.readVarint(); // change amount
    expect(r.readHex(1)).toBe("02");
  });

  it("change = inputs − amount − fee; deposit output is NOT decomposed (single vout[0])", () => {
    const extra = 7777;
    const built = buildDepositTransaction({
      keys: wallet.keys,
      amount: depositAmount,
      termBlocks: term,
      ownKeys: ownKeysOf(created),
      unspentOutputs: makeInputs(depositAmount + DEPOSIT_TX_FEE + extra),
      decoys: [],
      fee: DEPOSIT_TX_FEE,
      mixin: 0,
    });
    expect(built.changeAmount).toBe(extra);
    expect(built.outputs[0]?.amount).toBe(depositAmount);
  });

  it("deposit output is owned-scannable back to an OwnedDeposit with the right term/interest", () => {
    const lockHeight = 500000;
    const built = buildDepositTransaction({
      keys: wallet.keys,
      amount: depositAmount,
      termBlocks: term,
      ownKeys: ownKeysOf(created),
      unspentOutputs: makeInputs(depositAmount + DEPOSIT_TX_FEE),
      decoys: [],
      fee: DEPOSIT_TX_FEE,
      mixin: 0,
    });

    // The deposit output is vout[0]; reconstruct a RawTransaction and scan it back.
    const rawTx: RawTransaction = {
      extra: built.extra,
      vout: [
        {
          amount: depositAmount,
          target: {
            type: "03",
            data: { keys: [built.outputs[0]?.publicKey as string], required_signatures: 1, term },
          },
        },
      ],
      outputIndexes: [424242],
      hash: "cd".repeat(32),
      height: lockHeight,
    };
    const { deposits } = scanTransactionOutputsAndDeposits(rawTx, keysOf(created));
    expect(deposits).toHaveLength(1);
    const d = deposits[0] as OwnedDeposit;
    expect(d.amount).toBe(depositAmount);
    expect(d.term).toBe(term);
    expect(d.globalIndex).toBe(424242);
    expect(d.outputIndex).toBe(0);
    expect(d.blockHeight).toBe(lockHeight);
    expect(d.unlockHeight).toBe(lockHeight + term);
    expect(d.interest).toBe(32_500_000);
    expect(d.publicKey).toBe(built.outputs[0]?.publicKey);
  });
});

// ===========================================================================
// 3. buildWithdrawTransaction
// ===========================================================================

describe("buildWithdrawTransaction", () => {
  const wallet = createAccount();

  /** Construct a real OwnedDeposit by deriving a deposit one-time key from a tx key. */
  function makeOwnedDeposit(amount: number, term: number, blockHeight: number): OwnedDeposit {
    const tx = ccxCrypto.generate_keys(ccxCrypto.sc_reduce32("77".repeat(32)));
    const derivation = ccxCrypto.generate_key_derivation(wallet.keys.view.pub, tx.sec);
    const outputIndex = 0;
    const depositKey = ccxCrypto.derive_public_key(derivation, outputIndex, wallet.keys.spend.pub);
    return {
      amount,
      globalIndex: 9001,
      outputIndex,
      txPublicKey: tx.pub,
      publicKey: depositKey,
      keys: [depositKey],
      term,
      blockHeight,
      txHash: "ef".repeat(32),
      interest: calculateDepositInterest({ amount, term, lockHeight: blockHeight }),
      unlockHeight: blockHeight + term,
    };
  }

  it("emits version 2, one input_to_deposit_key vin, one type-02 vout = principal+interest−fee", () => {
    const deposit = makeOwnedDeposit(1e10, 21900, 413401);
    const built = buildWithdrawTransaction({
      keys: wallet.keys,
      deposit,
      ownKeys: { spendPublicKey: wallet.keys.spend.pub, viewPublicKey: wallet.keys.view.pub },
      withdrawFee: DEPOSIT_SMALL_WITHDRAW_FEE,
    });

    const expectedOut = deposit.amount + deposit.interest - DEPOSIT_SMALL_WITHDRAW_FEE;
    expect(built.sentAmount).toBe(expectedOut);
    expect(built.outputs).toHaveLength(1);
    expect(built.outputs[0]?.amount).toBe(expectedOut);
    expect(built.inputs).toHaveLength(1);
    expect(built.inputs[0]?.signatures).toHaveLength(1); // exactly one signature

    // Wire-format walk.
    const r = makeHexReader(built.serialized);
    expect(r.readVarint()).toBe(DEPOSIT_TX_VERSION); // version 2
    expect(r.readVarint()).toBe(0); // unlock_time
    expect(r.readVarint()).toBe(1); // vin count
    expect(r.readHex(1)).toBe("03"); // input_to_deposit_key tag
    expect(r.readVarint()).toBe(deposit.amount); // PRINCIPAL
    expect(r.readVarint()).toBe(1); // required signatures
    expect(r.readVarint()).toBe(deposit.globalIndex); // outputIndex = global index
    expect(r.readVarint()).toBe(deposit.term); // term
    expect(r.readVarint()).toBe(1); // vout count
    expect(r.readVarint()).toBe(expectedOut);
    expect(r.readHex(1)).toBe("02"); // txout_to_key
  });

  it("the single signature verifies against the prefix hash + ephemeral pub", () => {
    const deposit = makeOwnedDeposit(5e9, 262800, 500000);
    const built = buildWithdrawTransaction({
      keys: wallet.keys,
      deposit,
      ownKeys: { spendPublicKey: wallet.keys.spend.pub, viewPublicKey: wallet.keys.view.pub },
      withdrawFee: DEPOSIT_SMALL_WITHDRAW_FEE,
    });

    // Re-derive the ephemeral pub the same way the builder does and verify the sig.
    const derivation = ccxCrypto.generate_key_derivation(deposit.txPublicKey, wallet.keys.view.sec);
    const ephPub = ccxCrypto.derive_public_key(
      derivation,
      deposit.outputIndex,
      wallet.keys.spend.pub,
    );
    const sig = built.inputs[0]?.signatures[0] as string;
    expect(ccxCrypto.check_signature(built.prefixHash, ephPub, sig)).toBe(true);
    const out = built.outputs[0] as { amount: number; publicKey: string };
    // The serializer accepts exactly one signature for the type-03 input.
    const { raw } = ccxTransactions.serializeTransactionWithHash({
      version: DEPOSIT_TX_VERSION,
      unlock_time: 0,
      vin: [
        {
          type: "input_to_deposit_key",
          amount: deposit.amount,
          term: deposit.term,
          outputIndex: deposit.globalIndex,
          signatures: 1,
        },
      ],
      vout: [
        { amount: out.amount, target: { type: "txout_to_key", data: { key: out.publicKey } } },
      ],
      extra: built.extra,
      signatures: [[sig]],
    });
    expect(raw).toBe(built.serialized);
  });

  it("rejects a tampered interest (real-money guard)", () => {
    const deposit = makeOwnedDeposit(1e10, 21900, 413401);
    const tampered: OwnedDeposit = { ...deposit, interest: deposit.interest + 1 };
    expect(() =>
      buildWithdrawTransaction({
        keys: wallet.keys,
        deposit: tampered,
        ownKeys: { spendPublicKey: wallet.keys.spend.pub, viewPublicKey: wallet.keys.view.pub },
        withdrawFee: DEPOSIT_SMALL_WITHDRAW_FEE,
      }),
    ).toThrow(/interest mismatch/i);
  });

  it("defaults withdrawFee to DEPOSIT_SMALL_WITHDRAW_FEE (10) when omitted", () => {
    const deposit = makeOwnedDeposit(1e10, 21900, 413401);
    const withDefault = buildWithdrawTransaction({
      keys: wallet.keys,
      deposit,
      ownKeys: { spendPublicKey: wallet.keys.spend.pub, viewPublicKey: wallet.keys.view.pub },
    });
    expect(DEPOSIT_SMALL_WITHDRAW_FEE).toBe(10);
    expect(withDefault.fee).toBe(10);
    // Output = principal + interest − 10, identical to passing 10 explicitly.
    expect(withDefault.sentAmount).toBe(deposit.amount + deposit.interest - 10);
    const withExplicit = buildWithdrawTransaction({
      keys: wallet.keys,
      deposit,
      ownKeys: { spendPublicKey: wallet.keys.spend.pub, viewPublicKey: wallet.keys.view.pub },
      withdrawFee: 10,
    });
    expect(withDefault.sentAmount).toBe(withExplicit.sentAmount);
  });
});

// ===========================================================================
// 3b. buildDepositTransaction — banking constraints
// ===========================================================================

describe("buildDepositTransaction — constraints", () => {
  const wallet = createAccount();
  const created = { spend: wallet.keys.spend, view: wallet.keys.view } as Created;
  const ownKeys = { spendPublicKey: wallet.keys.spend.pub, viewPublicKey: wallet.keys.view.pub };

  function inputs(amount: number): SpendableOutput[] {
    return [spendableOutput(created, amount, 200, "dd")];
  }

  it("rejects an amount below the 1 CCX (1e6 atomic) minimum", () => {
    expect(() =>
      buildDepositTransaction({
        keys: wallet.keys,
        amount: 1, // 1 atomic, far below 1e6
        termBlocks: 21900,
        ownKeys,
        unspentOutputs: inputs(1e10),
        decoys: [],
        fee: DEPOSIT_TX_FEE,
        mixin: 0,
      }),
    ).toThrow(/Deposit amount must be a safe integer/i);
  });

  it("accepts exactly the 1 CCX minimum", () => {
    expect(() =>
      buildDepositTransaction({
        keys: wallet.keys,
        amount: 1e6,
        termBlocks: 21900,
        ownKeys,
        unspentOutputs: inputs(1e10),
        decoys: [],
        fee: DEPOSIT_TX_FEE,
        mixin: 0,
      }),
    ).not.toThrow();
  });

  it("rejects a term that is not a whole-month multiple of 21900", () => {
    expect(() =>
      buildDepositTransaction({
        keys: wallet.keys,
        amount: 1e10,
        termBlocks: 5040, // a week, not a month-multiple
        ownKeys,
        unspentOutputs: inputs(1e10),
        decoys: [],
        fee: DEPOSIT_TX_FEE,
        mixin: 0,
      }),
    ).toThrow(/whole-month multiple/i);
  });

  it("rejects a term beyond 12 months (262800 blocks)", () => {
    expect(() =>
      buildDepositTransaction({
        keys: wallet.keys,
        amount: 1e10,
        termBlocks: 21900 * 13, // 13 months
        ownKeys,
        unspentOutputs: inputs(1e10),
        decoys: [],
        fee: DEPOSIT_TX_FEE,
        mixin: 0,
      }),
    ).toThrow(/whole-month multiple/i);
  });

  it("rejects a zero/negative term", () => {
    expect(() =>
      buildDepositTransaction({
        keys: wallet.keys,
        amount: 1e10,
        termBlocks: 0,
        ownKeys,
        unspentOutputs: inputs(1e10),
        decoys: [],
        fee: DEPOSIT_TX_FEE,
        mixin: 0,
      }),
    ).toThrow(/whole-month multiple/i);
  });

  it("accepts all 1..12 month terms", () => {
    for (let months = 1; months <= 12; months++) {
      expect(() =>
        buildDepositTransaction({
          keys: wallet.keys,
          amount: 1e10,
          termBlocks: 21900 * months,
          ownKeys,
          unspentOutputs: inputs(2e10),
          decoys: [],
          fee: DEPOSIT_TX_FEE,
          mixin: 0,
        }),
      ).not.toThrow();
    }
  });
});

// ===========================================================================
// 4. Deposit scan + wallet state
// ===========================================================================

describe("deposit scan + wallet state", () => {
  const wallet = createAccount();

  function depositTx(
    amount: number,
    term: number,
    globalIndex: number,
    height: number,
    hash = "11".repeat(32),
  ) {
    const tx = ccxCrypto.generate_keys(ccxCrypto.sc_reduce32("33".repeat(32)));
    const derivation = ccxCrypto.generate_key_derivation(wallet.keys.view.pub, tx.sec);
    const depositKey = ccxCrypto.derive_public_key(derivation, 0, wallet.keys.spend.pub);
    const rawTx: RawTransaction = {
      extra: `01${tx.pub}`,
      vout: [
        {
          amount,
          target: {
            type: "03",
            data: { keys: [depositKey], required_signatures: 1, term },
          },
        },
      ],
      outputIndexes: [globalIndex],
      hash,
      height,
    };
    return { rawTx, depositKey };
  }

  it("applying a deposit tx adds an OwnedDeposit; principal stays out of spendable balance", () => {
    const { rawTx } = depositTx(1e10, 21900, 555, 413401);
    const { deposits } = scanTransactionOutputsAndDeposits(rawTx, {
      spend: wallet.keys.spend,
      view: wallet.keys.view,
    });
    expect(deposits).toHaveLength(1);

    let state = createWalletState({ address: wallet.address, keys: wallet.keys });
    state = applyScannedDeposits(state, deposits);
    expect(state.deposits).toHaveLength(1);
    // Deposit principal is not a spendable OwnedOutput.
    expect(getBalance(state).spendable).toBe(0);
  });

  it("a matching type-03 vin marks the owned deposit spent", () => {
    const { rawTx } = depositTx(1e10, 21900, 777, 413401);
    const { deposits } = scanTransactionOutputsAndDeposits(rawTx, {
      spend: wallet.keys.spend,
      view: wallet.keys.view,
    });
    let state = createWalletState({ address: wallet.address, keys: wallet.keys });
    state = applyScannedDeposits(state, deposits);

    const withdrawInputs = [
      { type: "input_to_deposit_key", outputIndex: 777, term: 21900, amount: 1e10 },
    ];
    const deposit = state.deposits[0];
    expect(deposit).toBeDefined();
    if (deposit === undefined) return;
    const withdrawn = findWithdrawnDepRefs(withdrawInputs, state.deposits);
    expect(withdrawn).toEqual([depRef(deposit)]);

    state = applyScannedDeposits(state, [], withdrawn);
    expect(state.spentDepositRefs).toEqual([depRef(deposit)]);
  });

  it("another user's unlock (non-owned global index) does not mark our deposit spent", () => {
    const { rawTx } = depositTx(1e10, 21900, 888, 413401);
    const { deposits } = scanTransactionOutputsAndDeposits(rawTx, {
      spend: wallet.keys.spend,
      view: wallet.keys.view,
    });
    const withdrawn = findWithdrawnDepositIndexes(
      [{ type: "input_to_deposit_key", outputIndex: 999999, term: 21900, amount: 1e10 }],
      deposits,
    );
    expect(withdrawn).toEqual([]);
  });

  it("index match without principal amount does not mark spent", () => {
    const { rawTx } = depositTx(1e10, 21900, 777, 413401);
    const { deposits } = scanTransactionOutputsAndDeposits(rawTx, {
      spend: wallet.keys.spend,
      view: wallet.keys.view,
    });
    const withdrawn = findWithdrawnDepositIndexes(
      [{ type: "input_to_deposit_key", outputIndex: 777, term: 21900 }],
      deposits,
    );
    expect(withdrawn).toEqual([]);
  });

  it("wrong principal amount does not mark spent even when index matches", () => {
    const { rawTx } = depositTx(1e10, 21900, 777, 413401);
    const { deposits } = scanTransactionOutputsAndDeposits(rawTx, {
      spend: wallet.keys.spend,
      view: wallet.keys.view,
    });
    const withdrawn = findWithdrawnDepositIndexes(
      [{ type: "input_to_deposit_key", outputIndex: 777, term: 21900, amount: 1e10 - 1 }],
      deposits,
    );
    expect(withdrawn).toEqual([]);
  });

  it("globalIndex falls back to 0 when output_indexes missing (wallet-core)", () => {
    const tx = ccxCrypto.generate_keys(ccxCrypto.sc_reduce32("44".repeat(32)));
    const derivation = ccxCrypto.generate_key_derivation(wallet.keys.view.pub, tx.sec);
    const depositKey = ccxCrypto.derive_public_key(derivation, 0, wallet.keys.spend.pub);
    const rawTx: RawTransaction = {
      extra: `01${tx.pub}`,
      vout: [
        {
          amount: 1e10,
          target: {
            type: "03",
            data: { keys: [depositKey], required_signatures: 1, term: 21900 },
          },
        },
      ],
      hash: "22".repeat(32),
      height: 413401,
    };
    const { deposits } = scanTransactionOutputsAndDeposits(rawTx, {
      spend: wallet.keys.spend,
      view: wallet.keys.view,
    });
    expect(deposits[0]?.globalIndex).toBe(0);
  });

  it("isWithdrawShape requires vout total > vin principal", () => {
    const inputs = [{ type: "input_to_deposit_key", outputIndex: 1, term: 21900, amount: 100 }];
    expect(isWithdrawShape({ vout: [{ amount: 50 }] }, inputs)).toBe(false);
    expect(isWithdrawShape({ vout: [{ amount: 50 }, { amount: 100 }] }, inputs)).toBe(true);
  });

  it("locked/unlocked getters partition by height", () => {
    const { rawTx } = depositTx(1e10, 21900, 1234, 413401);
    const { deposits } = scanTransactionOutputsAndDeposits(rawTx, {
      spend: wallet.keys.spend,
      view: wallet.keys.view,
    });
    let state = createWalletState({ address: wallet.address, keys: wallet.keys });
    state = applyScannedDeposits(state, deposits);
    const unlockHeight = 413401 + 21900; // blockHeight + term

    // Strictly before unlockHeight → locked.
    expect(getLockedDeposits(state, unlockHeight - 1)).toHaveLength(1);
    expect(getUnlockedDeposits(state, unlockHeight - 1)).toHaveLength(0);
    // At/after unlockHeight → unlocked.
    expect(getLockedDeposits(state, unlockHeight)).toHaveLength(0);
    expect(getUnlockedDeposits(state, unlockHeight)).toHaveLength(1);

    // Once withdrawn, a deposit is neither locked nor unlocked.
    const deposit = deposits[0];
    expect(deposit).toBeDefined();
    if (deposit === undefined) return;
    const ref = depRef(deposit);
    state = applyScannedDeposits(state, [], [ref]);
    expect(getUnlockedDeposits(state, unlockHeight)).toHaveLength(0);
    expect(getLockedDeposits(state, unlockHeight)).toHaveLength(0);
  });

  it("keeps multiple deposits that share globalIndex 0 (wallet-core txHash identity)", () => {
    const { rawTx: rawA, depositKey: keyA } = depositTx(1e10, 21900, 0, 413401, "aa".repeat(32));
    const { rawTx: rawB, depositKey: keyB } = depositTx(2e10, 21900, 0, 414401, "bb".repeat(32));
    expect(keyA).toBeTruthy();
    expect(keyB).toBeTruthy();

    const scanA = scanTransactionOutputsAndDeposits(rawA, {
      spend: wallet.keys.spend,
      view: wallet.keys.view,
    });
    const scanB = scanTransactionOutputsAndDeposits(rawB, {
      spend: wallet.keys.spend,
      view: wallet.keys.view,
    });

    let state = createWalletState({ address: wallet.address, keys: wallet.keys });
    state = applyScannedDeposits(state, scanA.deposits);
    state = applyScannedDeposits(state, scanB.deposits);
    expect(state.deposits).toHaveLength(2);
    expect(state.deposits.map((d) => d.txHash).sort()).toEqual(
      ["aa".repeat(32), "bb".repeat(32)].sort(),
    );
  });
});

// ===========================================================================
// 5. v1 → v2 state migration
// ===========================================================================

describe("WalletState v1 → v2 deserialize", () => {
  it("a v1 blob (no deposit fields) deserializes with deposits defaulted to []", () => {
    const v1Blob = JSON.stringify({
      version: 1,
      state: {
        address: "ccx7test",
        scannedHeight: 100,
        outputs: [],
        spentKeyImages: [],
        transactions: [],
      },
    });
    const state = deserializeWalletState(v1Blob);
    expect(state.deposits).toEqual([]);
    expect(state.spentDepositRefs).toEqual([]);
  });

  it("v2 blob with spentDepositIndexes upgrades to spentDepositRefs on read", () => {
    const deposit: OwnedDeposit = {
      amount: 1e10,
      globalIndex: 777,
      outputIndex: 0,
      txPublicKey: "ab".repeat(32),
      publicKey: "cd".repeat(32),
      keys: ["cd".repeat(32)],
      term: 21900,
      blockHeight: 413401,
      txHash: "ef".repeat(32),
      interest: 32_500_000,
      unlockHeight: 413401 + 21900,
    };
    const v2Blob = JSON.stringify({
      version: 2,
      state: {
        address: "ccx7test",
        scannedHeight: 100,
        outputs: [],
        spentKeyImages: [],
        transactions: [],
        deposits: [deposit],
        spentDepositIndexes: [777],
      },
    });
    const state = deserializeWalletState(v2Blob);
    expect(state.spentDepositRefs).toEqual([depRef(deposit)]);
  });

  it("round-trips a v2 state with deposits", () => {
    const deposit: OwnedDeposit = {
      amount: 1e10,
      globalIndex: 42,
      outputIndex: 0,
      txPublicKey: "ab".repeat(32),
      publicKey: "cd".repeat(32),
      keys: ["cd".repeat(32)],
      term: 21900,
      blockHeight: 413401,
      txHash: "ef".repeat(32),
      interest: 32_500_000,
      unlockHeight: 413401 + 21900,
    };
    const state = createWalletState({ address: "ccx7test", keys: undefined as never });
    const withDeposit = applyScannedDeposits(state, [deposit]);
    const round = deserializeWalletState(serializeWalletState(withDeposit));
    expect(round.deposits).toHaveLength(1);
    expect(round.deposits[0]).toEqual(deposit);
  });

  it("rejects a version newer than the SDK understands", () => {
    const future = JSON.stringify({ version: 99, state: {} });
    expect(() => deserializeWalletState(future)).toThrow(/Unsupported wallet state version/);
  });

  it("DEPOSIT_MIN_TERM_BLOCK is one month (21900 blocks)", () => {
    expect(DEPOSIT_MIN_TERM_BLOCK).toBe(21900);
  });
});
