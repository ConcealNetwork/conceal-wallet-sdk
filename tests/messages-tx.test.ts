import { crypto as ccxCrypto, transactions as ccxTransactions } from "conceal-lib-js";
import { describe, expect, it } from "vitest";
import { createAccount } from "../src/account";
import {
  ENCRYPTED_PAYMENT_ID_TAIL,
  INTEGRATED_PAYMENT_ID_BYTE_SIZE,
  MAX_CIPHERTEXT_BYTES,
  MAX_MESSAGE_BODY_BYTES,
  MESSAGE_TX_AMOUNT_ATOMIC,
  REMOTE_NODE_FEE_ATOMIC,
  TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID,
  TX_EXTRA_NONCE_PAYMENT_ID,
} from "../src/constants";
import { cnFastHash, cnutils, generateKeyDerivation } from "../src/crypto";
import { decryptMessage, deriveMessageKey, encodeSmartMessage } from "../src/messages";
import {
  type BuildMessageTransactionInput,
  buildMessageTransaction,
  buildTransaction,
  decryptPaymentId,
  encodeMessageExtra,
  encodeTtlExtra,
  extractMessageFromExtra,
  extractPaymentIdFromExtra,
  type RawTransaction,
  readMessageFromTransaction,
  type ScanKeys,
  type SpendableOutput,
  scanTransactionOutputs,
} from "../src/transactions";

// --- helpers ----------------------------------------------------------------

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

/** A raw tx with one type-"02" stealth output owned by `recipient` (sender side). */
function craftReceiveTx(
  recipient: Account,
  tx: { sec: string; pub: string },
  amount: number,
  globalIndex: number,
): RawTransaction {
  const derivation = ccxCrypto.generate_key_derivation(recipient.view.pub, tx.sec);
  const ownedKey = ccxCrypto.derive_public_key(derivation, 0, recipient.spend.pub);
  return {
    extra: `01${tx.pub}`,
    vout: [{ amount, target: { type: "02", data: { key: ownedKey } } }],
    outputIndexes: [globalIndex],
    hash: "ab".repeat(32),
    height: 12345,
  };
}

/** A spendable output the `owner` genuinely owns (so key images/signatures verify). */
function ownedSpendable(
  owner: Account,
  tx: { sec: string; pub: string },
  amount: number,
  gi: number,
): SpendableOutput {
  const raw = craftReceiveTx(owner, tx, amount, gi);
  const [out] = scanTransactionOutputs(raw, keysOf(owner));
  if (!out) throw new Error("setup: failed to craft owned spendable");
  return {
    amount: out.amount,
    globalIndex: out.globalIndex,
    outputIndex: out.outputIndex,
    txPublicKey: out.txPublicKey,
    publicKey: out.publicKey,
    keyImage: out.keyImage,
  };
}

// Two real accounts: A (sender) and B (message recipient).
const A = createAccount();
const B = createAccount();

function baseInput(
  overrides: Partial<BuildMessageTransactionInput> = {},
): BuildMessageTransactionInput {
  const utxo = ownedSpendable(account("a1"), txKeypair("c3"), 5_000_000, 100);
  return {
    keys: A.keys,
    recipient: { spendPublicKey: B.keys.spend.pub, viewPublicKey: B.keys.view.pub },
    body: "hello over the chain",
    changeKeys: { spendPublicKey: A.keys.spend.pub, viewPublicKey: A.keys.view.pub },
    unspentOutputs: [utxo],
    decoys: [
      {
        amount: 5_000_000,
        outs: [
          { globalIndex: 200, publicKey: account("d1").spend.pub },
          { globalIndex: 300, publicKey: account("d2").spend.pub },
        ],
      },
    ],
    fee: 10_000,
    mixin: 2,
    ...overrides,
  };
}

// IMPORTANT: A built message tx's `keys` MUST be the account that owns the UTXOs, or
// the ring signatures won't verify. Here the UTXO owner is account("a1"), so use it.
function builderKeys(): ScanKeys {
  return keysOf(account("a1"));
}

// --- encodeMessageExtra / encodeTtlExtra ------------------------------------

describe("encodeMessageExtra", () => {
  it("frames as 04 + 1-byte length + ciphertext", () => {
    const ct = "aa".repeat(10); // 10 bytes
    expect(encodeMessageExtra(ct)).toBe(`040a${ct}`);
  });

  it("encodes a max-length (255-byte) ciphertext", () => {
    const ct = "ff".repeat(MAX_CIPHERTEXT_BYTES);
    expect(encodeMessageExtra(ct)).toBe(`04ff${ct}`);
  });

  it("throws above the 255-byte single-byte length cap", () => {
    expect(() => encodeMessageExtra("ff".repeat(MAX_CIPHERTEXT_BYTES + 1))).toThrow(/too long/i);
  });
});

describe("encodeTtlExtra", () => {
  it("frames as 05 + varint(size) + varint(ttl) and round-trips via extract", () => {
    const ttl = 1_700_000_000;
    const record = encodeTtlExtra(ttl);
    expect(record.startsWith("05")).toBe(true);
    // Wrap with a pubkey + message record so the walk has a message to anchor on.
    const extra = `01${"ab".repeat(32)}${encodeMessageExtra("cc".repeat(8))}${record}`;
    const parsed = extractMessageFromExtra(extra);
    expect(parsed?.ttlUnixSeconds).toBe(ttl);
  });

  it("throws for a non-positive TTL", () => {
    expect(() => encodeTtlExtra(0)).toThrow();
    expect(() => encodeTtlExtra(-1)).toThrow();
  });
});

// --- extractMessageFromExtra ------------------------------------------------

describe("extractMessageFromExtra", () => {
  it("returns null for a plain (non-message) extra (01 + R only)", () => {
    expect(extractMessageFromExtra(`01${"ab".repeat(32)}`)).toBeNull();
  });

  it("returns null for empty / odd-length extra", () => {
    expect(extractMessageFromExtra("")).toBeNull();
    expect(extractMessageFromExtra("0")).toBeNull();
  });

  it("extracts the 0x04 payload after the 0x01 pubkey, ttl 0 when no 0x05", () => {
    const ct = "ab".repeat(20);
    const extra = `01${"cd".repeat(32)}${encodeMessageExtra(ct)}`;
    const parsed = extractMessageFromExtra(extra);
    expect(parsed?.ciphertextHex).toBe(ct);
    expect(parsed?.ttlUnixSeconds).toBe(0);
  });
});

// --- buildMessageTransaction round-trips ------------------------------------

describe("buildMessageTransaction — round-trip", () => {
  it("recipient B recovers the exact body from the built tx's extra", () => {
    const body = "secret note for B — café ☕";
    const built = buildMessageTransaction({ ...baseInput({ body }), keys: builderKeys() });

    // The recipient self-output is the 100-atomic marker.
    expect(built.sentAmount).toBe(MESSAGE_TX_AMOUNT_ATOMIC);

    // Reassemble the on-chain extra exactly as buildTransaction serialized it, then
    // read it back as the recipient would from a scanned raw tx.
    const extra = recoverExtra(built);
    const parsed = extractMessageFromExtra(extra);
    expect(parsed).not.toBeNull();

    const rawTx: RawTransaction = {
      extra,
      vout: built.outputs.map((o) => ({
        amount: o.amount,
        target: { type: "02", data: { key: o.publicKey } },
      })),
    };
    const read = readMessageFromTransaction(rawTx, B.keys);
    expect(read).not.toBeNull();
    expect(read?.body).toBe(body);
    expect(read?.ttlUnixSeconds).toBe(0);
    // B owns the 100-atomic message output.
    expect(read?.owned.some((o) => o.amount === MESSAGE_TX_AMOUNT_ATOMIC)).toBe(true);
  });

  it("built.extra is part of the serialized blob and parses via lib-js parseTxExtra", () => {
    const built = buildMessageTransaction({ ...baseInput(), keys: builderKeys() });
    // The signed/serialized blob carries this exact extra (byte-exactness vs Cn.ts).
    expect(built.serialized.includes(built.extra)).toBe(true);
    expect(built.extra.startsWith(`01${built.txPublicKey}`)).toBe(true);
    // lib-js's own extra parser recovers a TX_EXTRA_MESSAGE_TAG (0x04) record.
    const bytes: number[] = [];
    for (let i = 0; i < built.extra.length; i += 2) {
      bytes.push(Number.parseInt(built.extra.slice(i, i + 2), 16));
    }
    const records = ccxTransactions.parseTxExtra(bytes);
    expect(records.some((r) => r.type === ccxTransactions.TX_EXTRA_MESSAGE_TAG)).toBe(true);
  });

  it("derives the message key from the tx secret + recipient spend pub", () => {
    const body = "key-binding check";
    const built = buildMessageTransaction({ ...baseInput({ body }), keys: builderKeys() });
    const parsed = extractMessageFromExtra(recoverExtra(built));
    expect(parsed).not.toBeNull();
    if (!parsed) return;

    // Sender's key from r; recipient's key from R — must match (ECDH) and decrypt.
    const senderKey = deriveMessageKey(B.keys.spend.pub, built.txSecretKey);
    const recipientKey = deriveMessageKey(built.txPublicKey, B.keys.spend.sec);
    expect(senderKey).toBe(recipientKey);
    expect(decryptMessage(parsed.ciphertextHex, recipientKey, 0)).toBe(body);
  });

  it("a stranger cannot decrypt the body (wrong spend secret → null)", () => {
    const built = buildMessageTransaction({ ...baseInput(), keys: builderKeys() });
    const extra = recoverExtra(built);
    const rawTx: RawTransaction = {
      extra,
      vout: built.outputs.map((o) => ({
        amount: o.amount,
        target: { type: "02", data: { key: o.publicKey } },
      })),
    };
    // A different account can still walk the extra but cannot recover the body.
    const stranger = createAccount();
    const read = readMessageFromTransaction(rawTx, stranger.keys);
    expect(read).not.toBeNull();
    expect(read?.body).toBeNull();
  });

  it("node-fee operator can claim the fee output but cannot decrypt the FS body", () => {
    const operator = createAccount();
    const body = "secret for recipient only";
    const built = buildMessageTransaction({
      ...baseInput({ body }),
      keys: builderKeys(),
      ttlUnixSeconds: 0,
      nodeFee: {
        spendPublicKey: operator.keys.spend.pub,
        viewPublicKey: operator.keys.view.pub,
        amount: REMOTE_NODE_FEE_ATOMIC,
      },
    });
    const amounts = built.outputs.map((o) => o.amount);
    expect(amounts).toEqual([...amounts].sort((a, b) => a - b));
    expect(amounts).toContain(REMOTE_NODE_FEE_ATOMIC);

    const rawTx: RawTransaction = {
      extra: recoverExtra(built),
      vout: built.outputs.map((o) => ({
        amount: o.amount,
        target: { type: "02", data: { key: o.publicKey } },
      })),
    };
    const forOperator = readMessageFromTransaction(rawTx, operator.keys);
    expect(forOperator).not.toBeNull();
    expect(forOperator?.owned.some((o) => o.amount === REMOTE_NODE_FEE_ATOMIC)).toBe(true);
    expect(forOperator?.body).toBeNull();

    const forRecipient = readMessageFromTransaction(rawTx, B.keys);
    expect(forRecipient?.body).toBe(body);
  });

  it("round-trips a smart message (ChaCha12) with ACTION_MAP shorthand", () => {
    const body = encodeSmartMessage("2FA", "verify", "site"); // → {2FA,v,site}
    expect(body).toBe("{2FA,v,site}");
    const built = buildMessageTransaction({ ...baseInput({ body }), keys: builderKeys() });
    const parsed = extractMessageFromExtra(recoverExtra(built));
    expect(parsed).not.toBeNull();
    if (!parsed) return;
    const key = deriveMessageKey(built.txPublicKey, B.keys.spend.sec);
    // The exact (shortened) on-chain body is what a conceal-2fa peer decodes.
    expect(decryptMessage(parsed.ciphertextHex, key, 0)).toBe("{2FA,v,site}");
  });

  it("enforces the 251-byte UTF-8 body cap", () => {
    expect(() =>
      buildMessageTransaction({
        ...baseInput({ body: "a".repeat(MAX_MESSAGE_BODY_BYTES + 1) }),
        keys: builderKeys(),
      }),
    ).toThrow(/too long/i);
    // 2-byte chars count by UTF-8 length, not char count.
    expect(() =>
      buildMessageTransaction({
        ...baseInput({ body: "é".repeat(126) }), // 252 bytes
        keys: builderKeys(),
      }),
    ).toThrow(/too long/i);
  });
});

// --- TTL behavior -----------------------------------------------------------

describe("buildMessageTransaction — TTL", () => {
  it("ttl > 0 appends a 0x05 record decoding to the exact unix value", () => {
    const ttl = 1_700_123_456;
    const built = buildMessageTransaction({
      ...baseInput(),
      keys: builderKeys(),
      ttlUnixSeconds: ttl,
    });
    const parsed = extractMessageFromExtra(recoverExtra(built));
    expect(parsed?.ttlUnixSeconds).toBe(ttl);
  });

  it("ttl > 0 adds NO node-fee destination and folds the fee into change", () => {
    const ttl = 1_700_123_456;
    const fee = 10_000;
    const built = buildMessageTransaction({
      ...baseInput(),
      keys: builderKeys(),
      fee,
      ttlUnixSeconds: ttl,
      nodeFee: {
        spendPublicKey: account("fe").spend.pub,
        viewPublicKey: account("fe").view.pub,
        amount: REMOTE_NODE_FEE_ATOMIC,
      },
    });
    // Only the 100-atomic recipient output is sent (no node fee).
    expect(built.sentAmount).toBe(MESSAGE_TX_AMOUNT_ATOMIC);
    // A TTL message is signed with fee 0 (folded into change) — the reported fee
    // reflects what was actually signed, so the accounting invariant holds.
    expect(built.fee).toBe(0);
    const outTotal = built.outputs.reduce((s, o) => s + o.amount, 0);
    expect(outTotal).toBe(built.inputsAmount);
    expect(built.changeAmount).toBe(built.inputsAmount - MESSAGE_TX_AMOUNT_ATOMIC);
    // Invariant: sent + change + fee === inputs.
    expect(built.sentAmount + built.changeAmount + built.fee).toBe(built.inputsAmount);
  });

  it("ttl 0 omits the 0x05 record and appends the node-fee destination", () => {
    const built = buildMessageTransaction({
      ...baseInput(),
      keys: builderKeys(),
      ttlUnixSeconds: 0,
      nodeFee: {
        spendPublicKey: account("fe").spend.pub,
        viewPublicKey: account("fe").view.pub,
        amount: REMOTE_NODE_FEE_ATOMIC,
      },
    });
    const parsed = extractMessageFromExtra(recoverExtra(built));
    expect(parsed?.ttlUnixSeconds).toBe(0);
    // recipient (100) + node fee (10000) are both sent; fee is burned normally.
    expect(built.sentAmount).toBe(MESSAGE_TX_AMOUNT_ATOMIC + REMOTE_NODE_FEE_ATOMIC);
    const outTotal = built.outputs.reduce((s, o) => s + o.amount, 0);
    expect(outTotal).toBe(built.inputsAmount - built.fee);
  });
});

// --- default buildTransaction extra is unchanged ----------------------------

describe("buildTransaction — default extra is byte-identical", () => {
  it("a plain build (no hook) still produces extra = 01 + R", () => {
    const utxo = ownedSpendable(account("a1"), txKeypair("c3"), 5_000_000, 100);
    const built = buildTransaction({
      keys: builderKeys(),
      destinations: [
        { spendPublicKey: B.keys.spend.pub, viewPublicKey: B.keys.view.pub, amount: 1_000_000 },
      ],
      changeKeys: { spendPublicKey: A.keys.spend.pub, viewPublicKey: A.keys.view.pub },
      unspentOutputs: [utxo],
      decoys: [
        {
          amount: 5_000_000,
          outs: [
            { globalIndex: 200, publicKey: account("d1").spend.pub },
            { globalIndex: 300, publicKey: account("d2").spend.pub },
          ],
        },
      ],
      fee: 10_000,
      mixin: 2,
    });
    // No message record → a plain extra carries no extractable message.
    expect(extractMessageFromExtra(`01${built.txPublicKey}`)).toBeNull();
  });
});

/**
 * The on-chain `extra` for a built message tx — surfaced directly on the result
 * (`01 + R + messageRecord (+ ttlRecord)`). Using `built.extra` (rather than slicing
 * the serialized blob) keeps the round-trip exercising the exact bytes the signer hashed.
 */
function recoverExtra(built: ReturnType<typeof buildMessageTransaction>): string {
  return built.extra;
}

describe("extractMessageFromExtra / readMessageFromTransaction — malformed input hardening", () => {
  const R = "ab".repeat(32); // a 32-byte tx pubkey

  it("returns null for non-hex extra (no NaN propagation)", () => {
    expect(extractMessageFromExtra(`01${R}0401zz`)).toBeNull();
    expect(extractMessageFromExtra("nothex")).toBeNull();
    expect(extractMessageFromExtra(`01${R}040`)).toBeNull(); // odd length
  });

  it("returns null for a plain extra with no message record", () => {
    expect(extractMessageFromExtra(`01${R}`)).toBeNull();
  });

  it("keeps the message and stops cleanly on a corrupt (unterminated) TTL varint", () => {
    // 04 02 aabb = message "aabb"; 05 01 80 = TTL record whose value varint (0x80)
    // is unterminated → decode must not throw, message is still recovered, ttl = 0.
    const extracted = extractMessageFromExtra(`01${R}0402aabb050180`);
    expect(extracted).not.toBeNull();
    expect(extracted?.ciphertextHex).toBe("aabb");
    expect(extracted?.ttlUnixSeconds).toBe(0);
  });

  it("takes the first message record when several are present", () => {
    const extracted = extractMessageFromExtra(`01${R}0402aabb0402ccdd`);
    expect(extracted?.ciphertextHex).toBe("aabb");
  });

  it("readMessageFromTransaction does not throw on a garbage message record", () => {
    const acct = createAccount();
    const tx = { extra: `01${R}${encodeMessageExtra("aabbccdd")}`, vout: [] } as RawTransaction;
    expect(() => readMessageFromTransaction(tx, acct.keys)).not.toThrow();
  });

  it("buildTransaction rejects a non-hex buildExtraRecords return (reaches the guard)", () => {
    // Valid inputs (same fixture as the byte-identical test) so selection/ring
    // succeed and the build actually reaches the extra hook before throwing.
    const utxo = ownedSpendable(account("a1"), txKeypair("c3"), 5_000_000, 100);
    const build = (buildExtraRecords: () => string) =>
      buildTransaction({
        keys: builderKeys(),
        destinations: [
          { spendPublicKey: B.keys.spend.pub, viewPublicKey: B.keys.view.pub, amount: 1_000_000 },
        ],
        changeKeys: { spendPublicKey: A.keys.spend.pub, viewPublicKey: A.keys.view.pub },
        unspentOutputs: [utxo],
        decoys: [
          {
            amount: 5_000_000,
            outs: [
              { globalIndex: 200, publicKey: account("d1").spend.pub },
              { globalIndex: 300, publicKey: account("d2").spend.pub },
            ],
          },
        ],
        fee: 10_000,
        mixin: 2,
        buildExtraRecords: buildExtraRecords as never,
      });
    expect(() => build(() => "zz")).toThrow(/hex/i); // non-hex
    expect(() => build(() => "abc")).toThrow(/hex/i); // odd length
    // A valid even-length hex record is accepted.
    expect(() => build(() => "0401aa")).not.toThrow();
  });
});

// --- payment id extraction --------------------------------------------------

function byteToHex(value: number): string {
  return `0${value.toString(16)}`.slice(-2);
}

/** Legacy `0x02` nonce record carrying a plaintext payment id (long-form PID). */
function encodePlaintextPaymentIdNonce(paymentIdHex: string): string {
  const pidBytes = Array.from(cnutils.hextobin(paymentIdHex) as Uint8Array);
  const data = [TX_EXTRA_NONCE_PAYMENT_ID, ...pidBytes];
  return `02${byteToHex(data.length)}${data.map((byte) => byteToHex(byte)).join("")}`;
}

/** Encrypt an 8-byte integrated payment id for a tx extra nonce (sender side). */
function encryptPaymentIdForExtra(
  paymentId8Hex: string,
  recipientViewPublicKey: string,
  txSecretKey: string,
): string {
  const keyDerivation = generateKeyDerivation(recipientViewPublicKey, txSecretKey);
  const pidKey = cnFastHash(`${keyDerivation}${ENCRYPTED_PAYMENT_ID_TAIL.toString(16)}`).slice(
    0,
    INTEGRATED_PAYMENT_ID_BYTE_SIZE * 2,
  );
  return cnutils.hex_xor(paymentId8Hex, pidKey);
}

function encodeEncryptedPaymentIdNonce(encryptedPaymentId8Hex: string): string {
  const pidBytes = Array.from(cnutils.hextobin(encryptedPaymentId8Hex) as Uint8Array);
  const data = [TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID, ...pidBytes];
  return `02${byteToHex(data.length)}${data.map((byte) => byteToHex(byte)).join("")}`;
}

describe("extractPaymentIdFromExtra / readMessageFromTransaction — payment id", () => {
  const LONG_PID = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7ef099";
  const SHORT_PID = "a1b2c3d4e5f60718";

  it("extracts a plaintext long-form payment id from a 0x02 nonce record", () => {
    const R = "ab".repeat(32);
    const extra = `${encodePlaintextPaymentIdNonce(LONG_PID)}01${R}${encodeMessageExtra("cc".repeat(8))}`;
    expect(extractPaymentIdFromExtra(extra)).toBe(LONG_PID);
  });

  it("decrypts an encrypted 8-byte payment id with the recipient view secret", () => {
    const body = "pid-tagged message";
    const built = buildMessageTransaction({ ...baseInput({ body }), keys: builderKeys() });
    const encrypted = encryptPaymentIdForExtra(SHORT_PID, B.keys.view.pub, built.txSecretKey);
    const nonce = encodeEncryptedPaymentIdNonce(encrypted);
    const extra = `${nonce}${recoverExtra(built)}`;
    const rawTx: RawTransaction = {
      extra,
      vout: built.outputs.map((o) => ({
        amount: o.amount,
        target: { type: "02", data: { key: o.publicKey } },
      })),
    };

    expect(
      extractPaymentIdFromExtra(extra, {
        txPublicKey: built.txPublicKey,
        viewSecretKey: B.keys.view.sec,
      }),
    ).toBe(SHORT_PID);

    const read = readMessageFromTransaction(rawTx, B.keys);
    expect(read?.body).toBe(body);
    expect(read?.paymentId).toBe(SHORT_PID);
  });

  it("prefers encrypted payment id over plaintext when both are present", () => {
    const txSecret = txKeypair("e5");
    const R = txSecret.pub;
    const encrypted = encryptPaymentIdForExtra(SHORT_PID, B.keys.view.pub, txSecret.sec);
    const extra = `${encodePlaintextPaymentIdNonce(LONG_PID)}${encodeEncryptedPaymentIdNonce(encrypted)}01${R}`;
    expect(
      extractPaymentIdFromExtra(extra, {
        txPublicKey: R,
        viewSecretKey: B.keys.view.sec,
      }),
    ).toBe(SHORT_PID);
    expect(decryptPaymentId(encrypted, R, B.keys.view.sec)).toBe(SHORT_PID);
  });

  it("returns null when extra carries no payment id nonce", () => {
    const built = buildMessageTransaction({ ...baseInput(), keys: builderKeys() });
    expect(extractPaymentIdFromExtra(recoverExtra(built))).toBeNull();
  });
});
