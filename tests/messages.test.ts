import { crypto as ccxCrypto } from "conceal-lib-js";
import { describe, expect, it } from "vitest";
import {
  decryptMessage,
  deriveMessageKey,
  encodeSmartMessage,
  encryptMessage,
  isKnownSmartMessage,
  isSmartMessage,
  KNOWN_MODULES,
  parseSmartMessage,
} from "../src/messages";

// Two real CCX accounts. A stands in for the sender (tx ephemeral keypair),
// B for the recipient. The legacy protocol derives the shared key from the SPEND
// keys: sender uses (recipientSpendPub, senderSpendSec), recipient uses
// (senderSpendPub, recipientSpendSec) — ECDH-symmetric, so both sides agree.
const A = ccxCrypto.create_address(ccxCrypto.sc_reduce32("11".repeat(32)));
const B = ccxCrypto.create_address(ccxCrypto.sc_reduce32("22".repeat(32)));

// Key as derived by each party (must be identical).
const keyAtoB = deriveMessageKey(B.spend.pub, A.spend.sec); // sender's view
const keyBfromA = deriveMessageKey(A.spend.pub, B.spend.sec); // recipient's view

describe("deriveMessageKey", () => {
  it("is a 32-byte hex key", () => {
    expect(keyAtoB).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is ECDH-symmetric across the two parties (sender ↔ recipient agree)", () => {
    expect(keyAtoB).toBe(keyBfromA);
  });
});

describe("encrypt/decrypt round-trip", () => {
  it("round-trips a plain chat message (ChaCha8)", () => {
    const body = "hello from A to B 👋";
    const ct = encryptMessage(body, keyAtoB);
    expect(ct).toMatch(/^[0-9a-f]+$/);
    expect(decryptMessage(ct, keyBfromA)).toBe(body);
  });

  it("round-trips a known smart message (ChaCha12) and stays structural", () => {
    const body = encodeSmartMessage("vault", "update", "note-1");
    expect(body).toBe("{vault,update,note-1}");
    expect(isKnownSmartMessage(body)).toBe(true);

    const ct = encryptMessage(body, keyAtoB);
    const decrypted = decryptMessage(ct, keyBfromA);
    expect(decrypted).toBe(body);
    expect(isSmartMessage(decrypted)).toBe(true);
  });

  it("decrypts an unknown-but-structural smart message via the broadened gate", () => {
    // {xyz,a} is structurally a smart message but xyz is not a KNOWN_MODULE, so
    // encrypt uses ChaCha8 (not known). Decrypt's ChaCha12 path rejects it
    // (checksum fails under the wrong cipher) and the ChaCha8 fallback recovers it.
    const body = "{xyz,a}";
    expect(isSmartMessage(body)).toBe(true);
    expect(isKnownSmartMessage(body)).toBe(false);

    const ct = encryptMessage(body, keyAtoB);
    expect(decryptMessage(ct, keyBfromA)).toBe(body);
  });

  it("returns null for the wrong key (checksum fails)", () => {
    const ct = encryptMessage("secret", keyAtoB);
    const wrongKey = deriveMessageKey(A.spend.pub, A.spend.sec); // unrelated key
    expect(wrongKey).not.toBe(keyAtoB);
    expect(decryptMessage(ct, wrongKey)).toBeNull();
  });

  it("round-trips a non-default message index", () => {
    const body = "indexed message";
    const ct = encryptMessage(body, keyAtoB, 1);
    expect(decryptMessage(ct, keyBfromA, 1)).toBe(body);
    // wrong index → wrong nonce → checksum fails.
    expect(decryptMessage(ct, keyBfromA, 0)).toBeNull();
  });
});

describe("size guard (UTF-8 bytes, not chars)", () => {
  it("accepts a 251-byte body", () => {
    const body = "a".repeat(251);
    const ct = encryptMessage(body, keyAtoB);
    expect(decryptMessage(ct, keyBfromA)).toBe(body);
  });

  it("throws on a 252-byte body", () => {
    expect(() => encryptMessage("a".repeat(252), keyAtoB)).toThrow(/too long/i);
  });

  it("measures bytes, not chars (multi-byte char counts as its UTF-8 length)", () => {
    // "é" is 2 UTF-8 bytes → 126 of them = 252 bytes > 251, must throw even
    // though it's only 126 characters.
    expect(() => encryptMessage("é".repeat(126), keyAtoB)).toThrow(/too long/i);
  });
});

describe("smart-message encode/parse", () => {
  it("encodes module + action + data", () => {
    expect(encodeSmartMessage("status", "alive")).toBe("{status,alive}");
    expect(encodeSmartMessage("2FA", "create", "site", "token")).toBe("{2FA,create,site,token}");
  });

  it("parses into trimmed parts", () => {
    expect(parseSmartMessage("{ vault , update , x }")).toEqual(["vault", "update", "x"]);
    expect(parseSmartMessage("plain text")).toBeNull();
  });

  it("round-trips encode → parse", () => {
    const parts = parseSmartMessage(encodeSmartMessage("to-do", "complete", "item-7"));
    expect(parts).toEqual(["to-do", "complete", "item-7"]);
  });

  it("rejects parts containing structural delimiters", () => {
    expect(() => encodeSmartMessage("mod", "act", "a,b")).toThrow();
    expect(() => encodeSmartMessage("mod", "act", "{bad}")).toThrow();
  });

  it("isKnownSmartMessage only accepts KNOWN_MODULES first parts", () => {
    for (const mod of KNOWN_MODULES) {
      expect(isKnownSmartMessage(`{${mod},action}`)).toBe(true);
    }
    expect(isKnownSmartMessage("{unknown,action}")).toBe(false);
    expect(isKnownSmartMessage("not a smart message")).toBe(false);
  });
});
