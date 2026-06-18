import { crypto as ccxCrypto } from "conceal-lib-js";
import { describe, expect, it } from "vitest";
import {
  buildPaymentUri,
  decodeAddress,
  encodeAddress,
  encodeIntegratedAddress,
  isValidAddress,
  makeIntegratedAddress,
  parsePaymentUri,
} from "../src/address";

/** Real CCX keys + address generated via lib-js — never a hand-typed literal. */
function freshKeys() {
  const seed = ccxCrypto.sc_reduce32(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  );
  return ccxCrypto.create_address(seed) as {
    spend: { sec: string; pub: string };
    view: { sec: string; pub: string };
    public_addr: string;
  };
}

function freshAddress(): string {
  return freshKeys().public_addr;
}

const HEX64 = /^[0-9a-f]{64}$/;

describe("decodeAddress", () => {
  it("decodes a real address to 64-hex spend/view public keys", () => {
    const decoded = decodeAddress(freshAddress());
    expect(decoded.spendPublicKey).toMatch(HEX64);
    expect(decoded.viewPublicKey).toMatch(HEX64);
    // A plain (non-integrated) address carries no payment id.
    expect(decoded.paymentId).toBeUndefined();
  });

  it("throws a clear Error on invalid input (lib-js throws bare strings)", () => {
    expect(() => decodeAddress("ccx7bad")).toThrow(/invalid ccx address/i);
    expect(() => decodeAddress("")).toThrow(/invalid ccx address/i);
  });
});

describe("isValidAddress", () => {
  it("is true for a real address", () => {
    expect(isValidAddress(freshAddress())).toBe(true);
  });

  it("is false for malformed / empty input", () => {
    expect(isValidAddress("ccx7bad")).toBe(false);
    expect(isValidAddress("")).toBe(false);
  });
});

describe("buildPaymentUri / parsePaymentUri", () => {
  it("round-trips address + amount + paymentId + label", () => {
    const address = freshAddress();
    const req = {
      address,
      amount: 12.5,
      paymentId: "a".repeat(64),
      label: "Alice's Shop",
    };

    const uri = buildPaymentUri(req);
    expect(uri.startsWith(address)).toBe(true);
    expect(uri.startsWith("conceal")).toBe(false); // bare address, no scheme prefix

    const parsed = parsePaymentUri(uri);
    expect(parsed).toEqual(req);
  });

  it("emits a bare address (no params) when only the address is given", () => {
    const address = freshAddress();
    expect(buildPaymentUri({ address })).toBe(address);
  });

  it("tolerates a `conceal:`-prefixed form on parse", () => {
    const address = freshAddress();
    const uri = buildPaymentUri({ address, amount: 3 });
    const parsed = parsePaymentUri(`conceal:${uri}`);
    expect(parsed).toEqual({ address, amount: 3 });
  });

  it("rejects a comma-decimal amount (returns null, never throws)", () => {
    const address = freshAddress();
    expect(parsePaymentUri(`${address}?amount=1,5`)).toBeNull();
  });

  it("returns null for malformed input without throwing", () => {
    expect(parsePaymentUri("ccx7bad?amount=1")).toBeNull();
    expect(parsePaymentUri("")).toBeNull();
    expect(parsePaymentUri("not-a-uri")).toBeNull();
    expect(parsePaymentUri(`${freshAddress()}?amount=%`)).toBeNull();
  });

  it("throws when building from an invalid address", () => {
    expect(() => buildPaymentUri({ address: "ccx7bad" })).toThrow(/invalid ccx address/i);
  });
});

describe("encodeAddress", () => {
  it("reproduces the canonical address from spend/view public keys (parity)", () => {
    const keys = freshKeys();
    expect(encodeAddress(keys.spend.pub, keys.view.pub)).toBe(keys.public_addr);
  });

  it("round-trips through decodeAddress", () => {
    const keys = freshKeys();
    const encoded = encodeAddress(keys.spend.pub, keys.view.pub);
    const decoded = decodeAddress(encoded);
    expect(decoded.spendPublicKey).toBe(keys.spend.pub);
    expect(decoded.viewPublicKey).toBe(keys.view.pub);
    expect(decoded.paymentId).toBeUndefined();
  });

  it("throws a clear Error on malformed keys", () => {
    expect(() => encodeAddress("zz", "a".repeat(64))).toThrow(/could not encode ccx address/i);
    expect(() => encodeAddress("ab", "a".repeat(64))).toThrow(/could not encode ccx address/i);
  });
});

describe("encodeIntegratedAddress / makeIntegratedAddress", () => {
  const paymentId = "00112233445566aa"; // 8 bytes / 16 hex

  it("produces a valid integrated address that decodes to the same keys + payment id", () => {
    const keys = freshKeys();
    const integrated = encodeIntegratedAddress(keys.spend.pub, keys.view.pub, paymentId);
    expect(isValidAddress(integrated)).toBe(true);
    const decoded = decodeAddress(integrated);
    expect(decoded.spendPublicKey).toBe(keys.spend.pub);
    expect(decoded.viewPublicKey).toBe(keys.view.pub);
    // decodeAddress now surfaces the integrated payment id (lib-js #6).
    expect(decoded.paymentId).toBe(paymentId);
  });

  it("makeIntegratedAddress derives from a standard address + payment id", () => {
    const address = freshAddress();
    const keys = freshKeys();
    const integrated = makeIntegratedAddress(address, paymentId);
    // Same wallet → integrated address embeds the same public keys, differs from base.
    expect(integrated).not.toBe(address);
    const decoded = decodeAddress(integrated);
    expect(decoded.spendPublicKey).toBe(keys.spend.pub);
    expect(decoded.viewPublicKey).toBe(keys.view.pub);
    expect(decoded.paymentId).toBe(paymentId);
  });

  it("throws on a malformed payment id", () => {
    const keys = freshKeys();
    expect(() => encodeIntegratedAddress(keys.spend.pub, keys.view.pub, "0011")).toThrow(
      /could not encode integrated address/i,
    );
    expect(() => makeIntegratedAddress(freshAddress(), "zzzz")).toThrow(
      /could not encode integrated address/i,
    );
  });

  it("makeIntegratedAddress throws on an invalid base address", () => {
    expect(() => makeIntegratedAddress("ccx7bad", paymentId)).toThrow(/invalid ccx address/i);
  });
});
