import { describe, expect, it } from "vitest";
import {
  createAccount,
  omitMnemonic,
  restoreFromMnemonic,
  restoreFromSpendKey,
} from "../src/account";

describe("account", () => {
  it("creates a wallet with a ccx7 address, hex keys, and a 25-word mnemonic", () => {
    const acc = createAccount();
    expect(acc.address.startsWith("ccx7")).toBe(true);
    expect(acc.keys.spend.sec).toMatch(/^[0-9a-f]{64}$/);
    expect(acc.keys.spend.pub).toMatch(/^[0-9a-f]{64}$/);
    expect(acc.keys.view.sec).toMatch(/^[0-9a-f]{64}$/);
    expect(acc.mnemonic?.split(" ")).toHaveLength(25);
  });

  it("round-trips: restoring from its own mnemonic reproduces address + keys", () => {
    const acc = createAccount();
    const restored = restoreFromMnemonic(acc.mnemonic as string);
    expect(restored.address).toBe(acc.address);
    expect(restored.keys).toEqual(acc.keys);
  });

  it("restores deterministically from the spend key", () => {
    const acc = createAccount();
    const restored = restoreFromSpendKey(acc.keys.spend.sec);
    expect(restored.address).toBe(acc.address);
    expect(restored.keys).toEqual(acc.keys);
  });

  it("auto-detects the language on restore (no language passed)", () => {
    const acc = createAccount("spanish");
    const restored = restoreFromMnemonic(acc.mnemonic as string);
    expect(restored.address).toBe(acc.address);
  });

  it("throws on an invalid mnemonic", () => {
    expect(() => restoreFromMnemonic("not a real phrase")).toThrow();
  });

  it("omitMnemonic strips the mnemonic and preserves address + keys", () => {
    const acc = createAccount();
    const safe = omitMnemonic(acc);
    expect("mnemonic" in safe).toBe(false);
    expect(safe.address).toBe(acc.address);
    expect(safe.keys).toEqual(acc.keys);
  });

  it("omitMnemonic does not mutate the input", () => {
    const acc = createAccount();
    const snapshot = { ...acc, keys: { ...acc.keys } };
    omitMnemonic(acc);
    expect(acc).toEqual(snapshot);
    expect(acc.mnemonic).toBe(snapshot.mnemonic);
  });

  it("omitMnemonic returns a copy with no mnemonic key when it is already absent", () => {
    const bare = restoreFromSpendKey(createAccount().keys.spend.sec);
    expect("mnemonic" in bare).toBe(false);
    const safe = omitMnemonic(bare);
    expect("mnemonic" in safe).toBe(false);
    expect(safe.address).toBe(bare.address);
    expect(safe.keys).toEqual(bare.keys);
    expect(safe).not.toBe(bare);
  });
});
