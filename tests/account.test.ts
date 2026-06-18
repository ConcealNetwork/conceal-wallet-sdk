import { describe, expect, it } from "vitest";
import { createAccount, restoreFromMnemonic, restoreFromSpendKey } from "../src/account";

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
});
