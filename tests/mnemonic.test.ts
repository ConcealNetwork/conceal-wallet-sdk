import { describe, expect, it } from "vitest";
import { detectLanguage, generateMnemonic, isValidMnemonic, mnemonicToSeed } from "../src/mnemonic";

describe("mnemonic", () => {
  it("generates a 25-word english phrase that round-trips to a 32-byte seed", () => {
    const phrase = generateMnemonic();
    expect(phrase.split(" ")).toHaveLength(25);
    expect(isValidMnemonic(phrase)).toBe(true);
    expect(mnemonicToSeed(phrase)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("detects the wordlist language (checksum makes cross-language decode fail)", () => {
    expect(detectLanguage(generateMnemonic("spanish"))).toBe("spanish");
    expect(detectLanguage(generateMnemonic("english"))).toBe("english");
  });

  it("rejects garbage phrases", () => {
    expect(isValidMnemonic("not a real mnemonic phrase at all")).toBe(false);
    expect(detectLanguage("zzz zzz zzz")).toBeNull();
  });
});
