import { createHash } from "node:crypto";
import { mnemonic as ccxMnemonic } from "conceal-lib-js";
import { describe, expect, it } from "vitest";
import { createAccount, restoreFromMnemonic } from "../src/account";
import {
  detectLanguage,
  generateMnemonic,
  isValidMnemonic,
  mnemonicToSeed,
  SEED_LANGUAGES,
} from "../src/mnemonic";

describe("mnemonic", () => {
  it("generates a 25-word english phrase that round-trips to a 32-byte seed", () => {
    const phrase = generateMnemonic();
    expect(phrase.split(" ")).toHaveLength(25);
    expect(isValidMnemonic(phrase)).toBe(true);
    expect(mnemonicToSeed(phrase)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("round-trips EVERY supported seed language (create -> restore -> same address)", () => {
    for (const lang of SEED_LANGUAGES) {
      const acct = createAccount(lang);
      expect(acct.mnemonic).toBeDefined();
      const phrase = acct.mnemonic as string;
      expect(isValidMnemonic(phrase, lang)).toBe(true);
      expect(detectLanguage(phrase)).toBe(lang);
      // The wallet-restore path the SDK engine uses (auto-detect language).
      expect(restoreFromMnemonic(phrase).address).toBe(acct.address);
    }
  });

  it(
    "decodes Portuguese seeds incl. prefix-colliding words (lib-js disambiguation fix)",
    () => {
      const seededHex = (n: number) => createHash("sha256").update(`ccx-${n}`).digest("hex");
      for (let n = 1; n <= 400; n++) {
        const seed = seededHex(n);
        const phrase = ccxMnemonic.mn_encode(seed, "portuguese") as string;
        expect(mnemonicToSeed(phrase, "portuguese")).toBe(seed);
      }
    },
    30_000,
  );

  it("detects the wordlist language (checksum makes cross-language decode fail)", () => {
    expect(detectLanguage(generateMnemonic("spanish"))).toBe("spanish");
    expect(detectLanguage(generateMnemonic("english"))).toBe("english");
  });

  it("rejects garbage phrases", () => {
    expect(isValidMnemonic("not a real mnemonic phrase at all")).toBe(false);
    expect(detectLanguage("zzz zzz zzz")).toBeNull();
  });
});
