import { describe, expect, it } from "vitest";
import { createAccount } from "../src/account";
import {
  analyzeKeysShape,
  normalizeUserKeys,
  userKeysFromEncryptedKeysString,
  userKeysFromPriv,
} from "../src/keys";

describe("analyzeKeysShape", () => {
  // Transferred 1:1 from app:tests/keys-repository.test.ts ("keys normalization").
  it("returns invalid for missing keys", () => {
    expect(analyzeKeysShape(null)).toEqual({ kind: "invalid" });
    expect(analyzeKeysShape(undefined)).toEqual({ kind: "invalid" });
  });

  it("accepts full UserKeys shape", () => {
    const keys = {
      priv: { spend: "aa", view: "bb" },
      pub: { spend: "cc", view: "dd" },
    };
    expect(analyzeKeysShape(keys)).toEqual({ kind: "ready", keys });
  });

  it("requests pub derivation when priv is present but pub is empty", () => {
    expect(
      analyzeKeysShape({
        priv: { spend: "aa", view: "bb" },
        pub: { spend: "", view: "" },
      }),
    ).toEqual({ kind: "derive_pub", spend: "aa", view: "bb" });
  });

  it("accepts Cn-style spend/view objects (flat v0 shape)", () => {
    expect(
      analyzeKeysShape({
        spend: { sec: "aa", pub: "cc" },
        view: { sec: "bb", pub: "dd" },
      }),
    ).toEqual({ kind: "derive_pub", spend: "aa", view: "bb" });
  });

  // SDK-specific coverage of the remaining decision-table rows.
  it("treats a view-only blob (priv.spend === '' + pub.spend present) as ready", () => {
    expect(
      analyzeKeysShape({
        priv: { spend: "", view: "bb" },
        pub: { spend: "cc", view: "" },
      }),
    ).toEqual({
      kind: "ready",
      keys: {
        priv: { spend: "", view: "bb" },
        pub: { spend: "cc", view: "" },
      },
    });
  });

  it("returns invalid for an incomplete pub with empty priv.spend and no pub.spend", () => {
    expect(
      analyzeKeysShape({
        priv: { spend: "", view: "bb" },
        pub: { spend: "", view: "dd" },
      }),
    ).toEqual({ kind: "invalid" });
  });

  it("returns invalid for empty objects and unrelated shapes", () => {
    expect(analyzeKeysShape({})).toEqual({ kind: "invalid" });
    expect(analyzeKeysShape({ foo: "bar" })).toEqual({ kind: "invalid" });
    expect(analyzeKeysShape(42)).toEqual({ kind: "invalid" });
  });
});

describe("userKeysFromPriv", () => {
  it("rebuilds the public keys to match a real create_address result", () => {
    const acc = createAccount();
    const keys = userKeysFromPriv(acc.keys.spend.sec, acc.keys.view.sec);
    expect(keys.pub.spend).toBe(acc.keys.spend.pub);
    expect(keys.pub.view).toBe(acc.keys.view.pub);
    expect(keys.priv.spend).toBe(acc.keys.spend.sec);
    expect(keys.priv.view).toBe(acc.keys.view.sec);
  });
});

describe("normalizeUserKeys", () => {
  it("passes through a ready full UserKeys shape", () => {
    const keys = {
      priv: { spend: "aa", view: "bb" },
      pub: { spend: "cc", view: "dd" },
    };
    expect(normalizeUserKeys(keys)).toEqual(keys);
  });

  it("derives the missing pub from full secrets (matches create_address)", () => {
    const acc = createAccount();
    const normalized = normalizeUserKeys({
      priv: { spend: acc.keys.spend.sec, view: acc.keys.view.sec },
      pub: { spend: "", view: "" },
    });
    expect(normalized).toEqual({
      pub: { view: acc.keys.view.pub, spend: acc.keys.spend.pub },
      priv: { view: acc.keys.view.sec, spend: acc.keys.spend.sec },
    });
  });

  it("derives from the flat v0 {spend:{sec},view:{sec}} shape", () => {
    const acc = createAccount();
    const normalized = normalizeUserKeys({
      spend: { sec: acc.keys.spend.sec, pub: acc.keys.spend.pub },
      view: { sec: acc.keys.view.sec, pub: acc.keys.view.pub },
    });
    expect(normalized).toEqual({
      pub: { view: acc.keys.view.pub, spend: acc.keys.spend.pub },
      priv: { view: acc.keys.view.sec, spend: acc.keys.spend.sec },
    });
  });

  it("normalizes a view-only blob without deriving spend", () => {
    expect(
      normalizeUserKeys({
        priv: { spend: "", view: "bb" },
        pub: { spend: "cc", view: "" },
      }),
    ).toEqual({
      priv: { spend: "", view: "bb" },
      pub: { spend: "cc", view: "" },
    });
  });

  it("returns null for invalid shapes", () => {
    expect(normalizeUserKeys(null)).toBeNull();
    expect(normalizeUserKeys({})).toBeNull();
    expect(
      normalizeUserKeys({
        priv: { spend: "", view: "bb" },
        pub: { spend: "", view: "dd" },
      }),
    ).toBeNull();
  });
});

describe("userKeysFromEncryptedKeysString", () => {
  it("decodes the 128-char (privView||privSpend) form via userKeysFromPriv", () => {
    const acc = createAccount();
    const privView = acc.keys.view.sec;
    const privSpend = acc.keys.spend.sec;
    const keys = userKeysFromEncryptedKeysString(privView + privSpend);
    expect(keys).toEqual({
      pub: { view: acc.keys.view.pub, spend: acc.keys.spend.pub },
      priv: { view: privView, spend: privSpend },
    });
  });

  it("decodes the 192-char (privView||pubView||pubSpend) view-only form", () => {
    const privView = "a".repeat(64);
    const pubView = "b".repeat(64);
    const pubSpend = "c".repeat(64);
    const keys = userKeysFromEncryptedKeysString(privView + pubView + pubSpend);
    expect(keys).toEqual({
      pub: { view: pubView, spend: pubSpend },
      priv: { view: privView, spend: "" },
    });
  });

  it("returns null for other lengths", () => {
    expect(userKeysFromEncryptedKeysString("")).toBeNull();
    expect(userKeysFromEncryptedKeysString("ab")).toBeNull();
    expect(userKeysFromEncryptedKeysString("a".repeat(64))).toBeNull();
    expect(userKeysFromEncryptedKeysString("a".repeat(160))).toBeNull();
    expect(userKeysFromEncryptedKeysString("a".repeat(256))).toBeNull();
  });

  it("returns null for non-hex input", () => {
    expect(userKeysFromEncryptedKeysString("z".repeat(128))).toBeNull();
    expect(userKeysFromEncryptedKeysString(`${"a".repeat(127)} `)).toBeNull();
  });
});

describe("analyzeKeysShape — hardened corrupt-input edges (review findings)", () => {
  // Valid wallets are unchanged; these cover degenerate inputs that the legacy
  // logic mis-handled (derive_pub with empty view → sec_key_to_pub("") crash;
  // ready-with-empty-view). Now they fail fast as `invalid`.
  it("does not request derive_pub when the view secret is missing", () => {
    expect(analyzeKeysShape({ priv: { spend: "aa", view: "" }, pub: { spend: "", view: "" } })).toEqual(
      { kind: "invalid" },
    );
  });

  it("accepts a view-only shape (no spend secret) when the view secret + spend pub are present", () => {
    expect(
      analyzeKeysShape({ priv: { spend: "", view: "bb" }, pub: { spend: "cc", view: "" } }),
    ).toEqual({
      kind: "ready",
      keys: { priv: { spend: "", view: "bb" }, pub: { spend: "cc", view: "" } },
    });
  });

  it("rejects a view-only shape with no view secret", () => {
    expect(
      analyzeKeysShape({ priv: { spend: "", view: "" }, pub: { spend: "cc", view: "" } }),
    ).toEqual({ kind: "invalid" });
  });

  it("returns a canonical UserKeys shape (no undefined leakage) on the ready path", () => {
    // priv.view absent → canonicalized to "" rather than passed through undefined.
    expect(analyzeKeysShape({ priv: { spend: "aa" }, pub: { spend: "cc", view: "dd" } })).toEqual({
      kind: "ready",
      keys: { priv: { spend: "aa", view: "" }, pub: { spend: "cc", view: "dd" } },
    });
  });
});
