import { address as ccxAddress, secretbox } from "conceal-lib-js";
import { describe, expect, it } from "vitest";
import { createMemoryStorage } from "../src/adapters";
import {
  type EncryptedWalletEnvelope,
  hasStoredWallet,
  normalizeWalletPassword,
  openEncryptedWallet,
  openStoredWallet,
  type RawWalletV1,
  saveEncryptedWallet,
  saveStoredWallet,
} from "../src/envelope";
import { userKeysFromPriv } from "../src/keys";

const CCX_PREFIX = ccxAddress.ADDRESS_PREFIX; // 0x7ad4 / 31444

// 64-char hex secrets used across the suite (valid scalars not required by the codec).
const PRIV_SPEND = "a".repeat(64);
const PRIV_VIEW = "b".repeat(64);

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** Build a minimal valid RawWalletV1 with a canonical keys object. */
function makeRaw(overrides: Partial<RawWalletV1> = {}): RawWalletV1 {
  return {
    deposits: [],
    withdrawals: [],
    transactions: [],
    txPrivateKeys: {},
    lastHeight: 0,
    nonce: "",
    keys: userKeysFromPriv(PRIV_SPEND, PRIV_VIEW),
    options: { readSpeed: 50, checkMinerTx: false, customNode: false, nodeUrl: "https://x/" },
    coinAddressPrefix: CCX_PREFIX,
    ...overrides,
  };
}

describe("normalizeWalletPassword (KDF byte-exactness)", () => {
  it("left-pads a short password with ASCII '0' to 32 bytes", () => {
    const key = normalizeWalletPassword("abc");
    // ("0".repeat(32) + "abc").slice(-32) === "0".repeat(29) + "abc"
    const expected = utf8(`${"0".repeat(29)}abc`);
    expect(Array.from(key)).toEqual(Array.from(expected));
    expect(key.length).toBe(32);
  });

  it("clamps a >32-char password to its first 32 chars (char-clamp first)", () => {
    const pw = "0123456789abcdefghijklmnopqrstuvwxyzABCD"; // 40 chars
    const key = normalizeWalletPassword(pw);
    const expected = utf8(pw.slice(0, 32));
    expect(Array.from(key)).toEqual(Array.from(expected));
    expect(key.length).toBe(32);
  });

  it("passes a 32-char ASCII password through unchanged", () => {
    const pw = "0123456789abcdefghijklmnopqrstuv"; // exactly 32 chars
    expect(Array.from(normalizeWalletPassword(pw))).toEqual(Array.from(utf8(pw)));
  });

  it("does clamp-then-byteslice: a multibyte password >32 bytes keeps the LAST 32 bytes", () => {
    // 20 cyrillic chars (< 32 chars, no char-clamp) → 40 UTF-8 bytes → byte-slice last 32.
    const pw = "д".repeat(20);
    const key = normalizeWalletPassword(pw);
    expect(key.length).toBe(32);

    // Replicate the exact legacy order to prove parity.
    const padded = ("0".repeat(32) + pw).slice(-32); // char-clamp/pad (still 32 CHARS)
    let expected = utf8(padded); // 32 cyrillic chars → 64 bytes
    if (expected.length > 32) expected = expected.slice(-32); // byte-slice last 32
    expect(Array.from(key)).toEqual(Array.from(expected));
  });
});

describe("openEncryptedWallet / saveEncryptedWallet round-trip", () => {
  it("round-trips a full RawWalletV1 including v3 fields", () => {
    const raw = makeRaw({
      creationHeight: 12345,
      txPrivateKeys: { abcd: "ef".repeat(32) },
      deposits: [{ term: 1, txHash: "dd" }],
      addressBook: [{ id: "1", label: "Alice", address: "ccx7..." }],
      sentMessages: [{ txHash: "tx1", body: "hi" }],
    });
    const env = saveEncryptedWallet(raw, "hunter2");
    expect(env.nonce.length).toBe(24);
    expect(Array.isArray(env.data)).toBe(true);

    const opened = openEncryptedWallet(env, "hunter2");
    expect(opened).not.toBeNull();
    expect(opened?.raw).toEqual(raw);
    // v3 fields preserved verbatim.
    expect(opened?.raw.addressBook).toEqual(raw.addressBook);
    expect(opened?.raw.sentMessages).toEqual(raw.sentMessages);
    expect(opened?.raw.txPrivateKeys).toEqual(raw.txPrivateKeys);
    expect(opened?.raw.deposits).toEqual(raw.deposits);
    expect(opened?.keys).toEqual(raw.keys);
  });

  it("returns null for a wrong password", () => {
    const env = saveEncryptedWallet(makeRaw(), "correct-horse");
    expect(openEncryptedWallet(env, "battery-staple")).toBeNull();
  });

  it("preserves unknown future fields on round-trip (lossless)", () => {
    const raw = makeRaw({ futureField: { nested: [1, 2, 3] } } as Partial<RawWalletV1>);
    const env = saveEncryptedWallet(raw, "pw");
    expect(openEncryptedWallet(env, "pw")?.raw).toEqual(raw);
  });
});

describe("legacy-compat cross-check (gold standard)", () => {
  // Independently reproduce the legacy encode path (WalletRepository.getEncrypted)
  // using the SAME KDF + lib-js secretbox + utf8(base64-nonce) trick, then assert
  // the SDK opener recovers it byte-identically.
  function legacyEncode(raw: RawWalletV1, password: string): EncryptedWalletEnvelope {
    // KDF (clamp/pad/cyrillic) — duplicated here so the test does NOT trust the SDK.
    let pw = password;
    if (pw.length > 32) pw = pw.slice(0, 32);
    else if (pw.length < 32) pw = ("0".repeat(32) + pw).slice(-32);
    let key = utf8(pw);
    if (key.length > 32) key = key.slice(-32);

    // rawNonce = base64(16 random bytes); the nonce is its 24 ASCII bytes.
    const random = new Uint8Array(16);
    globalThis.crypto.getRandomValues(random);
    const rawNonce = Buffer.from(random).toString("base64"); // standard base64
    const nonce = utf8(rawNonce);

    const cipher = secretbox(utf8(JSON.stringify(raw)), nonce, key);
    return { data: Array.from(cipher), nonce: rawNonce };
  }

  it("opens an independently-built legacy new-format envelope byte-identically", () => {
    const raw = makeRaw({ creationHeight: 777 });
    const env = legacyEncode(raw, "passw0rd");
    const opened = openEncryptedWallet(env, "passw0rd");
    expect(opened).not.toBeNull();
    expect(opened?.raw).toEqual(raw);
  });

  it("the SDK base64 nonce matches Node's standard base64 (16 bytes → 24 chars)", () => {
    // saveEncryptedWallet must emit a 24-char standard base64 nonce.
    const env = saveEncryptedWallet(makeRaw(), "x") as { nonce: string };
    expect(env.nonce.length).toBe(24);
    expect(env.nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/); // 16 bytes → 22 data chars + "=="
  });
});

describe("old inline format", () => {
  it("decrypts encryptedKeys (number[]) and resolves keys", () => {
    const keysString = PRIV_VIEW + PRIV_SPEND; // 128 hex → privView||privSpend
    const key = normalizeWalletPassword("inline-pw");
    const random = new Uint8Array(16);
    globalThis.crypto.getRandomValues(random);
    const rawNonce = Buffer.from(random).toString("base64");
    const cipher = secretbox(utf8(keysString), utf8(rawNonce), key);

    const env: EncryptedWalletEnvelope = {
      deposits: [],
      withdrawals: [],
      transactions: [],
      lastHeight: 0,
      nonce: rawNonce, // RawWallet.nonce carries the real nonce in the old format
      coinAddressPrefix: CCX_PREFIX,
      encryptedKeys: Array.from(cipher),
    };

    const opened = openEncryptedWallet(env, "inline-pw");
    expect(opened).not.toBeNull();
    // 128-hex → fromPriv(privSpend, privView)
    expect(opened?.keys).toEqual(userKeysFromPriv(PRIV_SPEND, PRIV_VIEW));
    expect(opened?.raw.encryptedKeys).toBe(keysString);
  });

  it("returns null for a wrong password on the old format", () => {
    const key = normalizeWalletPassword("right");
    const cipher = secretbox(utf8(PRIV_VIEW + PRIV_SPEND), utf8("AAAAAAAAAAAAAAAAAAAAAA=="), key);
    const env: EncryptedWalletEnvelope = {
      deposits: [],
      withdrawals: [],
      transactions: [],
      lastHeight: 0,
      nonce: "AAAAAAAAAAAAAAAAAAAAAA==",
      coinAddressPrefix: CCX_PREFIX,
      encryptedKeys: Array.from(cipher),
    };
    expect(openEncryptedWallet(env, "wrong")).toBeNull();
  });
});

describe("wrong-network prefix guard", () => {
  it("rejects a coinAddressPrefix mismatch", () => {
    const env = saveEncryptedWallet(makeRaw({ coinAddressPrefix: 0x1234 }), "pw");
    expect(openEncryptedWallet(env, "pw")).toBeNull();
  });

  it("accepts the matching CCX prefix (default)", () => {
    const env = saveEncryptedWallet(makeRaw({ coinAddressPrefix: CCX_PREFIX }), "pw");
    expect(openEncryptedWallet(env, "pw")).not.toBeNull();
  });

  it("honors an explicit expectedAddressPrefix override", () => {
    const env = saveEncryptedWallet(makeRaw({ coinAddressPrefix: 0x1234 }), "pw");
    expect(openEncryptedWallet(env, "pw", { expectedAddressPrefix: 0x1234 })).not.toBeNull();
  });
});

describe("key resolution", () => {
  it("rebuilds pub from a partial keys object (missing pub) via normalizeUserKeys", () => {
    const raw = makeRaw({
      keys: {
        priv: { spend: PRIV_SPEND, view: PRIV_VIEW },
        pub: { spend: "", view: "" },
      } as RawWalletV1["keys"],
    });
    const env = saveEncryptedWallet(raw, "pw");
    const opened = openEncryptedWallet(env, "pw");
    expect(opened?.keys).toEqual(userKeysFromPriv(PRIV_SPEND, PRIV_VIEW));
  });

  it("resolves a 192-char encryptedKeys string (view-only export)", () => {
    const pubView = "c".repeat(64);
    const pubSpend = "d".repeat(64);
    const keysString = PRIV_VIEW + pubView + pubSpend; // 192
    const key = normalizeWalletPassword("vo");
    const cipher = secretbox(utf8(keysString), utf8("AAAAAAAAAAAAAAAAAAAAAA=="), key);
    const env: EncryptedWalletEnvelope = {
      deposits: [],
      withdrawals: [],
      transactions: [],
      lastHeight: 0,
      nonce: "AAAAAAAAAAAAAAAAAAAAAA==",
      coinAddressPrefix: CCX_PREFIX,
      encryptedKeys: Array.from(cipher),
    };
    const opened = openEncryptedWallet(env, "vo");
    expect(opened?.keys).toEqual({
      pub: { view: pubView, spend: pubSpend },
      priv: { view: PRIV_VIEW, spend: "" },
    });
  });

  it("returns null when keys cannot be resolved", () => {
    const env = saveEncryptedWallet(makeRaw({ keys: undefined }), "pw");
    expect(openEncryptedWallet(env, "pw")).toBeNull();
  });
});

describe("storage glue", () => {
  it("round-trips through saveStoredWallet / openStoredWallet", async () => {
    const storage = createMemoryStorage();
    const raw = makeRaw({ creationHeight: 42 });

    expect(await hasStoredWallet(storage)).toBe(false);
    await saveStoredWallet(storage, raw, "secret");
    expect(await hasStoredWallet(storage)).toBe(true);

    const opened = await openStoredWallet(storage, "secret");
    expect(opened?.raw).toEqual(raw);
    expect(opened?.keys).toEqual(raw.keys);

    expect(await openStoredWallet(storage, "nope")).toBeNull();
  });

  it("openStoredWallet returns null when no wallet is stored", async () => {
    const storage = createMemoryStorage();
    expect(await openStoredWallet(storage, "x")).toBeNull();
  });
});

describe("openEncryptedWallet — review hardening (Codex HIGH + 2 MED, GLM LOW)", () => {
  const RAW: RawWalletV1 = {
    transactions: [],
    deposits: [],
    withdrawals: [],
    txPrivateKeys: {},
    lastHeight: 0,
    nonce: "",
    keys: {
      pub: { view: "a".repeat(64), spend: "b".repeat(64) },
      priv: { view: "c".repeat(64), spend: "d".repeat(64) },
    },
    options: {},
    coinAddressPrefix: ccxAddress.ADDRESS_PREFIX,
  };
  const enc = (s: string) => new TextEncoder().encode(s);
  const craft = (plaintext: string, pw: string): EncryptedWalletEnvelope => {
    const key = normalizeWalletPassword(pw);
    const nonce = "AAAAAAAAAAAAAAAAAAAAAA=="; // 24-char valid nonce string
    const cipher = secretbox(enc(plaintext), enc(nonce), key);
    return { data: Array.from(cipher), nonce } as EncryptedWalletEnvelope;
  };

  it("opens a legacy wallet that omits coinAddressPrefix (defaults to expected)", () => {
    const { coinAddressPrefix: _omit, ...noPrefix } = RAW;
    const env = saveEncryptedWallet(noPrefix as RawWalletV1, "pw");
    const opened = openEncryptedWallet(env, "pw");
    expect(opened).not.toBeNull();
    expect(opened?.keys.pub.spend).toBe("b".repeat(64));
  });

  it("rejects (not throws) a malformed envelope with a bad-length nonce", () => {
    expect(openEncryptedWallet({ data: [], nonce: "" } as EncryptedWalletEnvelope, "pw")).toBeNull();
    expect(
      openEncryptedWallet({ data: [1, 2, 3], nonce: "short" } as EncryptedWalletEnvelope, "pw"),
    ).toBeNull();
  });

  it("rejects (not throws) non-array data", () => {
    expect(
      openEncryptedWallet(
        { data: "notarray", nonce: "AAAAAAAAAAAAAAAAAAAAAA==" } as unknown as EncryptedWalletEnvelope,
        "pw",
      ),
    ).toBeNull();
  });

  it("rejects authenticated-but-non-object plaintext (null / array) without crashing", () => {
    expect(openEncryptedWallet(craft("null", "pw"), "pw")).toBeNull();
    expect(openEncryptedWallet(craft("[1,2,3]", "pw"), "pw")).toBeNull();
    expect(openEncryptedWallet(craft("not json", "pw"), "pw")).toBeNull();
  });

  it("KDF: >32-char multibyte password clamps to 32 CHARS then byte-slices", () => {
    // 'д' is 2 UTF-8 bytes; 40 chars -> clamp to 32 chars -> 64 bytes -> last 32.
    const key = normalizeWalletPassword("д".repeat(40));
    expect(key.length).toBe(32);
    const legacy = (() => {
      const p = "д".repeat(40).length > 32 ? "д".repeat(40).slice(0, 32) : "";
      let k = new TextEncoder().encode(p);
      if (k.length > 32) k = k.slice(-32);
      return k;
    })();
    expect([...key]).toEqual([...legacy]);
  });
});
