// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

import { address as ccxAddress, secretbox } from "conceal-lib-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMemoryStorage, type StorageAdapter } from "../src/adapters";
import * as cryptoMod from "../src/crypto";
import { canonicalizeHex, hexDecode, hexEncode } from "../src/crypto";
import {
  bytesEqual,
  type Envelope3,
  type Envelope3Kdf,
  MAX_ENVELOPE_CIPHERTEXT_BYTES,
  MAX_ENVELOPE_JSON_CHARS,
  migrateToEnvelope3,
  normalizeWalletPassword,
  openEncryptedWallet,
  openStoredWallet,
  parseClosedArgon2idKdf,
  parseEncryptedWalletJson,
  parseEnvelope3Nonce,
  type RawWalletV1,
  saveEncryptedWallet,
  saveStoredWallet,
  WALLET_STORAGE_KEY,
} from "../src/envelope";
import { userKeysFromPriv } from "../src/keys";

/** 16-byte salt as lowercase hex. */
const SALT16 = "01".repeat(16);
/** 24-byte nonce as lowercase hex. */
const NONCE24 = "ab".repeat(24);
/** Fixed 32-byte secretbox key as 64 hex chars (argon2id mock return). */
const FAKE_KEY_HEX = "11".repeat(32);

const PRIV_SPEND = "a".repeat(64);
const PRIV_VIEW = "b".repeat(64);
const CCX_PREFIX = ccxAddress.ADDRESS_PREFIX;

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function validKdf(overrides: Record<string, unknown> = {}) {
  return {
    alg: "argon2id",
    v: 19,
    m: 32768,
    t: 3,
    p: 1,
    salt: SALT16,
    ...overrides,
  };
}

function makeWallet(overrides: Partial<RawWalletV1> = {}): RawWalletV1 {
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

/** Craft a decryptable Envelope 3 using the FAKE_KEY_HEX secretbox key. */
function craftEnvelope3(
  wallet: RawWalletV1,
  kdfOverrides: Record<string, unknown> = {},
  opts: { outerKdfPatch?: Record<string, unknown>; data?: number[] } = {},
): Envelope3 {
  const kdf = validKdf({ m: 19456, t: 2, p: 1, ...kdfOverrides }) as Envelope3Kdf;
  const inner = {
    envelope: 3 as const,
    kdf,
    nonce: NONCE24,
    wallet,
  };
  const key = hexDecode(FAKE_KEY_HEX);
  const nonceBytes = hexDecode(NONCE24);
  const cipher = secretbox(utf8(JSON.stringify(inner)), nonceBytes, key);
  const outerKdf = { ...kdf, ...opts.outerKdfPatch };
  return {
    envelope: 3,
    kdf: outerKdf as Envelope3Kdf,
    nonce: NONCE24,
    data: opts.data ?? Array.from(cipher),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("envelope size constants", () => {
  it("exports the Envelope 3 size gates", () => {
    expect(MAX_ENVELOPE_CIPHERTEXT_BYTES).toBe(8_388_608);
    expect(MAX_ENVELOPE_JSON_CHARS).toBe(33_554_432);
  });
});

describe("parseEncryptedWalletJson", () => {
  it("rejects oversize strings before JSON.parse", () => {
    const text = "x".repeat(MAX_ENVELOPE_JSON_CHARS + 1);
    expect(parseEncryptedWalletJson(text)).toBeNull();
  });

  it("rejects non-string input", () => {
    expect(parseEncryptedWalletJson(null as unknown as string)).toBeNull();
    expect(parseEncryptedWalletJson(42 as unknown as string)).toBeNull();
  });

  it("rejects invalid JSON", () => {
    expect(parseEncryptedWalletJson("{")).toBeNull();
    expect(parseEncryptedWalletJson("not-json")).toBeNull();
  });

  it("rejects non-plain-object JSON values", () => {
    expect(parseEncryptedWalletJson("null")).toBeNull();
    expect(parseEncryptedWalletJson("[]")).toBeNull();
    expect(parseEncryptedWalletJson('"hi"')).toBeNull();
    expect(parseEncryptedWalletJson("3")).toBeNull();
  });

  it("returns a valid plain object without decrypting", () => {
    const obj = { envelope: 3, kdf: validKdf(), nonce: NONCE24, data: [1, 2, 3] };
    const parsed = parseEncryptedWalletJson(JSON.stringify(obj));
    expect(parsed).toEqual(obj);
  });

  it("accepts a string at the exact MAX_ENVELOPE_JSON_CHARS bound when it is valid JSON object", () => {
    // Minimal object padded via a long string field to hit the char bound exactly.
    const prefix = '{"pad":"';
    const suffix = '"}';
    const padLen = MAX_ENVELOPE_JSON_CHARS - prefix.length - suffix.length;
    const text = `${prefix}${"a".repeat(padLen)}${suffix}`;
    expect(text.length).toBe(MAX_ENVELOPE_JSON_CHARS);
    expect(parseEncryptedWalletJson(text)).toEqual({ pad: "a".repeat(padLen) });
  });
});

describe("parseClosedArgon2idKdf", () => {
  it("accepts a closed kdf and canonicalizes mixed-case salt", () => {
    const mixed = "AaBbCcDd".repeat(4); // 32 hex chars = 16 bytes
    const parsed = parseClosedArgon2idKdf(validKdf({ salt: mixed }));
    expect(parsed).not.toBeNull();
    if (parsed === null) return;
    expect(parsed.alg).toBe("argon2id");
    expect(parsed.v).toBe(19);
    expect(parsed.m).toBe(32768);
    expect(parsed.t).toBe(3);
    expect(parsed.p).toBe(1);
    expect(parsed.saltCanonicalHex).toBe(canonicalizeHex(mixed));
    expect(parsed.saltBytes.length).toBe(16);
    expect(hexEncode(parsed.saltBytes)).toBe(parsed.saltCanonicalHex);
  });

  it("rejects an extra key on the closed kdf object", () => {
    expect(parseClosedArgon2idKdf(validKdf({ extra: true }))).toBeNull();
  });

  it("rejects wrong types (stringy numbers, bad alg)", () => {
    expect(parseClosedArgon2idKdf(validKdf({ v: "19" }))).toBeNull();
    expect(parseClosedArgon2idKdf(validKdf({ m: "32768" }))).toBeNull();
    expect(parseClosedArgon2idKdf(validKdf({ t: "3" }))).toBeNull();
    expect(parseClosedArgon2idKdf(validKdf({ p: "1" }))).toBeNull();
    expect(parseClosedArgon2idKdf(validKdf({ alg: "argon2i" }))).toBeNull();
    expect(parseClosedArgon2idKdf(null)).toBeNull();
    expect(parseClosedArgon2idKdf([])).toBeNull();
  });

  it("rejects salt that does not decode to exactly 16 bytes", () => {
    expect(parseClosedArgon2idKdf(validKdf({ salt: "aa".repeat(15) }))).toBeNull();
    expect(parseClosedArgon2idKdf(validKdf({ salt: "aa".repeat(17) }))).toBeNull();
    expect(parseClosedArgon2idKdf(validKdf({ salt: "zz".repeat(16) }))).toBeNull();
    expect(parseClosedArgon2idKdf(validKdf({ salt: 123 }))).toBeNull();
  });
});

describe("parseEnvelope3Nonce + bytesEqual", () => {
  it("decodes a 24-byte hex nonce", () => {
    const nonce = parseEnvelope3Nonce(NONCE24);
    expect(nonce).not.toBeNull();
    if (nonce === null) return;
    expect(nonce.length).toBe(24);
    expect(hexEncode(nonce)).toBe(NONCE24);
  });

  it("rejects wrong nonce length or type", () => {
    expect(parseEnvelope3Nonce("ab".repeat(23))).toBeNull();
    expect(parseEnvelope3Nonce("ab".repeat(25))).toBeNull();
    expect(parseEnvelope3Nonce(123)).toBeNull();
  });

  it("bytesEqual compares decoded salt/nonce bytes", () => {
    const a = parseClosedArgon2idKdf(validKdf({ salt: "Aa".repeat(16) }));
    const b = parseClosedArgon2idKdf(validKdf({ salt: "aa".repeat(16) }));
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    if (a === null || b === null) return;
    expect(bytesEqual(a.saltBytes, b.saltBytes)).toBe(true);

    const n1 = parseEnvelope3Nonce(NONCE24);
    const n2 = parseEnvelope3Nonce(NONCE24.toUpperCase());
    const nZero = parseEnvelope3Nonce("00".repeat(24));
    expect(n1).not.toBeNull();
    expect(n2).not.toBeNull();
    expect(nZero).not.toBeNull();
    if (n1 === null || n2 === null || nZero === null) return;
    expect(bytesEqual(n1, n2)).toBe(true);
    expect(bytesEqual(n1, nZero)).toBe(false);
  });
});

describe("Envelope3 type shape", () => {
  it("describes the Envelope 3 wire object", () => {
    const env: Envelope3 = {
      envelope: 3,
      kdf: {
        alg: "argon2id",
        v: 19,
        m: 32768,
        t: 3,
        p: 1,
        salt: SALT16,
      },
      nonce: NONCE24,
      data: [0, 1, 2],
    };
    expect(env.envelope).toBe(3);
    expect(env.kdf.alg).toBe("argon2id");
    expect(env.data).toEqual([0, 1, 2]);
  });
});

describe("openEncryptedWallet — Envelope 3 dispatch", () => {
  function mockArgon2id() {
    return vi.spyOn(cryptoMod, "argon2id").mockReturnValue(FAKE_KEY_HEX);
  }

  it("rejects envelope: 4 (fail-closed)", () => {
    mockArgon2id();
    expect(openEncryptedWallet({ envelope: 4, data: [1], nonce: "x" } as never, "pw")).toBeNull();
    expect(cryptoMod.argon2id).not.toHaveBeenCalled();
  });

  it('rejects envelope: "3" string (fail-closed)', () => {
    mockArgon2id();
    expect(
      openEncryptedWallet(
        { envelope: "3", kdf: validKdf(), nonce: NONCE24, data: [1] } as never,
        "pw",
      ),
    ).toBeNull();
    expect(cryptoMod.argon2id).not.toHaveBeenCalled();
  });

  it("rejects non-plain-object envelope args", () => {
    expect(openEncryptedWallet(null as never, "pw")).toBeNull();
    expect(openEncryptedWallet([] as never, "pw")).toBeNull();
    expect(openEncryptedWallet("nope" as never, "pw")).toBeNull();
  });

  it("opens a valid Envelope 3 (allowlist 19456/2/1) and returns envelope: 3", () => {
    const argonSpy = mockArgon2id();
    const wallet = makeWallet({ creationHeight: 99 });
    const env = craftEnvelope3(wallet);
    const opened = openEncryptedWallet(env, "correct-horse");
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(3);
    expect(opened?.raw).toEqual(wallet);
    expect(opened?.keys).toEqual(wallet.keys);
    expect(argonSpy).toHaveBeenCalledWith(
      hexEncode(utf8("correct-horse")),
      canonicalizeHex(SALT16),
      19456,
      2,
      1,
    );
  });

  it("does not call normalizeWalletPassword when opening envelope: 3", async () => {
    const argonSpy = mockArgon2id();
    const legacyKdf = await import("../src/legacy-kdf");
    const normalizeSpy = vi.spyOn(legacyKdf, "normalizeWalletPassword");
    // Discriminating fixture: 40-char password — pad-KDF would clamp to 32 chars first;
    // argon2id must receive the full UTF-8 password hex (proves legacy KDF unused).
    const longPw = "x".repeat(40);
    const env = craftEnvelope3(makeWallet());
    const opened = openEncryptedWallet(env, longPw);
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(3);
    expect(argonSpy).toHaveBeenCalledWith(
      hexEncode(utf8(longPw)),
      canonicalizeHex(SALT16),
      19456,
      2,
      1,
    );
    expect(normalizeSpy).not.toHaveBeenCalled();
  });

  it("rejects a non-allowlisted (m,t,p) without deriving", () => {
    mockArgon2id();
    const env = craftEnvelope3(makeWallet(), { m: 20000, t: 2, p: 1 });
    expect(openEncryptedWallet(env, "pw")).toBeNull();
    expect(cryptoMod.argon2id).not.toHaveBeenCalled();
  });

  it("rejects m too large (m > 65536) without deriving", () => {
    mockArgon2id();
    const env = craftEnvelope3(makeWallet(), { m: 65537, t: 3, p: 1 });
    expect(openEncryptedWallet(env, "pw")).toBeNull();
    expect(cryptoMod.argon2id).not.toHaveBeenCalled();
  });

  it("rejects p=0 without deriving", () => {
    mockArgon2id();
    const env = craftEnvelope3(makeWallet(), { m: 32768, t: 3, p: 0 });
    expect(openEncryptedWallet(env, "pw")).toBeNull();
    expect(cryptoMod.argon2id).not.toHaveBeenCalled();
  });

  it("returns null when outer kdf.m is tampered after encryption", () => {
    mockArgon2id();
    // Outer claims allowlisted 32768/3/1 but inner (and cipher) was built with 19456/2/1.
    const env = craftEnvelope3(
      makeWallet(),
      { m: 19456, t: 2, p: 1 },
      {
        outerKdfPatch: { m: 32768, t: 3, p: 1 },
      },
    );
    expect(openEncryptedWallet(env, "pw")).toBeNull();
  });

  it("returns null when a ciphertext byte is flipped (authenticated secretbox)", () => {
    mockArgon2id();
    const env = craftEnvelope3(makeWallet({ lastHeight: 5 }));
    expect(env.data.length).toBeGreaterThan(0);
    // Discriminating flip: XOR first byte so MAC fails — distinct from kdf.m outer/inner mismatch.
    const tampered: Envelope3 = {
      ...env,
      data: env.data.map((b, i) => (i === 0 ? b ^ 0xff : b)),
    };
    expect(tampered.data[0]).not.toBe(env.data[0]);
    expect(openEncryptedWallet(tampered, "pw")).toBeNull();
  });

  it("rejects closed kdf with an extra key", () => {
    mockArgon2id();
    const env = craftEnvelope3(makeWallet());
    (env.kdf as unknown as Record<string, unknown>).extra = true;
    expect(openEncryptedWallet(env, "pw")).toBeNull();
    expect(cryptoMod.argon2id).not.toHaveBeenCalled();
  });

  it("rejects oversize ciphertext before deriving", () => {
    mockArgon2id();
    const env = craftEnvelope3(
      makeWallet(),
      {},
      {
        data: new Array(MAX_ENVELOPE_CIPHERTEXT_BYTES + 1).fill(0),
      },
    );
    expect(openEncryptedWallet(env, "pw")).toBeNull();
    expect(cryptoMod.argon2id).not.toHaveBeenCalled();
  });

  it("returns null on wrong password without throwing", () => {
    // Mock returns a different key than the one used to craft → secretbox.open null.
    vi.spyOn(cryptoMod, "argon2id").mockReturnValue("22".repeat(32));
    const env = craftEnvelope3(makeWallet());
    expect(() => openEncryptedWallet(env, "wrong")).not.toThrow();
    expect(openEncryptedWallet(env, "wrong")).toBeNull();
  });

  it("decodes as Envelope 3 when both envelope:3 and data[] are present (not env 2)", () => {
    mockArgon2id();
    const wallet = makeWallet({ lastHeight: 7 });
    const env = craftEnvelope3(wallet);
    // If legacy env-2 path were taken, utf8(nonce hex string) would be wrong nonce → null.
    const opened = openEncryptedWallet(env, "pw");
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(3);
    expect(opened?.raw.lastHeight).toBe(7);
  });
});

describe("saveEncryptedWallet — Envelope 3 write", () => {
  function mockArgon2id() {
    return vi.spyOn(cryptoMod, "argon2id").mockReturnValue(FAKE_KEY_HEX);
  }

  it("writes envelope:3 with write profile 32768/3/1 and closed argon2id kdf", () => {
    const argonSpy = mockArgon2id();
    const wallet = makeWallet({ creationHeight: 42 });
    const env = saveEncryptedWallet(wallet, "hunter2");

    expect(env.envelope).toBe(3);
    expect(env.kdf).toEqual({
      alg: "argon2id",
      v: 19,
      m: 32768,
      t: 3,
      p: 1,
      salt: env.kdf.salt,
    });
    expect(Object.keys(env.kdf).sort()).toEqual(["alg", "m", "p", "salt", "t", "v"]);
    expect(env.kdf.salt).toMatch(/^[0-9a-f]{32}$/);
    expect(env.nonce).toMatch(/^[0-9a-f]{48}$/);
    expect(Array.isArray(env.data)).toBe(true);
    expect(env.data.length).toBeGreaterThan(0);

    expect(argonSpy).toHaveBeenCalledWith(
      hexEncode(utf8("hunter2")),
      canonicalizeHex(env.kdf.salt),
      32768,
      3,
      1,
    );
  });

  it("round-trips save → open with the correct password", () => {
    mockArgon2id();
    const wallet = makeWallet({ lastHeight: 99, creationHeight: 7 });
    const env = saveEncryptedWallet(wallet, "correct-horse");
    const opened = openEncryptedWallet(env, "correct-horse");
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(3);
    expect(opened?.raw).toEqual(wallet);
    expect(opened?.keys).toEqual(wallet.keys);
  });

  it("returns null on wrong password after save", () => {
    mockArgon2id();
    const env = saveEncryptedWallet(makeWallet(), "right");
    // Different derived key than the one used at save time.
    vi.spyOn(cryptoMod, "argon2id").mockReturnValue("22".repeat(32));
    expect(openEncryptedWallet(env, "wrong")).toBeNull();
  });

  it("round-trips a non-ASCII UTF-8 password without legacy clamp", async () => {
    const argonSpy = mockArgon2id();
    const legacyKdf = await import("../src/legacy-kdf");
    const normalizeSpy = vi.spyOn(legacyKdf, "normalizeWalletPassword");
    const pw = "пароль🔐";
    const wallet = makeWallet({ lastHeight: 3 });
    const env = saveEncryptedWallet(wallet, pw);
    const opened = openEncryptedWallet(env, pw);
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(3);
    expect(opened?.raw).toEqual(wallet);
    expect(argonSpy).toHaveBeenCalledWith(
      hexEncode(utf8(pw)),
      canonicalizeHex(env.kdf.salt),
      32768,
      3,
      1,
    );
    expect(normalizeSpy).not.toHaveBeenCalled();
  });

  it("throws RangeError when password UTF-8 length exceeds 1024", () => {
    mockArgon2id();
    const tooLong = "a".repeat(1025);
    expect(() => saveEncryptedWallet(makeWallet(), tooLong)).toThrow(RangeError);
    expect(cryptoMod.argon2id).not.toHaveBeenCalled();
  });
});

/** Craft a decryptable Envelope 2 (`{ data, nonce }`) with legacy pad-KDF. */
function craftEnvelope2(wallet: RawWalletV1, password: string): { data: number[]; nonce: string } {
  const key = normalizeWalletPassword(password);
  const random = new Uint8Array(16);
  globalThis.crypto.getRandomValues(random);
  const rawNonce = Buffer.from(random).toString("base64");
  const cipher = secretbox(utf8(JSON.stringify(wallet)), utf8(rawNonce), key);
  return { data: Array.from(cipher), nonce: rawNonce };
}

describe("migrateToEnvelope3 + openStoredWallet migration", () => {
  function mockArgon2id() {
    return vi.spyOn(cryptoMod, "argon2id").mockReturnValue(FAKE_KEY_HEX);
  }

  it("migrateToEnvelope3 re-encrypts opened.raw to Envelope 3 and verifies", () => {
    mockArgon2id();
    const wallet = makeWallet({ creationHeight: 55 });
    const env2 = craftEnvelope2(wallet, "migrate-pw");
    const opened = openEncryptedWallet(env2, "migrate-pw");
    expect(opened).not.toBeNull();
    if (opened === null) return;
    expect(opened.envelope).toBe(2);

    const v3 = migrateToEnvelope3(opened, "migrate-pw");
    expect(v3).not.toBeNull();
    if (v3 === null) return;
    expect(v3.envelope).toBe(3);
    expect(v3.kdf.m).toBe(32768);

    const reopened = openEncryptedWallet(v3, "migrate-pw");
    expect(reopened?.raw).toEqual(wallet);
    expect(reopened?.envelope).toBe(3);
  });

  it("migrateToEnvelope3 returns null when verify open fails", () => {
    let argonCalls = 0;
    vi.spyOn(cryptoMod, "argon2id").mockImplementation(() => {
      argonCalls += 1;
      // save derives with FAKE_KEY; verify open gets a different key → null
      return argonCalls === 1 ? FAKE_KEY_HEX : "22".repeat(32);
    });
    const wallet = makeWallet();
    const opened = openEncryptedWallet(craftEnvelope2(wallet, "pw"), "pw");
    expect(opened).not.toBeNull();
    if (opened === null) return;

    expect(migrateToEnvelope3(opened, "pw")).toBeNull();
    expect(argonCalls).toBeGreaterThanOrEqual(2);
  });

  it("openStoredWallet migrates Envelope 2 → 3 and rewrites storage", async () => {
    mockArgon2id();
    const storage = createMemoryStorage();
    const wallet = makeWallet({ lastHeight: 12 });
    const env2 = craftEnvelope2(wallet, "secret");
    const legacyJson = JSON.stringify(env2);
    await storage.setItem(WALLET_STORAGE_KEY, legacyJson);

    const opened = await openStoredWallet(storage, "secret");
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(3);
    expect(opened?.raw).toEqual(wallet);

    const after = await storage.getItem(WALLET_STORAGE_KEY);
    expect(after).not.toBeNull();
    if (after === null) return;
    expect(after).not.toBe(legacyJson);
    const stored = JSON.parse(after) as Envelope3;
    expect(stored.envelope).toBe(3);
    expect(stored.kdf.alg).toBe("argon2id");
  });

  it("openStoredWallet leaves storage unchanged when migrate verify fails", async () => {
    let argonCalls = 0;
    vi.spyOn(cryptoMod, "argon2id").mockImplementation(() => {
      argonCalls += 1;
      return argonCalls === 1 ? FAKE_KEY_HEX : "22".repeat(32);
    });
    const storage = createMemoryStorage();
    const wallet = makeWallet({ creationHeight: 9 });
    const legacyJson = JSON.stringify(craftEnvelope2(wallet, "secret"));
    await storage.setItem(WALLET_STORAGE_KEY, legacyJson);

    const opened = await openStoredWallet(storage, "secret");
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(2);
    expect(opened?.raw).toEqual(wallet);
    expect(await storage.getItem(WALLET_STORAGE_KEY)).toBe(legacyJson);
  });

  it("openStoredWallet returns legacy opened when setItem throws after verify", async () => {
    mockArgon2id();
    const base = createMemoryStorage();
    const wallet = makeWallet({ lastHeight: 3 });
    const legacyJson = JSON.stringify(craftEnvelope2(wallet, "secret"));
    await base.setItem(WALLET_STORAGE_KEY, legacyJson);

    const storage: StorageAdapter = {
      getItem: (key) => base.getItem(key),
      setItem: async () => {
        throw new Error("quota exceeded");
      },
      removeItem: (key) => base.removeItem(key),
      keys: () => base.keys(),
    };

    const opened = await openStoredWallet(storage, "secret");
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(2);
    expect(opened?.raw).toEqual(wallet);
    expect(await base.getItem(WALLET_STORAGE_KEY)).toBe(legacyJson);
  });

  it("openStoredWallet does not rewrite storage when already Envelope 3", async () => {
    mockArgon2id();
    const storage = createMemoryStorage();
    const wallet = makeWallet({ creationHeight: 1 });
    await saveStoredWallet(storage, wallet, "secret");
    const before = await storage.getItem(WALLET_STORAGE_KEY);
    expect(before).not.toBeNull();

    const opened = await openStoredWallet(storage, "secret");
    expect(opened?.envelope).toBe(3);
    expect(await storage.getItem(WALLET_STORAGE_KEY)).toBe(before);
  });

  it("openStoredWallet migrates env2 with non-default coinAddressPrefix when opts match", async () => {
    mockArgon2id();
    const storage = createMemoryStorage();
    const customPrefix = 0x1234;
    const wallet = makeWallet({ coinAddressPrefix: customPrefix, lastHeight: 44 });
    await storage.setItem(WALLET_STORAGE_KEY, JSON.stringify(craftEnvelope2(wallet, "secret")));

    const opened = await openStoredWallet(storage, "secret", {
      expectedAddressPrefix: customPrefix,
    });
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(3);
    expect(opened?.raw.coinAddressPrefix).toBe(customPrefix);

    const after = await storage.getItem(WALLET_STORAGE_KEY);
    expect(after).not.toBeNull();
    if (after === null) return;
    expect(JSON.parse(after).envelope).toBe(3);
  });

  it("openStoredWallet returns null for oversize stored JSON via parseEncryptedWalletJson", async () => {
    mockArgon2id();
    const storage = createMemoryStorage();
    const oversize = "x".repeat(MAX_ENVELOPE_JSON_CHARS + 1);
    await storage.setItem(WALLET_STORAGE_KEY, oversize);

    expect(await openStoredWallet(storage, "secret")).toBeNull();
    expect(await storage.getItem(WALLET_STORAGE_KEY)).toBe(oversize);
  });
});

/**
 * Live Argon2id (write profile 32768/3/1, ~32 MiB). CI leaves CONCEAL_ARGON2_LIVE
 * unset so this block is skipped; set CONCEAL_ARGON2_LIVE=1 to exercise the real
 * primitive. Unit tests above mock argon2id for codec coverage.
 */
describe.skipIf(!process.env.CONCEAL_ARGON2_LIVE)("live argon2id", () => {
  it("save → open round-trips with real Argon2id (32768,3,1)", () => {
    const wallet = makeWallet({ creationHeight: 777, lastHeight: 11 });
    const password = "live-argon2id-pw";
    const env = saveEncryptedWallet(wallet, password);
    expect(env.envelope).toBe(3);
    expect(env.kdf.m).toBe(32768);
    expect(env.kdf.t).toBe(3);
    expect(env.kdf.p).toBe(1);

    const opened = openEncryptedWallet(env, password);
    expect(opened).not.toBeNull();
    expect(opened?.envelope).toBe(3);
    expect(opened?.raw).toEqual(wallet);
    expect(opened?.keys).toEqual(wallet.keys);

    expect(openEncryptedWallet(env, "wrong-password")).toBeNull();
  });
});
