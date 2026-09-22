// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

import { describe, expect, it } from "vitest";
import { argon2id, canonicalizeHex, hexDecode, hexEncode } from "../src/crypto";

describe("crypto.argon2id facade", () => {
  it("returns 64 lowercase hex for minimal valid params (m=8*p)", () => {
    // lib-js allows memoryKiB from 8*p … 65536; use the floor for a fast unit test.
    const out = argon2id("00", "00000000000000000000000000000000", 8, 1, 1);
    expect(out).toMatch(/^[0-9a-f]{64}$/);
  });

  it("hexEncode / hexDecode / canonicalizeHex round-trip to lowercase", () => {
    const bytes = hexDecode("AaBb");
    expect(Array.from(bytes)).toEqual([0xaa, 0xbb]);
    expect(hexEncode(bytes)).toBe("aabb");
    expect(canonicalizeHex("AaBbCcDd")).toBe("aabbccdd");
  });
});
