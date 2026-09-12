// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Investment m8 parity test.
 *
 * Expected hex values were produced by running the C++ generator at
 * tools/interest-parity/gen_m8.cpp (g++ -O0 -lm) which exactly reproduces
 * the Currency.cpp investment pow line:
 *
 *   auto mq = static_cast<float>(1.4473);
 *   float termQuarters = term / 64800;
 *   auto m8 = (float)(100.0 * pow(1.0 + (mq / 100.0), termQuarters) - 100.0);
 *
 * Each entry: [quarter, float32 bit pattern as hex string]
 */
import { describe, expect, it } from "vitest";
import { INVESTMENT_M8 } from "../src/deposits/investment-m8";

// C++ generator output — do not hand-edit these hex values.
const EXPECTED_HEX: readonly [number, string][] = [
  [1, "3FB94120"],
  [2, "403A9851"],
  [3, "408CF61D"],
  [4, "40BD50AC"],
  [5, "40EE5E62"],
  [6, "411010EB"],
  [7, "41294ED6"],
  [8, "4142EA47"],
  [9, "415CE499"],
  [10, "41773F2B"],
  [11, "4188FDB0"],
  [12, "41968D53"],
  [13, "41A44F34"],
  [14, "41B2440D"],
  [15, "41C06C9D"],
  [16, "41CEC9A2"],
  [17, "41DD5BDF"],
  [18, "41EC2418"],
  [19, "41FB2316"],
  [20, "42052CD2"],
];

describe("INVESTMENT_M8 table", () => {
  it("has exactly 20 entries", () => {
    expect(INVESTMENT_M8.length).toBe(20);
  });

  it("each entry Math.fround bit-pattern matches C++ float32", () => {
    const buf = new Float32Array(1);
    const view = new DataView(buf.buffer);

    for (const [quarter, hex] of EXPECTED_HEX) {
      const entry = INVESTMENT_M8[quarter - 1];
      expect(entry, `quarter ${quarter} entry missing`).toBeDefined();

      // Store the value from the table as float32, read the bits back.
      // biome-ignore lint/style/noNonNullAssertion: guarded by toBeDefined above
      buf[0] = Math.fround(entry!.m8);
      const actualBits = view.getUint32(0, true); // little-endian (native x86)

      const expectedBits = Number.parseInt(hex, 16);
      expect(
        actualBits.toString(16).toUpperCase().padStart(8, "0"),
        `quarter ${quarter} bit-pattern mismatch`,
      ).toBe(hex);
      expect(actualBits, `quarter ${quarter} uint32 mismatch`).toBe(expectedBits);

      // Also verify the table's own hex field matches the expected hex string.
      // biome-ignore lint/style/noNonNullAssertion: guarded by toBeDefined above
      expect(entry!.hex, `quarter ${quarter} entry.hex mismatch`).toBe(hex);
    }
  });
});
