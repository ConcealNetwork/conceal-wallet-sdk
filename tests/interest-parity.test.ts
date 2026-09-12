// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Interest parity test — loads tests/fixtures/interest-parity.json (produced by
 * tools/interest-parity/gen_interest.cpp) and asserts each case against
 * calculateDepositInterest().
 *
 * ## Expected test status (post float32 rewrite)
 *
 * GREEN: V1 (BigInt), V3 (float32), V2i (float32 + m8 table), V2w (float32).
 *   Historical notes: before the rewrite, V3 e.g. v3-6mo-20k returned 539_999_999
 *   instead of 540_000_000; V2i e.g. v2i-1q-50k returned 727_268_249 instead of
 *   727_268_224 (daemon float32).
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { calculateDepositInterest } from "../src/deposits";

// ---------------------------------------------------------------------------
// Load fixture
// ---------------------------------------------------------------------------

interface FixtureCase {
  id: string;
  version: "V3" | "V2i" | "V2w" | "V1";
  amount: number;
  term: number;
  lockHeight: number;
  expectedInterest: number;
}

interface Fixture {
  source: string;
  cases: FixtureCase[];
}

const FIXTURE_PATH = join(__dirname, "fixtures/interest-parity.json");
const fixture: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf-8"));

// ---------------------------------------------------------------------------
// Sanity-check the fixture itself (always green — no JS math involved)
// ---------------------------------------------------------------------------

describe("interest-parity fixture integrity", () => {
  it("loads without error", () => {
    expect(fixture).toBeDefined();
    expect(fixture.source).toBe("tools/interest-parity/gen_interest.cpp");
  });

  it("contains at least 22 cases covering all four versions", () => {
    expect(fixture.cases.length).toBeGreaterThanOrEqual(22);
    const versions = new Set(fixture.cases.map((c) => c.version));
    expect(versions).toContain("V3");
    expect(versions).toContain("V2i");
    expect(versions).toContain("V2w");
    expect(versions).toContain("V1");
  });

  it("includes the canonical 540000000 (20000 CCX × 6 months V3) case", () => {
    const c = fixture.cases.find((x) => x.id === "v3-6mo-20k");
    expect(c).toBeDefined();
    expect(c?.expectedInterest).toBe(540_000_000);
    expect(c?.amount).toBe(20_000_000_000); // 20000 CCX × 1e6 = 2e10 atomic units
    expect(c?.term).toBe(6 * 21900);
  });

  it("V1 cases have lockHeight values that span END_MULTIPLIER_BLOCK (12750)", () => {
    const v1 = fixture.cases.filter((c) => c.version === "V1");
    expect(v1.some((c) => c.lockHeight <= 12750)).toBe(true);
    expect(v1.some((c) => c.lockHeight > 12750)).toBe(true);
  });

  it("all expectedInterest values are non-negative integers", () => {
    for (const c of fixture.cases) {
      expect(c.expectedInterest).toBeGreaterThanOrEqual(0);
      expect(Number.isInteger(c.expectedInterest)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// V1 parity — BigInt path matches C++ mul128/div128_32 exactly (GREEN)
// ---------------------------------------------------------------------------

describe("interest-parity V1 — JS BigInt matches C++ (expected GREEN)", () => {
  const v1Cases = fixture.cases.filter((c) => c.version === "V1");

  for (const c of v1Cases) {
    it(`${c.id}: amount=${c.amount} term=${c.term} lockHeight=${c.lockHeight} → ${c.expectedInterest}`, () => {
      const result = calculateDepositInterest({
        amount: c.amount,
        term: c.term,
        lockHeight: c.lockHeight,
      });
      expect(result).toBe(c.expectedInterest);
    });
  }
});

// ---------------------------------------------------------------------------
// V3 parity — float32 rewrite matches daemon
//
// Canonical proof case v3-6mo-20k:
//   C++ float32 → 540_000_000   (float32(2e10) * float32(0.027) rounds up)
//   JS  float64 → 539_999_999   (historical; fixed by float32 rewrite)
// ---------------------------------------------------------------------------

describe("interest-parity V3 — float32 rewrite matches C++ daemon [GREEN]", () => {
  const v3Cases = fixture.cases.filter((c) => c.version === "V3");

  for (const c of v3Cases) {
    it(`${c.id}: amount=${c.amount} term=${c.term} → ${c.expectedInterest}`, () => {
      const result = calculateDepositInterest({
        amount: c.amount,
        term: c.term,
        lockHeight: c.lockHeight,
      });
      expect(result).toBe(c.expectedInterest);
    });
  }
});

// ---------------------------------------------------------------------------
// V2i parity — quarterly investments (float32 + m8 table)
// ---------------------------------------------------------------------------

describe("interest-parity V2i — quarterly investment [GREEN]", () => {
  const v2iCases = fixture.cases.filter((c) => c.version === "V2i");

  for (const c of v2iCases) {
    it(`${c.id}: amount=${c.amount} term=${c.term} → ${c.expectedInterest}`, () => {
      const result = calculateDepositInterest({
        amount: c.amount,
        term: c.term,
        lockHeight: c.lockHeight,
      });
      expect(result).toBe(c.expectedInterest);
    });
  }
});

// ---------------------------------------------------------------------------
// V2w parity — weekly deposits (GREEN after float32 rewrite)
// ---------------------------------------------------------------------------

describe("interest-parity V2w — weekly deposits [GREEN]", () => {
  const v2wCases = fixture.cases.filter((c) => c.version === "V2w");

  for (const c of v2wCases) {
    it(`${c.id}: amount=${c.amount} term=${c.term} → ${c.expectedInterest}`, () => {
      const result = calculateDepositInterest({
        amount: c.amount,
        term: c.term,
        lockHeight: c.lockHeight,
      });
      expect(result).toBe(c.expectedInterest);
    });
  }
});

// ---------------------------------------------------------------------------
// Highlighted: the 540_000_000 case (GREEN after float32 rewrite)
//
// C++ float32 produces 540_000_000.
// JS float64 produced 539_999_999 (historical bug; 0.027 not exactly representable
// in binary; float32 rounding rounds up to 540M while float64 rounded down).
// The float32 rewrite now matches the daemon exactly.
// ---------------------------------------------------------------------------

describe("interest-parity 540000000 canonical edge case [GREEN after float32 rewrite]", () => {
  it("JS float32 rewrite produces 540_000_000 matching the C++ daemon", () => {
    // V3: amount=20000*1e6=20_000_000_000 atomic, term=6*21900=131400, lockHeight>413400
    // Historical note: the old float64 implementation returned 539_999_999 (one less);
    // the float32 rewrite now matches the daemon exactly.
    const result = calculateDepositInterest({
      amount: 20_000_000_000, // 20000 CCX × 1_000_000 atomic units
      term: 6 * 21900, // 131400 blocks (6 months)
      lockHeight: 500_000, // post-V3 height
    });
    expect(result).toBe(540_000_000); // C++ float32 (daemon) value

    const fixtureCase = fixture.cases.find((c) => c.id === "v3-6mo-20k");
    expect(fixtureCase?.expectedInterest).toBe(540_000_000);
    expect(result).toBe(fixtureCase?.expectedInterest);
  });
});

describe("interest-parity V3 21256 CCX × 11 months", () => {
  it("earns 1149.595264 CCX (1_149_595_264 atomic) matching Currency.cpp", () => {
    const amount = 21_256 * 1_000_000;
    const term = 11 * 21_900;
    const result = calculateDepositInterest({
      amount,
      term,
      lockHeight: 500_000,
    });
    expect(result).toBe(1_149_595_264);
    expect(result / 1_000_000).toBe(1149.595264);

    const fixtureCase = fixture.cases.find((c) => c.id === "v3-11mo-21256");
    expect(fixtureCase?.expectedInterest).toBe(1_149_595_264);
    expect(result).toBe(fixtureCase?.expectedInterest);
  });
});
