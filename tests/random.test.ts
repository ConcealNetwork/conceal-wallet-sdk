// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

import { describe, expect, it } from "vitest";
import { randomIndex, randomUnit } from "../src/random";

describe("randomUnit / randomIndex (CSPRNG)", () => {
  it("randomUnit stays in [0, 1)", () => {
    for (let i = 0; i < 50; i++) {
      const u = randomUnit();
      expect(u).toBeGreaterThanOrEqual(0);
      expect(u).toBeLessThan(1);
    }
  });

  it("randomIndex stays in [0, n)", () => {
    for (let i = 0; i < 50; i++) {
      const idx = randomIndex(7);
      expect(idx).toBeGreaterThanOrEqual(0);
      expect(idx).toBeLessThan(7);
    }
  });

  it("randomIndex(0) is 0", () => {
    expect(randomIndex(0)).toBe(0);
  });
});
