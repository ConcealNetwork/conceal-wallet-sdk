// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * CSPRNG helpers for spend/fusion input picks — port of legacy
 * `MathUtil.randomFloat` (`conceal-web-wallet/src/model/MathUtil.ts`), which uses
 * Web Crypto `getRandomValues` rather than `Math.random`.
 *
 * `globalThis.crypto` is available in Node 20+ and browsers.
 */

/**
 * Uniform float in `[0, 1)` from {@link crypto.getRandomValues}.
 * Same construction as legacy `MathUtil.randomFloat`.
 */
export function randomUnit(): number {
  const buf = new Uint32Array(1);
  globalThis.crypto.getRandomValues(buf);
  return (buf[0] as number) / (0xffffffff + 1);
}

/**
 * Uniform index in `[0, n)`. Returns `0` when `n <= 0` (empty pool guard).
 */
export function randomIndex(n: number): number {
  if (n <= 0) return 0;
  return Math.floor(randomUnit() * n);
}
