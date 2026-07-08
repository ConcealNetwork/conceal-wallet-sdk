// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Canonical CryptoNote type tags and daemon JSON coercion.
 *
 * The builder/serializer uses symbolic names (`txout_to_deposit_key`, `input_to_key`, …)
 * while lib-js scan helpers and legacy wallet code expect wire codes (`"02"`, `"03"`).
 * Daemon RPC may return either form and may encode numeric fields as strings.
 */

/** Canonical vout target type for scanning (`lib-js` understands `"02"` / `"03"` only). */
export type CanonVoutType = "02" | "03";

/** Canonical deposit-spend vin type (withdraw inputs). */
export type CanonDepositVinType = "input_to_deposit_key";

/**
 * Normalize a vout target type from builder, wire, or daemon JSON into `"02"` or `"03"`.
 * Returns `null` when the tag is not a known spend/deposit output type.
 */
export function canonVoutType(type: unknown): CanonVoutType | null {
  if (type === "02" || type === 2 || type === "txout_to_key") return "02";
  if (type === "03" || type === 3 || type === "txout_to_deposit_key") return "03";
  return null;
}

/**
 * Normalize a vin type from daemon JSON. Ring spends become `"02"`; deposit spends become
 * `"input_to_deposit_key"`. Returns `null` for coinbase / unknown tags.
 */
export function canonVinType(type: unknown): "02" | CanonDepositVinType | null {
  if (type === "02" || type === 2 || type === "input_to_key") return "02";
  if (type === "03" || type === 3 || type === "input_to_deposit_key") return "input_to_deposit_key";
  return null;
}

/** Coerce daemon JSON numbers that may arrive as strings (amount, term, outputIndex, …). */
export function parseDaemonNum(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}
