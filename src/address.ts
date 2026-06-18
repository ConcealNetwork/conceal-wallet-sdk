/**
 * CCX address validation/decoding and payment-URI (CoinUri) codec. Wraps
 * lib-js's loosely-typed `decode_address` and builds/parses the bare-address
 * payment links the Conceal wallets exchange (QR codes, `conceal:` links).
 */
import { ccxAddress, ccxCrypto } from "./crypto";
import type { DecodedAddress, Hex } from "./types";

/** Raw shape `crypto.decode_address` returns: public-key hex + optional integrated payment id. */
interface RawDecodedAddress {
  spend: Hex;
  view: Hex;
  /** Present only for integrated addresses. */
  intPaymentId?: Hex;
}

/**
 * Decode and validate a CCX address, normalizing to public spend/view keys
 * plus an optional integrated payment id. `decode_address` validates the
 * checksum/prefix and throws **bare strings** (not `Error`s) on bad input, so
 * we catch everything and rethrow a clear, typed `Error`.
 */
export function decodeAddress(address: string): DecodedAddress {
  let raw: RawDecodedAddress;
  try {
    raw = ccxCrypto.decode_address(address) as RawDecodedAddress;
  } catch {
    throw new Error("Invalid CCX address.");
  }
  if (!raw || typeof raw.spend !== "string" || typeof raw.view !== "string") {
    throw new Error("Invalid CCX address.");
  }
  return {
    spendPublicKey: raw.spend,
    viewPublicKey: raw.view,
    ...(raw.intPaymentId ? { paymentId: raw.intPaymentId } : {}),
  };
}

/** True iff `address` decodes to a valid CCX address. */
export function isValidAddress(address: string): boolean {
  try {
    decodeAddress(address);
    return true;
  } catch {
    return false;
  }
}

/**
 * Encode a standard CCX address from spend + view **public** keys (64-char hex
 * each). Lets a view-only wallet — which holds public keys but no seed —
 * reconstruct its address without the WASM `create_address` path. Throws on
 * malformed keys. (lib-js `address.encode_address`.)
 */
export function encodeAddress(spendPublicKey: Hex, viewPublicKey: Hex): string {
  try {
    return ccxAddress.encode_address(spendPublicKey, viewPublicKey) as string;
  } catch (error) {
    throw new Error(`Could not encode CCX address: ${(error as Error).message ?? error}`);
  }
}

/**
 * Encode a CCX **integrated** address — a standard address with an embedded
 * 8-byte (16-hex) payment id, used to attribute incoming payments without a
 * separate paymentId field. Throws on malformed keys or payment id.
 * (lib-js `address.encode_integrated_address`.)
 */
export function encodeIntegratedAddress(
  spendPublicKey: Hex,
  viewPublicKey: Hex,
  paymentId: Hex,
): string {
  try {
    return ccxAddress.encode_integrated_address(spendPublicKey, viewPublicKey, paymentId) as string;
  } catch (error) {
    throw new Error(`Could not encode integrated address: ${(error as Error).message ?? error}`);
  }
}

/**
 * Derive an integrated address from an existing standard address and a 16-hex
 * payment id — the common case for generating a per-invoice receive address.
 * Decodes the base address to its public keys, then re-encodes with the id.
 * Throws if the address is invalid or the payment id is malformed.
 */
export function makeIntegratedAddress(address: string, paymentId: Hex): string {
  const { spendPublicKey, viewPublicKey } = decodeAddress(address);
  return encodeIntegratedAddress(spendPublicKey, viewPublicKey, paymentId);
}

/** A request to be paid, as encoded in a CoinUri payment link / QR code. */
export interface PaymentRequest {
  address: string;
  amount?: number;
  paymentId?: string;
  /** Recipient name (CoinUri `recipient_name`). */
  label?: string;
  /** Free-text note (CoinUri `tx_description`). */
  message?: string;
}

/** CoinUri query-parameter names (match the legacy wallet codec). */
const PARAM = {
  amount: "amount",
  paymentId: "payment_id",
  label: "recipient_name",
  message: "tx_description",
} as const;

/** Amounts must be a plain decimal — reject commas, spaces, signs, trailing junk. */
const AMOUNT_RE = /^\d+(\.\d+)?$/;

/**
 * Build a payment URI: a **bare** validated address followed by
 * `?amount=&payment_id=&recipient_name=&tx_description=`. No `conceal:` prefix
 * (the legacy wallet dropped it — `:` broke QR scanning). Throws if the address
 * is invalid or the amount is non-finite/non-positive.
 */
export function buildPaymentUri(req: PaymentRequest): string {
  if (!isValidAddress(req.address)) {
    throw new Error("Invalid CCX address.");
  }

  const params: string[] = [];
  if (req.amount !== undefined) {
    if (!Number.isFinite(req.amount) || req.amount <= 0) {
      throw new Error("Payment amount must be a positive, finite number.");
    }
    params.push(`${PARAM.amount}=${encodeURIComponent(String(req.amount))}`);
  }
  if (req.paymentId) params.push(`${PARAM.paymentId}=${encodeURIComponent(req.paymentId)}`);
  if (req.label) params.push(`${PARAM.label}=${encodeURIComponent(req.label)}`);
  if (req.message) params.push(`${PARAM.message}=${encodeURIComponent(req.message)}`);

  return params.length > 0 ? `${req.address}?${params.join("&")}` : req.address;
}

/** Strip a tolerated `conceal:` / `conceal.` / `web+conceal:` scheme prefix. */
function stripScheme(uri: string): string {
  return uri.replace(/^(web\+)?conceal[:.]/i, "");
}

/**
 * Parse a payment URI back into a {@link PaymentRequest}. Tolerant of
 * `conceal:` / `conceal.` / bare prefixes and `?`/`&` separators. Validates the
 * address, rejects non-numeric/comma amounts, and **never throws** — returns
 * `null` on any malformed input.
 */
export function parsePaymentUri(uri: string): PaymentRequest | null {
  if (typeof uri !== "string") return null;

  // Normalize: drop the scheme, then treat both `?` and `&` as separators.
  const segments = stripScheme(uri.trim()).replace(/&/g, "?").split("?");
  const address = segments[0]?.trim();
  if (!address || !isValidAddress(address)) return null;

  const request: PaymentRequest = { address };

  for (let i = 1; i < segments.length; i++) {
    const segment = segments[i];
    if (!segment) continue;
    const eq = segment.indexOf("=");
    if (eq < 0) continue;
    const key = segment.slice(0, eq).trim();
    const rawValue = segment.slice(eq + 1);

    let value: string;
    try {
      value = decodeURIComponent(rawValue);
    } catch {
      // A malformed percent-escape (e.g. a lone `%`) makes decodeURIComponent
      // throw — treat the whole URI as malformed rather than silently dropping.
      return null;
    }

    switch (key) {
      case PARAM.amount:
      case "tx_amount": {
        if (!AMOUNT_RE.test(value)) return null;
        const amount = Number.parseFloat(value);
        if (!Number.isFinite(amount) || amount <= 0) return null;
        request.amount = amount;
        break;
      }
      case PARAM.paymentId:
      case "tx_payment_id":
        if (value) request.paymentId = value;
        break;
      case PARAM.label:
        if (value) request.label = value;
        break;
      case PARAM.message:
      case "label":
        if (value) request.message = value;
        break;
    }
  }

  return request;
}
