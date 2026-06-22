// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Legacy key normalization — opens the canonical v1 `UserKeys` shape out of the
 * many partial / historical shapes the original wallet-core stored. Ported
 * verbatim from `conceal-web-wallet`'s `KeysRepository` + `keys-normalize`
 * (shape analysis is crypto-free; pub rebuilding uses {@link cnutils}).
 */
import { cnutils } from "./crypto";
import type { Hex } from "./types";

/** Canonical v1 wallet keys — spend + view, public + private (hex, 64 chars each). */
export interface UserKeys {
  pub: { view: Hex; spend: Hex };
  priv: { spend: Hex; view: Hex };
}

/** Result of {@link analyzeKeysShape}: ready-to-use, needs pub derivation, or unusable. */
export type KeysShape =
  | { kind: "ready"; keys: UserKeys }
  | { kind: "derive_pub"; spend: Hex; view: Hex }
  | { kind: "invalid" };

/** Rebuild a full {@link UserKeys} from the two secrets — pub = `sec_key_to_pub(priv)`. */
export function userKeysFromPriv(spend: Hex, view: Hex): UserKeys {
  const pubView = cnutils.sec_key_to_pub(view) as Hex;
  const pubSpend = cnutils.sec_key_to_pub(spend) as Hex;
  return {
    pub: {
      view: pubView,
      spend: pubSpend,
    },
    priv: {
      view,
      spend,
    },
  };
}

/** Pure shape analysis — no crypto; classifies a decrypted `raw.keys` object. */
export function analyzeKeysShape(keys: unknown): KeysShape {
  if (!keys || typeof keys !== "object") {
    return { kind: "invalid" };
  }

  const k = keys as Record<string, unknown>;

  if (k.priv && k.pub) {
    const priv = k.priv as { spend?: string; view?: string };
    const pub = k.pub as { spend?: string; view?: string };
    const spend = priv.spend ?? "";
    const view = priv.view ?? "";

    if (!pub.spend || !pub.view) {
      // Full secrets present but pub missing/partial → rebuild pub from the
      // secrets. Require BOTH secrets: deriving with an empty view would call
      // sec_key_to_pub("") (throws / garbage). (legacy parity for valid wallets;
      // corrupt "spend-only" input now fails fast instead of crashing downstream.)
      if (spend !== "" && view !== "") {
        return { kind: "derive_pub", spend, view };
      }
      // View-only: no spend secret, but a spend PUBLIC key and a view secret.
      if (spend === "" && pub.spend && view !== "") {
        return {
          kind: "ready",
          keys: {
            priv: { spend: "", view },
            pub: { spend: pub.spend, view: pub.view ?? "" },
          },
        };
      }
      return { kind: "invalid" };
    }

    // Complete pub + priv → canonical pass-through, rebuilt to guarantee the
    // declared UserKeys shape (same key values; no blind cast of `k`).
    return {
      kind: "ready",
      keys: {
        priv: { spend, view },
        pub: { spend: pub.spend, view: pub.view },
      },
    };
  }

  const spend = k.spend as { sec?: string } | undefined;
  const view = k.view as { sec?: string } | undefined;
  if (spend?.sec && view?.sec) {
    return { kind: "derive_pub", spend: spend.sec, view: view.sec };
  }

  return { kind: "invalid" };
}

/** Normalize any stored key shape to canonical {@link UserKeys}, rebuilding pub when needed. */
export function normalizeUserKeys(keys: unknown): UserKeys | null {
  const shape = analyzeKeysShape(keys);
  if (shape.kind === "ready") return shape.keys;
  if (shape.kind === "derive_pub") return userKeysFromPriv(shape.spend, shape.view);
  return null;
}

/**
 * Decode the legacy `encryptedKeys` hex string (pre-`keys`-object wallets):
 * - length 128 (`privView||privSpend`) → {@link userKeysFromPriv}.
 * - length 192 (`privView||pubView||pubSpend`, view-only export) → view-only keys.
 *
 * Returns `null` for any other length or non-hex input.
 */
export function userKeysFromEncryptedKeysString(s: string): UserKeys | null {
  if (!/^[0-9a-fA-F]+$/.test(s)) {
    return null;
  }

  if (s.length === 128) {
    const privView = s.slice(0, 64);
    const privSpend = s.slice(64, 128);
    return userKeysFromPriv(privSpend, privView);
  }

  if (s.length === 192) {
    const privView = s.slice(0, 64);
    const pubView = s.slice(64, 128);
    const pubSpend = s.slice(128, 192);
    return {
      pub: {
        view: pubView,
        spend: pubSpend,
      },
      priv: {
        view: privView,
        spend: "",
      },
    };
  }

  return null;
}
