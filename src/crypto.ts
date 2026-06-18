/**
 * Typed facade over conceal-lib-js cryptographic primitives. This is the single
 * module that touches lib-js's loosely-typed (`any`) surface; everything else in
 * the SDK consumes these typed wrappers. lib-js is imported as a normal module
 * (no `window.concealjs` global) so the SDK works in Node, browsers, and bundlers.
 */
import {
  address as ccxAddress,
  crypto as ccxCrypto,
  cnutils,
  cypher,
  mnemonic,
} from "conceal-lib-js";
import type { Hex, WalletKeys } from "./types";

/** Reduce 32 bytes of entropy (hex) modulo the Ed25519 group order → a valid scalar. */
export function scReduce32(seedHex: Hex): Hex {
  return ccxCrypto.sc_reduce32(seedHex) as Hex;
}

/** Full wallet keys + encoded address from a 32-byte reduced spend seed. */
export interface CreatedAddress extends WalletKeys {
  /** The encoded ccx7… public address. */
  public_addr: string;
}

export function createAddress(seedHex: Hex): CreatedAddress {
  return ccxCrypto.create_address(seedHex) as CreatedAddress;
}

/** Derive a `{sec, pub}` pair from a seed (sec = sc_reduce32(seed), pub = sec·G). */
export function generateKeys(seedHex: Hex): { sec: Hex; pub: Hex } {
  return ccxCrypto.generate_keys(seedHex) as { sec: Hex; pub: Hex };
}

/** Keccak-256 (CryptoNote `cn_fast_hash`) of hex input → hex. */
export function cnFastHash(dataHex: Hex): Hex {
  return ccxCrypto.cn_fast_hash(dataHex) as Hex;
}

export function generateKeyDerivation(pubHex: Hex, secHex: Hex): Hex {
  return ccxCrypto.generate_key_derivation(pubHex, secHex) as Hex;
}

export function derivePublicKey(derivationHex: Hex, outIndex: number, basePubHex: Hex): Hex {
  return ccxCrypto.derive_public_key(derivationHex, outIndex, basePubHex) as Hex;
}

export function deriveSecretKey(derivationHex: Hex, outIndex: number, baseSecHex: Hex): Hex {
  return ccxCrypto.derive_secret_key(derivationHex, outIndex, baseSecHex) as Hex;
}

export function generateKeyImage(pubHex: Hex, secHex: Hex): Hex {
  return ccxCrypto.generate_key_image(pubHex, secHex) as Hex;
}

/**
 * Single (non-ring) Schnorr-style signature over `prefixHash` with the keypair
 * `(pub, sec)`. Used for deposit-withdraw inputs, which commit exactly one
 * signature (legacy `CnNativeBride.generate_signature`).
 */
export function generateSignature(prefixHash: Hex, pubHex: Hex, secHex: Hex): Hex {
  return ccxCrypto.generate_signature(prefixHash, pubHex, secHex) as Hex;
}

/**
 * Verify a single {@link generateSignature} signature. Maps to lib-js
 * `check_signature` (the legacy `CnNativeBride.verify_signature`); returns `true`
 * when `sig` is a valid signature of `prefixHash` under `pub`.
 */
export function checkSignature(prefixHash: Hex, pubHex: Hex, sigHex: Hex): boolean {
  return ccxCrypto.check_signature(prefixHash, pubHex, sigHex) as boolean;
}

/** Cryptographically-strong 32-byte entropy as hex — Node 20+ and browsers both
 *  expose `globalThis.crypto` (Web Crypto), so this is environment-agnostic. */
export function randomSeed(): Hex {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return scReduce32(hex);
}

let wasmReady: Promise<void> | null = null;

/**
 * Initialize the underlying conceal-lib-js WASM (crypto + cypher).
 *
 * **Required in the browser before ANY crypto/cypher use.** A bundler resolves
 * lib-js to its `browser` entry, which loads the WASM *asynchronously* and
 * exposes an `init()` that must be awaited — call this once at startup (e.g.
 * before opening/creating a wallet). In Node the WASM auto-initializes on import,
 * so lib-js exposes no `init` and this is a no-op. Idempotent (memoized).
 */
export async function init(): Promise<void> {
  if (wasmReady === null) {
    wasmReady = (async () => {
      const lib = (await import("conceal-lib-js")) as { init?: () => Promise<unknown> };
      if (typeof lib.init === "function") {
        await lib.init();
      }
    })();
  }
  return wasmReady;
}

// Re-export the lower-level namespaces for advanced consumers / internal modules.
export { ccxAddress, ccxCrypto, cnutils, cypher, mnemonic };
