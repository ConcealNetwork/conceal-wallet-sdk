/**
 * conceal-wallet-sdk — framework-agnostic, typed TypeScript wallet engine for
 * Conceal (CCX), built on the conceal-lib-js cryptographic primitives.
 */

export { type Account, createAccount, restoreFromMnemonic, restoreFromSpendKey } from "./account";
export {
  buildPaymentUri,
  decodeAddress,
  isValidAddress,
  type PaymentRequest,
  parsePaymentUri,
} from "./address";
/** Low-level typed crypto primitives (advanced use). */
export * as crypto from "./crypto";
export {
  createDaemonClient,
  type DaemonClient,
  type DaemonClientOptions,
  normalizeNodeUrl,
} from "./daemon";
/** Encrypted messages + the smart-message protocol. */
export * as messages from "./messages";
export {
  detectLanguage,
  generateMnemonic,
  isValidMnemonic,
  mnemonicToSeed,
  SEED_LANGUAGES,
} from "./mnemonic";
export type {
  DecodedAddress,
  Hex,
  KeyPair,
  PublicKeys,
  SeedLanguage,
  ViewOnlyKeys,
  WalletKeys,
} from "./types";
