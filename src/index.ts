/**
 * conceal-wallet-sdk — framework-agnostic, typed TypeScript wallet engine for
 * Conceal (CCX), built on the conceal-lib-js cryptographic primitives.
 */

export { type Account, createAccount, restoreFromMnemonic, restoreFromSpendKey } from "./account";
/** Low-level typed crypto primitives (advanced use). */
export * as crypto from "./crypto";
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
