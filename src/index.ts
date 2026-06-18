/**
 * conceal-wallet-sdk — framework-agnostic, typed TypeScript wallet engine for
 * Conceal (CCX), built on the conceal-lib-js cryptographic primitives.
 */

export { type Account, createAccount, restoreFromMnemonic, restoreFromSpendKey } from "./account";
export {
  createMemoryStorage,
  createNamespacedStorage,
  createWebStorage,
  type StorageAdapter,
  type WebStorageLike,
} from "./adapters";
export {
  buildPaymentUri,
  decodeAddress,
  encodeAddress,
  encodeIntegratedAddress,
  isValidAddress,
  makeIntegratedAddress,
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
export {
  analyzeKeysShape,
  type KeysShape,
  normalizeUserKeys,
  type UserKeys,
  userKeysFromEncryptedKeysString,
  userKeysFromPriv,
} from "./keys";
/** Encrypted messages + the smart-message protocol. */
export * as messages from "./messages";
export {
  detectLanguage,
  generateMnemonic,
  isValidMnemonic,
  mnemonicToSeed,
  SEED_LANGUAGES,
} from "./mnemonic";
export {
  createWalletSync,
  DEFAULT_BATCH_SIZE,
  DEFAULT_STORAGE_KEY,
  type SyncOptions,
  type WalletSync,
} from "./sync";
export type { OwnedOutput, RawTransaction } from "./transactions";
/** Transaction scanning + (testnet-pending) spend building. */
export * as transactions from "./transactions";
export type {
  DecodedAddress,
  Hex,
  KeyPair,
  PublicKeys,
  SeedLanguage,
  ViewOnlyKeys,
  WalletKeys,
} from "./types";
export {
  applyScannedTransaction,
  type Balance,
  createWalletState,
  deserializeWalletState,
  getBalance,
  getTransactions,
  getUnspentOutputs,
  serializeWalletState,
  WALLET_STATE_VERSION,
  type WalletState,
  type WalletTransaction,
} from "./wallet";
