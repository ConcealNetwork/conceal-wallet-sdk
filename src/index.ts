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
/** Initialize the lib-js WASM — await once in the browser before any crypto use. */
export { init } from "./crypto";
export {
  createDaemonClient,
  type DaemonClient,
  type DaemonClientOptions,
  normalizeNodeUrl,
} from "./daemon";
/** Deposits / banking (type-`03`): interest, scan, locked/unlocked state. */
export * as deposits from "./deposits";
export {
  COIN_UNIT_PLACES,
  calculateDepositInterest,
  DEPOSIT_MAX_TERM_MONTH,
  DEPOSIT_MIN_AMOUNT_COIN,
  DEPOSIT_MIN_TERM_BLOCK,
  DEPOSIT_MIN_TERM_MONTH,
  DEPOSIT_RATE_V3,
  DEPOSIT_SMALL_WITHDRAW_FEE,
  DEPOSIT_TX_FEE,
  DEPOSIT_TX_VERSION,
  type DepositInterestInput,
  deriveDepositOneTimeKey,
  findWithdrawnDepositIndexes,
  M_COIN,
  type OwnedDeposit,
  type RawDepositInput,
  recomputeDepositInterest,
} from "./deposits";
export {
  type EncryptedWalletEnvelope,
  hasStoredWallet,
  normalizeWalletPassword,
  type OpenWalletOptions,
  openEncryptedWallet,
  openStoredWallet,
  type RawAddressEntry,
  type RawFullyEncryptedWallet,
  type RawInlineEncryptedWallet,
  type RawTxPrivateKeys,
  type RawWalletOptions,
  type RawWalletV1,
  saveEncryptedWallet,
  saveStoredWallet,
  WALLET_STORAGE_KEY,
} from "./envelope";
/** Wallet fusion / optimization (denomination-bucketed self-consolidation). */
export * as fusion from "./fusion";
export {
  type BuildFusionTransactionInput,
  buildFusionTransaction,
  CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE,
  DEFAULT_MIXIN,
  DUST_THRESHOLD,
  FUSION_TX_MAX_INPUT_COUNT,
  FUSION_TX_MAX_SIZE,
  FUSION_TX_MIN_IN_OUT_COUNT_RATIO,
  FUSION_TX_MIN_INPUT_COUNT,
  type FusionAmountApplicability,
  type FusionInputSelection,
  type FusionShuffle,
  type FusionStatus,
  type FusionStatusInput,
  getApproximateMaximumInputCount,
  getApproximateTransactionSize,
  isAmountApplicableInFusionInput,
  isOptimizationNeeded,
  MAX_FUSION_OUTPUTS,
  MINIMUM_FEE_V2,
  NUM_BUCKETS,
  OPTIMIZE_OUTPUTS,
  OPTIMIZE_THRESHOLD,
  PRETTY_AMOUNTS,
  selectFusionInputs,
  UPGRADE_HEIGHT_V4,
} from "./fusion";
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
export type {
  BuildDepositTransactionInput,
  BuildMessageTransactionInput,
  BuildWithdrawTransactionInput,
  OwnedOutput,
  RawTransaction,
  ScannedMessage,
  ScannedOutputs,
} from "./transactions";
/** Transaction scanning + (testnet-pending) spend building + message/TTL framing. */
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
  applyScannedDeposits,
  applyScannedTransaction,
  type Balance,
  createWalletState,
  deserializeWalletState,
  getBalance,
  getLockedDeposits,
  getTransactions,
  getUnlockedDeposits,
  getUnspentOutputs,
  serializeWalletState,
  WALLET_STATE_VERSION,
  type WalletState,
  type WalletTransaction,
} from "./wallet";
