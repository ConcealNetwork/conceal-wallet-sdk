// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

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
/** Chain / consensus scalars — single source of truth. */
export * from "./constants";
export * as constants from "./constants";
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
  calculateDepositInterest,
  type DepositInterestInput,
  deriveDepositOneTimeKey,
  findWithdrawnDepositIndexes,
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
  type FusionAmountApplicability,
  type FusionInputSelection,
  type FusionShuffle,
  type FusionStatus,
  type FusionStatusInput,
  getApproximateMaximumInputCount,
  getApproximateTransactionSize,
  isAmountApplicableInFusionInput,
  isOptimizationNeeded,
  selectFusionInputs,
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
  createOutboundQueue,
  type EnqueueOptions,
  OUTBOUND_QUEUE_NAMESPACE,
  type OutboundQueue,
  type OutboundQueueEntry,
  type OutboundQueueFailReason,
  type OutboundQueueOptions,
  type OutboundQueueResult,
  type OutboundQueueState,
} from "./outbound-queue";
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
  type ApplyScannedTransactionContext,
  type Balance,
  createWalletState,
  deserializeWalletState,
  getBalance,
  getDustAmount,
  getLockedDeposits,
  getTransactions,
  getUnlockedDeposits,
  getUnspentOutputs,
  serializeWalletState,
  WALLET_STATE_VERSION,
  type WalletState,
  type WalletTransaction,
} from "./wallet";
export {
  classifyTransactionKind,
  extractTxKindHints,
  isCoinbaseRawTransaction,
  isDustOutput,
  isFusionShape,
  resolveWalletTransactionKind,
  type ClassifyTransactionKindInput,
  type TxKindHints,
  type WalletTransactionKind,
} from "./transaction-kind";
