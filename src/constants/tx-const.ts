// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Transaction fees and general spend parameters.
 */

// --- fees (atomic) ---

/** Network minimum fee (fusion + standard spends). */
export const MINIMUM_FEE_V2 = 1000;
/** Dust threshold, atomic. */
export const DUST_THRESHOLD = 10;
/**
 * Remote-node operator fee paid as an extra type-`02` destination on regular
 * spends, non-TTL messages, and deposits (0.01 CCX).
 */
export const REMOTE_NODE_FEE_ATOMIC = 10000;
/** Recipient self-output amount that marks a transaction as a message. */
export const MESSAGE_TX_AMOUNT_ATOMIC = 100;
/** Deposit-tx network fee, atomic units. */
export const DEPOSIT_TX_FEE = 1000;
/** Withdraw-tx fee, atomic units — NOT the 1000 coinFee. */
export const DEPOSIT_SMALL_WITHDRAW_FEE = 10;

// --- parameters ---

/** Wallet default mixin; the decoy ring is `mixin + 1` outs per amount. */
export const DEFAULT_MIXIN = 5;
