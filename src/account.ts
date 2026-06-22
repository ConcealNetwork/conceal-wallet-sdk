// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Wallet account creation + restoration. An {@link Account} is the keys + address
 * for a CCX wallet — the root object the higher-level wallet/sync layers build on.
 */
import { createAddress, mnemonic as mn, randomSeed } from "./crypto";
import { detectLanguage, mnemonicToSeed } from "./mnemonic";
import type { Hex, SeedLanguage, WalletKeys } from "./types";

export interface Account {
  /** The encoded ccx7… public address. */
  address: string;
  keys: WalletKeys;
  /** The seed phrase, present when created/restored from a mnemonic. */
  mnemonic?: string;
}

function accountFromSeed(seed: Hex, mnemonic?: string): Account {
  const created = createAddress(seed);
  return {
    address: created.public_addr,
    keys: { spend: created.spend, view: created.view },
    ...(mnemonic ? { mnemonic } : {}),
  };
}

/** Create a brand-new wallet: random seed → keys, address, and seed phrase. */
export function createAccount(language: SeedLanguage = "english"): Account {
  const seed = randomSeed();
  return accountFromSeed(seed, mn.mn_encode(seed, language));
}

/**
 * Restore a wallet from a mnemonic phrase. The language is auto-detected when not
 * given; throws if the phrase doesn't decode in any supported wordlist.
 */
export function restoreFromMnemonic(phrase: string, language?: SeedLanguage): Account {
  const trimmed = phrase.trim();
  const lang = language ?? detectLanguage(trimmed);
  if (!lang) throw new Error("Unrecognized or invalid mnemonic phrase.");
  return accountFromSeed(mnemonicToSeed(trimmed, lang), trimmed);
}

/**
 * Restore from a raw private spend key (hex). The view key is derived
 * deterministically (standard CryptoNote wallet), reproducing the same address.
 */
export function restoreFromSpendKey(spendSecHex: Hex): Account {
  return accountFromSeed(spendSecHex);
}
