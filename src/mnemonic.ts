// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Seed-phrase helpers — a typed facade over conceal-lib-js `mnemonic`
 * (env-agnostic entropy via the SDK's `randomSeed`, not lib-js's browser-only
 * `mn_random`).
 */
import { mnemonic as mn, randomSeed } from "./crypto";
import type { Hex, SeedLanguage } from "./types";

export const SEED_LANGUAGES: readonly SeedLanguage[] = [
  "english",
  "spanish",
  "portuguese",
  "japanese",
  "electrum",
];

/** Generate a fresh random mnemonic phrase in the given language. */
export function generateMnemonic(language: SeedLanguage = "english"): string {
  return mn.mn_encode(randomSeed(), language);
}

/** Decode a phrase back to its 32-byte hex spend seed. Throws on a bad phrase. */
export function mnemonicToSeed(phrase: string, language: SeedLanguage = "english"): Hex {
  return mn.mn_decode(phrase.trim(), language) as Hex;
}

/** True if the phrase decodes in the given language (or any supported one). */
export function isValidMnemonic(phrase: string, language?: SeedLanguage): boolean {
  const candidates = language ? [language] : SEED_LANGUAGES;
  for (const lang of candidates) {
    try {
      mn.mn_decode(phrase.trim(), lang);
      return true;
    } catch {
      // try the next language
    }
  }
  return false;
}

/** Detect which supported wordlist a phrase belongs to, or null. */
export function detectLanguage(phrase: string): SeedLanguage | null {
  for (const lang of SEED_LANGUAGES) {
    try {
      mn.mn_decode(phrase.trim(), lang);
      return lang;
    } catch {
      // try the next language
    }
  }
  return null;
}
