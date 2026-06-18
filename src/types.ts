/** Lowercase hex string (no `0x` prefix), as used throughout conceal-lib-js. */
export type Hex = string;

/** Seed-phrase wordlists supported by conceal-lib-js `mnemonic`. */
export type SeedLanguage = "english" | "spanish" | "portuguese" | "japanese" | "electrum";

/** A CryptoNote secret/public key pair (hex). */
export interface KeyPair {
  sec: Hex;
  pub: Hex;
}

/** Full wallet keys — spend + view pairs, as produced by `crypto.create_address`. */
export interface WalletKeys {
  spend: KeyPair;
  view: KeyPair;
}

/** Public-key view of a wallet (no secrets) — what an address encodes. */
export interface PublicKeys {
  spendPublicKey: Hex;
  viewPublicKey: Hex;
}

/** Result of decoding/validating a CCX address string. */
export interface DecodedAddress extends PublicKeys {
  /** Integrated-address payment id, if the address embeds one. */
  paymentId?: Hex;
}

/** A view-only wallet: public spend key + private view key (can scan, can't spend). */
export interface ViewOnlyKeys {
  address: string;
  spendPublicKey: Hex;
  view: KeyPair;
}
