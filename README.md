# conceal-wallet-sdk

Framework-agnostic, fully-typed **TypeScript wallet engine for Conceal (CCX)**, built on the [`conceal-lib-js`](https://github.com/ConcealNetwork/conceal-lib-js) cryptographic primitives.

It's the missing middle layer: the wallet *logic* (accounts, addresses, mnemonics, encrypted messages, transactions, sync) that today is re-ported into every Conceal app. One implementation, fix-once, consumed by the web / mobile / lite wallets.

```
conceal-lib-js     (Rust → WASM crypto primitives)   ← dependency
        ↓
conceal-wallet-sdk (typed TS wallet engine)          ← this package
        ↓
apps: next-wallet · mobile · lite                    ← UI only
```

> **Status: alpha (0.1.x).** Implemented + tested (140 tests): accounts, mnemonics, addresses + payment URIs, encrypted messages + smart-message protocol, daemon RPC client, output **scanning**, wallet state, **sync**, and **broadcast-ready spend transactions** (input selection, decoys, ring signatures, key images, and byte-exact serialization via conceal-lib-js v0.2.6's mainnet-proven serializer). APIs may change pre-1.0; end-to-end broadcast against a live daemon is still recommended before production use.

## Install

```bash
npm install conceal-wallet-sdk
```

Runs in Node 20+, modern browsers, and any bundler (Vite/webpack/Next). lib-js is imported as a normal module — **no `window` globals**.

## Quick start

```ts
import { createAccount, restoreFromMnemonic, isValidMnemonic } from "conceal-wallet-sdk";

// Create a new wallet
const account = createAccount();
console.log(account.address);   // ccx7…
console.log(account.mnemonic);  // 25-word seed phrase

// Restore from a seed phrase (language auto-detected)
const restored = restoreFromMnemonic(account.mnemonic!);

// Validate
isValidMnemonic("…", "spanish"); // boolean
```

## Design

- **Typed** — proper types over lib-js's primitive surface; no `any` leaking to consumers.
- **Environment-agnostic** — entropy via Web Crypto (`globalThis.crypto`), pluggable storage/network adapters (no hard DOM/Node assumptions).
- **Dual ESM + CJS** with `.d.ts`.

## Development

```bash
npm install
npm run types   # tsc --noEmit
npm run check   # biome lint + format
npm test        # vitest
npm run build   # tsup → dist (esm + cjs + dts)
```

## License

MIT
