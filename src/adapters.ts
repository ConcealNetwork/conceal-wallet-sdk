// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Pluggable persistence boundary for the wallet/sync layers.
 *
 * The SDK is environment-agnostic: it must run in Node, browsers, React Native,
 * web workers, and tests without assuming IndexedDB, `localStorage`, DOM, or
 * AsyncStorage exist. Higher layers depend on the {@link StorageAdapter}
 * interface here and are handed a concrete implementation by the host app, so
 * the engine never reaches for a global storage API itself.
 */

/**
 * Async key/value persistence the wallet layer builds on. Implementations may
 * be backed by anything (memory, `localStorage`, IndexedDB, AsyncStorage, a
 * file, a remote KV store) so long as they honor these semantics.
 */
export interface StorageAdapter {
  /** Resolve the stored value for `key`, or `null` when it is absent. */
  getItem(key: string): Promise<string | null>;
  /** Store `value` under `key`, replacing any existing value. */
  setItem(key: string, value: string): Promise<void>;
  /** Remove `key`; a no-op when the key does not exist. */
  removeItem(key: string): Promise<void>;
  /** List every key currently held (order is not guaranteed). */
  keys(): Promise<string[]>;
}

/**
 * In-memory {@link StorageAdapter} backed by a `Map`. Ideal for Node, tests,
 * and ephemeral wallets. Holds its own private state, never throws, and does
 * not mutate any argument it is given.
 */
export function createMemoryStorage(): StorageAdapter {
  const store = new Map<string, string>();
  return {
    getItem: (key) => Promise.resolve(store.has(key) ? (store.get(key) as string) : null),
    setItem: (key, value) => {
      store.set(key, value);
      return Promise.resolve();
    },
    removeItem: (key) => {
      store.delete(key);
      return Promise.resolve();
    },
    keys: () => Promise.resolve([...store.keys()]),
  };
}

const NAMESPACE_SEPARATOR = ":";

/**
 * Wrap an adapter so every key is transparently prefixed with `prefix`, letting
 * multiple wallets or features share one underlying store without collisions.
 * Reads/writes/removes operate only within the namespace, and {@link
 * StorageAdapter.keys} returns the *un-prefixed* keys belonging to it.
 */
export function createNamespacedStorage(base: StorageAdapter, prefix: string): StorageAdapter {
  const fullPrefix = `${prefix}${NAMESPACE_SEPARATOR}`;
  const toBaseKey = (key: string): string => `${fullPrefix}${key}`;
  return {
    getItem: (key) => base.getItem(toBaseKey(key)),
    setItem: (key, value) => base.setItem(toBaseKey(key), value),
    removeItem: (key) => base.removeItem(toBaseKey(key)),
    keys: async () => {
      const all = await base.keys();
      return all
        .filter((key) => key.startsWith(fullPrefix))
        .map((key) => key.slice(fullPrefix.length));
    },
  };
}

/**
 * The subset of the DOM `Storage` interface this SDK relies on. Accepting it as
 * a parameter (rather than reaching for `localStorage`/`window`) keeps the
 * module environment-agnostic — callers pass `globalThis.localStorage`,
 * `sessionStorage`, or any compatible shim.
 */
export interface WebStorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key(index: number): string | null;
  readonly length: number;
}

/**
 * Adapt a synchronous Web-Storage-like object (e.g. `localStorage`) to the async
 * {@link StorageAdapter} interface. Every call is guarded so it never throws on
 * quota errors, private-browsing restrictions, or a hostile shim: writes/removes
 * silently no-op on failure, reads fall back to `null`, and `keys()` to `[]`.
 */
export function createWebStorage(storage: WebStorageLike): StorageAdapter {
  return {
    getItem: (key) => {
      try {
        return Promise.resolve(storage.getItem(key));
      } catch {
        return Promise.resolve(null);
      }
    },
    setItem: (key, value) => {
      try {
        storage.setItem(key, value);
      } catch {
        // Ignore quota/private-mode failures — persistence is best-effort here.
      }
      return Promise.resolve();
    },
    removeItem: (key) => {
      try {
        storage.removeItem(key);
      } catch {
        // Ignore — removing a key that cannot be removed is harmless.
      }
      return Promise.resolve();
    },
    keys: () => {
      try {
        const result: string[] = [];
        for (let i = 0; i < storage.length; i++) {
          const key = storage.key(i);
          if (key !== null) result.push(key);
        }
        return Promise.resolve(result);
      } catch {
        return Promise.resolve([]);
      }
    },
  };
}
