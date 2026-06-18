import { describe, expect, it } from "vitest";
import {
  createMemoryStorage,
  createNamespacedStorage,
  createWebStorage,
  type StorageAdapter,
  type WebStorageLike,
} from "../src/adapters";

describe("createMemoryStorage", () => {
  it("round-trips set/get/remove and lists keys", async () => {
    const store = createMemoryStorage();
    await store.setItem("a", "1");
    await store.setItem("b", "2");

    expect(await store.getItem("a")).toBe("1");
    expect(await store.getItem("b")).toBe("2");
    expect((await store.keys()).sort()).toEqual(["a", "b"]);

    await store.removeItem("a");
    expect(await store.getItem("a")).toBeNull();
    expect(await store.keys()).toEqual(["b"]);
  });

  it("returns null for a missing key", async () => {
    const store = createMemoryStorage();
    expect(await store.getItem("nope")).toBeNull();
  });

  it("overwrites an existing key rather than duplicating it", async () => {
    const store = createMemoryStorage();
    await store.setItem("k", "first");
    await store.setItem("k", "second");
    expect(await store.getItem("k")).toBe("second");
    expect(await store.keys()).toEqual(["k"]);
  });

  it("never throws on removing a missing key", async () => {
    const store = createMemoryStorage();
    await expect(store.removeItem("ghost")).resolves.toBeUndefined();
  });
});

describe("createNamespacedStorage", () => {
  it("isolates keys so two namespaces over one base do not collide", async () => {
    const base = createMemoryStorage();
    const walletA = createNamespacedStorage(base, "walletA");
    const walletB = createNamespacedStorage(base, "walletB");

    await walletA.setItem("seed", "aaa");
    await walletB.setItem("seed", "bbb");

    expect(await walletA.getItem("seed")).toBe("aaa");
    expect(await walletB.getItem("seed")).toBe("bbb");
  });

  it("returns un-prefixed keys scoped to the namespace", async () => {
    const base = createMemoryStorage();
    const walletA = createNamespacedStorage(base, "walletA");
    const walletB = createNamespacedStorage(base, "walletB");

    await walletA.setItem("seed", "aaa");
    await walletA.setItem("notes", "ccc");
    await walletB.setItem("seed", "bbb");

    expect((await walletA.keys()).sort()).toEqual(["notes", "seed"]);
    expect(await walletB.keys()).toEqual(["seed"]);
  });

  it("stores prefixed keys in the underlying base store", async () => {
    const base = createMemoryStorage();
    const ns = createNamespacedStorage(base, "wallet");
    await ns.setItem("seed", "xyz");
    expect(await base.getItem("wallet:seed")).toBe("xyz");
  });

  it("remove only affects the namespace, leaving other namespaces intact", async () => {
    const base = createMemoryStorage();
    const walletA = createNamespacedStorage(base, "walletA");
    const walletB = createNamespacedStorage(base, "walletB");

    await walletA.setItem("seed", "aaa");
    await walletB.setItem("seed", "bbb");
    await walletA.removeItem("seed");

    expect(await walletA.getItem("seed")).toBeNull();
    expect(await walletB.getItem("seed")).toBe("bbb");
  });

  it("does not leak keys from other prefixes that share a string boundary", async () => {
    const base = createMemoryStorage();
    const wallet = createNamespacedStorage(base, "wallet");
    const walletX = createNamespacedStorage(base, "walletX");

    await wallet.setItem("seed", "aaa");
    await walletX.setItem("seed", "bbb");

    expect(await wallet.keys()).toEqual(["seed"]);
    expect(await walletX.keys()).toEqual(["seed"]);
  });

  it("can be nested (prefix on prefix)", async () => {
    const base = createMemoryStorage();
    const outer = createNamespacedStorage(base, "app");
    const inner = createNamespacedStorage(outer, "wallet");

    await inner.setItem("seed", "deep");
    expect(await inner.getItem("seed")).toBe("deep");
    expect(await inner.keys()).toEqual(["seed"]);
    expect(await base.getItem("app:wallet:seed")).toBe("deep");
  });
});

/** Minimal synchronous Web-Storage-like stub backed by a Map. */
function fakeWebStorage(overrides: Partial<WebStorageLike> = {}): WebStorageLike {
  const map = new Map<string, string>();
  const base: WebStorageLike = {
    get length() {
      return map.size;
    },
    getItem: (key: string) => (map.has(key) ? (map.get(key) as string) : null),
    setItem: (key: string, value: string) => {
      map.set(key, value);
    },
    removeItem: (key: string) => {
      map.delete(key);
    },
    key: (index: number) => {
      const all = [...map.keys()];
      return index >= 0 && index < all.length ? (all[index] as string) : null;
    },
  };
  // Layer overrides without flattening `base`'s live `length` getter.
  return Object.create(base, Object.getOwnPropertyDescriptors(overrides)) as WebStorageLike;
}

describe("createWebStorage", () => {
  it("round-trips set/get/remove and lists keys", async () => {
    const store = createWebStorage(fakeWebStorage());
    await store.setItem("a", "1");
    await store.setItem("b", "2");

    expect(await store.getItem("a")).toBe("1");
    expect((await store.keys()).sort()).toEqual(["a", "b"]);

    await store.removeItem("a");
    expect(await store.getItem("a")).toBeNull();
    expect(await store.keys()).toEqual(["b"]);
  });

  it("returns null for a missing key", async () => {
    const store = createWebStorage(fakeWebStorage());
    expect(await store.getItem("missing")).toBeNull();
  });

  it("swallows a throwing setItem (quota / private mode) without rejecting", async () => {
    const throwing = fakeWebStorage({
      setItem: () => {
        throw new DOMException("QuotaExceededError");
      },
    });
    const store = createWebStorage(throwing);
    await expect(store.setItem("a", "1")).resolves.toBeUndefined();
    expect(await store.getItem("a")).toBeNull();
  });

  it("swallows a throwing getItem and returns null", async () => {
    const throwing = fakeWebStorage({
      getItem: () => {
        throw new Error("boom");
      },
    });
    const store = createWebStorage(throwing);
    expect(await store.getItem("a")).toBeNull();
  });

  it("swallows a throwing removeItem", async () => {
    const throwing = fakeWebStorage({
      removeItem: () => {
        throw new Error("boom");
      },
    });
    const store = createWebStorage(throwing);
    await expect(store.removeItem("a")).resolves.toBeUndefined();
  });

  it("returns an empty key list when iteration throws", async () => {
    const throwing = fakeWebStorage({
      key: () => {
        throw new Error("boom");
      },
    });
    const store = createWebStorage(throwing);
    expect(await store.keys()).toEqual([]);
  });
});

describe("StorageAdapter contract", () => {
  it("memory and web adapters satisfy the same interface", async () => {
    const adapters: StorageAdapter[] = [createMemoryStorage(), createWebStorage(fakeWebStorage())];
    for (const adapter of adapters) {
      await adapter.setItem("x", "y");
      expect(await adapter.getItem("x")).toBe("y");
      expect(await adapter.keys()).toEqual(["x"]);
      await adapter.removeItem("x");
      expect(await adapter.getItem("x")).toBeNull();
    }
  });
});
