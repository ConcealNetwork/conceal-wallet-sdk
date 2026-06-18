import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createDaemonClient, DEFAULT_TIMEOUT_MS, normalizeNodeUrl } from "../src/daemon";

/** Build a `fetch`-compatible mock returning a JSON `Response`. */
function jsonFetch(payload: unknown, status = 200): typeof fetch {
  return vi.fn(
    async () =>
      new Response(JSON.stringify(payload), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
  ) as unknown as typeof fetch;
}

const NODE = "https://node.conceal.network/";

describe("normalizeNodeUrl", () => {
  it("appends a trailing slash when missing", () => {
    expect(normalizeNodeUrl("https://node.conceal.network")).toBe("https://node.conceal.network/");
  });

  it("leaves an already-normalized URL untouched", () => {
    expect(normalizeNodeUrl(NODE)).toBe(NODE);
  });

  it("trims surrounding whitespace", () => {
    expect(normalizeNodeUrl("  https://node.conceal.network/  ")).toBe(NODE);
  });

  it("throws on a non-https URL", () => {
    expect(() => normalizeNodeUrl("http://node.conceal.network/")).toThrow(/https/);
  });

  it("throws on an empty URL", () => {
    expect(() => normalizeNodeUrl("   ")).toThrow();
  });
});

describe("createDaemonClient", () => {
  it("normalizes the nodeUrl (trailing slash) and exposes it", () => {
    const client = createDaemonClient({
      nodeUrl: "https://node.conceal.network",
      fetch: jsonFetch({ status: "OK", height: 1 }),
    });
    expect(client.nodeUrl).toBe(NODE);
  });

  it("throws when constructed with a non-https URL", () => {
    expect(() =>
      createDaemonClient({ nodeUrl: "http://node.conceal.network/", fetch: jsonFetch({}) }),
    ).toThrow(/https/);
  });
});

describe("getHeight", () => {
  it("parses the height from an OK response", async () => {
    const fetchMock = jsonFetch({ status: "OK", height: "123456" });
    const client = createDaemonClient({ nodeUrl: NODE, fetch: fetchMock });

    await expect(client.getHeight()).resolves.toBe(123456);
    expect(fetchMock).toHaveBeenCalledWith(
      `${NODE}getheight`,
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("rejects on a non-OK status", async () => {
    const client = createDaemonClient({ nodeUrl: NODE, fetch: jsonFetch({ status: "BUSY" }) });
    await expect(client.getHeight()).rejects.toThrow(/non-OK/i);
  });

  it("rejects on an HTTP error response", async () => {
    const client = createDaemonClient({
      nodeUrl: NODE,
      fetch: jsonFetch({ status: "OK", height: 1 }, 500),
    });
    await expect(client.getHeight()).rejects.toThrow(/HTTP 500/);
  });

  it("rejects when the height is missing/invalid", async () => {
    const client = createDaemonClient({
      nodeUrl: NODE,
      fetch: jsonFetch({ status: "OK", height: "not-a-number" }),
    });
    await expect(client.getHeight()).rejects.toThrow(/invalid height/i);
  });

  it("rejects when the response is not a JSON object", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response("[1,2,3]", { status: 200, headers: { "Content-Type": "application/json" } }),
    ) as unknown as typeof fetch;
    const client = createDaemonClient({ nodeUrl: NODE, fetch: fetchMock });
    await expect(client.getHeight()).rejects.toThrow(/not a JSON object/i);
  });
});

describe("getNodeFeeAddress", () => {
  it("returns the fee address from an OK response", async () => {
    const client = createDaemonClient({
      nodeUrl: NODE,
      fetch: jsonFetch({ status: "OK", fee_address: "ccx7feeaddress" }),
    });
    await expect(client.getNodeFeeAddress()).resolves.toBe("ccx7feeaddress");
  });

  it("returns an empty string when the node charges no fee", async () => {
    const client = createDaemonClient({ nodeUrl: NODE, fetch: jsonFetch({ status: "OK" }) });
    await expect(client.getNodeFeeAddress()).resolves.toBe("");
  });
});

describe("sendRawTransaction", () => {
  it("posts to sendrawtransaction with the tx hex and do_not_relay=false", async () => {
    const fetchMock = jsonFetch({ status: "OK" });
    const client = createDaemonClient({ nodeUrl: NODE, fetch: fetchMock });

    await expect(client.sendRawTransaction("deadbeef")).resolves.toEqual({ status: "OK" });

    const calls = (fetchMock as unknown as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls).toHaveLength(1);
    const [url, init] = calls[0] as [string, RequestInit];
    expect(url).toBe(`${NODE}sendrawtransaction`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      tx_as_hex: "deadbeef",
      do_not_relay: false,
    });
  });

  it("rejects with the daemon reason on a non-OK status", async () => {
    const client = createDaemonClient({
      nodeUrl: NODE,
      fetch: jsonFetch({ status: "Failed", reason: "double spend" }),
    });
    await expect(client.sendRawTransaction("deadbeef")).rejects.toThrow(/Failed.*double spend/);
  });

  it("rejects on an empty tx hex without calling fetch", async () => {
    const fetchMock = jsonFetch({ status: "OK" });
    const client = createDaemonClient({ nodeUrl: NODE, fetch: fetchMock });
    await expect(client.sendRawTransaction("")).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("getRandomOuts", () => {
  it("posts to getrandom_outs with amounts + outs_count and maps the response", async () => {
    const fetchMock = jsonFetch({
      status: "OK",
      outs: [
        {
          amount: 100,
          outs: [{ global_index: 7, public_key: "aa" }],
        },
      ],
    });
    const client = createDaemonClient({ nodeUrl: NODE, fetch: fetchMock });

    const result = await client.getRandomOuts([100], 3);
    expect(result).toEqual([{ amount: 100, outs: [{ globalIndex: 7, publicKey: "aa" }] }]);

    const calls = (fetchMock as unknown as ReturnType<typeof vi.fn>).mock.calls;
    const [url, init] = calls[0] as [string, RequestInit];
    expect(url).toBe(`${NODE}getrandom_outs`);
    expect(JSON.parse(init.body as string)).toEqual({ amounts: [100], outs_count: 3 });
  });

  it("rejects when the outs array is missing", async () => {
    const client = createDaemonClient({ nodeUrl: NODE, fetch: jsonFetch({ status: "OK" }) });
    await expect(client.getRandomOuts([100], 3)).rejects.toThrow(/missing the outs array/i);
  });
});

describe("getWalletSyncData", () => {
  it("posts the inclusive height range and maps transactions", async () => {
    const fetchMock = jsonFetch({
      status: "OK",
      transactions: [
        {
          transaction: { version: 1 },
          timestamp: 1700000000,
          output_indexes: [10, 11],
          height: 5000,
          block_hash: "bbbb",
          hash: "cccc",
          fee: 1000,
        },
        // Empty slot — should be skipped, not fabricated.
        { transaction: null, height: 5001 },
      ],
    });
    const client = createDaemonClient({ nodeUrl: NODE, fetch: fetchMock });

    const result = await client.getWalletSyncData(5000, 5001);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({
      transaction: { version: 1 },
      timestamp: 1700000000,
      outputIndexes: [10, 11],
      height: 5000,
      blockHash: "bbbb",
      hash: "cccc",
      fee: 1000,
    });

    const calls = (fetchMock as unknown as ReturnType<typeof vi.fn>).mock.calls;
    const [url, init] = calls[0] as [string, RequestInit];
    expect(url).toBe(`${NODE}get_raw_transactions_by_heights`);
    expect(JSON.parse(init.body as string)).toEqual({
      heights: [5000, 5001],
      include_miner_txs: true,
      range: true,
    });
  });

  it("normalizes a startBlock of 0 to 1 (genesis guard)", async () => {
    const fetchMock = jsonFetch({ status: "OK", transactions: [] });
    const client = createDaemonClient({ nodeUrl: NODE, fetch: fetchMock });

    await client.getWalletSyncData(0, 10);
    const calls = (fetchMock as unknown as ReturnType<typeof vi.fn>).mock.calls;
    const [, init] = calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string).heights).toEqual([1, 10]);
  });

  it("rejects when endBlock < startBlock", async () => {
    const client = createDaemonClient({ nodeUrl: NODE, fetch: jsonFetch({ status: "OK" }) });
    await expect(client.getWalletSyncData(10, 5)).rejects.toThrow(/endBlock/);
  });
});

describe("timeouts", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("rejects with a clear error when the request exceeds timeoutMs", async () => {
    // A fetch that never resolves on its own, but honors the abort signal.
    const hangingFetch = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal;
          if (signal) {
            signal.addEventListener("abort", () => {
              reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
            });
          }
        }),
    ) as unknown as typeof fetch;

    const client = createDaemonClient({ nodeUrl: NODE, fetch: hangingFetch, timeoutMs: 50 });

    const promise = client.getHeight();
    const assertion = expect(promise).rejects.toThrow(/timed out after 50ms/);
    await vi.advanceTimersByTimeAsync(60);
    await assertion;
  });

  it("falls back to the default timeout when none is provided", () => {
    expect(DEFAULT_TIMEOUT_MS).toBe(10_000);
  });
});
