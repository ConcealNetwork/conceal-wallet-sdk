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

  it("throws on a public http URL without allowInsecure", () => {
    expect(() => normalizeNodeUrl("http://node.conceal.network/")).toThrow(/https/);
  });

  it("allows http for a public host when allowInsecure is set", () => {
    expect(normalizeNodeUrl("http://ccxapi.conceal.network:16000", { allowInsecure: true })).toBe(
      "http://ccxapi.conceal.network:16000/",
    );
  });

  it("allows http for loopback / private / CGNAT hosts without opt-in", () => {
    expect(normalizeNodeUrl("http://127.0.0.1:16000")).toBe("http://127.0.0.1:16000/");
    expect(normalizeNodeUrl("http://127.0.0.2:16000")).toBe("http://127.0.0.2:16000/"); // 127/8
    expect(normalizeNodeUrl("http://localhost:16800")).toBe("http://localhost:16800/");
    expect(normalizeNodeUrl("http://localhost.:16800")).toBe("http://localhost.:16800/"); // trailing dot
    expect(normalizeNodeUrl("http://192.168.1.50:16000")).toBe("http://192.168.1.50:16000/");
    expect(normalizeNodeUrl("http://10.0.0.5:16000")).toBe("http://10.0.0.5:16000/");
    expect(normalizeNodeUrl("http://100.100.90.103:16800")).toBe("http://100.100.90.103:16800/");
    expect(normalizeNodeUrl("http://[::1]:16000")).toBe("http://[::1]:16000/"); // IPv6 loopback
  });

  it("does NOT treat a public DNS name with a private-looking prefix as private", () => {
    // Regression: unanchored prefix regexes used to allow these over plaintext http.
    for (const url of [
      "http://10.evil.com",
      "http://10.0.0.5.evil.com",
      "http://192.168.1.attacker.com",
      "http://172.16.pwned.net",
      "http://100.64.foo.example",
      "http://999.0.0.1", // not a valid IPv4 (octet > 255) → not private
    ]) {
      // Rejected outright (not silently downgraded to plaintext http).
      expect(() => normalizeNodeUrl(url)).toThrow();
      // And explicitly NOT classified as a local/private host.
      expect(() => normalizeNodeUrl(url, { allowInsecure: false })).toThrow();
    }
  });

  it("throws on a non-http(s) scheme", () => {
    expect(() => normalizeNodeUrl("ftp://node.conceal.network/")).toThrow();
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

describe("getInfo", () => {
  it("maps the getinfo telemetry fields", async () => {
    const fetchMock = jsonFetch({
      status: "OK",
      height: 2097670,
      difficulty: 123456789,
      transactions_pool_size: 7,
      incoming_connections_count: 4,
      outgoing_connections_count: 8,
      white_peerlist_size: 250,
      grey_peerlist_size: 1500,
      alt_blocks_count: 113,
      start_time: 1700000000,
      version: "6.7.4",
    });
    const client = createDaemonClient({ nodeUrl: NODE, fetch: fetchMock });
    const info = await client.getInfo();
    expect(info).toEqual({
      height: 2097670,
      difficulty: 123456789,
      txPoolSize: 7,
      incomingConnections: 4,
      outgoingConnections: 8,
      whitePeerlistSize: 250,
      greyPeerlistSize: 1500,
      altBlocksCount: 113,
      startTime: 1700000000,
      version: "6.7.4",
      status: "OK",
    });
  });

  it("defaults missing numeric fields to 0", async () => {
    const client = createDaemonClient({ nodeUrl: NODE, fetch: jsonFetch({ status: "OK" }) });
    const info = await client.getInfo();
    expect(info).toEqual({
      height: 0,
      difficulty: 0,
      txPoolSize: 0,
      incomingConnections: 0,
      outgoingConnections: 0,
      whitePeerlistSize: 0,
      greyPeerlistSize: 0,
      altBlocksCount: 0,
      startTime: 0,
      version: "",
      status: "OK",
    });
  });

  it("throws on a non-OK getinfo status", async () => {
    const client = createDaemonClient({ nodeUrl: NODE, fetch: jsonFetch({ status: "BUSY" }) });
    await expect(client.getInfo()).rejects.toThrow(/getinfo/i);
  });
});
