// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/**
 * Typed HTTP client for the Conceal daemon proxy.
 *
 * Talks to the same endpoints the legacy `conceal-web-wallet` daemon explorer
 * uses (`getheight`, `feeaddress`, `sendrawtransaction`, `getrandom_outs`,
 * `get_raw_transactions_by_heights`), but modernized: pluggable `fetch`, no DOM
 * or Node globals assumed, per-request timeout via `AbortController`, and every
 * response shape validated before it is trusted.
 */

import type { Hex } from "./types";

/** Options for {@link createDaemonClient}. */
export interface DaemonClientOptions {
  /**
   * Daemon proxy base URL. `https://` is always accepted; `http://` is accepted
   * for loopback/private hosts (localhost, 127.0.0.0/8, 10/8, 192.168/16,
   * 172.16/12, 100.64/10, `[::1]`) or for any host when {@link allowInsecure} is
   * set. A trailing slash is enforced.
   *
   * Security: if your application lets end users supply an arbitrary `nodeUrl`,
   * validate it yourself — the loopback/private http auto-allow means a
   * user-supplied `http://127.0.0.1:6379`-style URL could be used to probe
   * internal services (SSRF), and any allowed http sends traffic in plaintext.
   */
  nodeUrl: string;
  /** `fetch` implementation to use. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Per-request timeout in milliseconds. Defaults to {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number;
  /**
   * Permit a plain-`http://` node URL for any host (e.g. a public self-hosted
   * node on `:16000`). Off by default — https is required for non-local hosts.
   */
  allowInsecure?: boolean;
}

/** A single decoy output returned by `getrandom_outs`. */
export interface DaemonRandomOut {
  globalIndex: number;
  publicKey: Hex;
}

/** Decoy outputs for one amount, as returned by `getrandom_outs`. */
export interface DaemonRandomOutsForAmount {
  amount: number;
  outs: DaemonRandomOut[];
}

/** A raw transaction within a block, as returned by `get_raw_transactions_by_heights`. */
export interface DaemonRawTransaction {
  /** Raw daemon transaction object (kept opaque; the engine decodes it). */
  transaction: unknown;
  timestamp: number;
  outputIndexes: number[];
  height: number;
  blockHash: Hex;
  hash: Hex;
  fee: number;
}

/** Result of {@link DaemonClient.sendRawTransaction}. */
export interface SendRawTransactionResult {
  status: string;
}

/**
 * Node telemetry from the daemon `getinfo` endpoint — numeric/string fields the
 * wallet surfaces (difficulty, peers, mempool, version, last-block time). Fields
 * default to `0`/`""` when a node omits them.
 */
export interface DaemonInfo {
  height: number;
  difficulty: number;
  /** Pending tx count in the mempool (`transactions_pool_size`). */
  txPoolSize: number;
  incomingConnections: number;
  outgoingConnections: number;
  whitePeerlistSize: number;
  greyPeerlistSize: number;
  altBlocksCount: number;
  /** Daemon start time (unix seconds); used for "last block N ago". */
  startTime: number;
  version: string;
  status: string;
}

/** The typed Conceal daemon client. */
export interface DaemonClient {
  /** Normalized base URL (always `https://…/`). */
  readonly nodeUrl: string;
  /** Current network height. */
  getHeight(): Promise<number>;
  /** Node telemetry (`getinfo`): difficulty, peers, mempool, version, etc. */
  getInfo(): Promise<DaemonInfo>;
  /** Node fee address (`""` when the node charges no fee). */
  getNodeFeeAddress(): Promise<string>;
  /** Submit a raw, hex-encoded transaction for relay. */
  sendRawTransaction(txHex: Hex): Promise<SendRawTransactionResult>;
  /** Fetch `count` random decoy outputs for each requested amount. */
  getRandomOuts(amounts: number[], count: number): Promise<DaemonRandomOutsForAmount[]>;
  /**
   * Fetch raw transactions for the HALF-OPEN block range `[startBlock, endBlock)` — the daemon
   * EXCLUDES the upper bound `endBlock` (e.g. `(100, 101)` returns only block 100; `(200, 300)`
   * returns 200..299). To cover an INCLUSIVE range `[a, b]`, pass `endBlock = b + 1`.
   */
  getWalletSyncData(
    startBlock: number,
    endBlock: number,
    includeMinerTxs?: boolean,
  ): Promise<DaemonRawTransaction[]>;
  /**
   * Fetch the daemon's current mempool (unconfirmed) transactions in the same
   * full `DaemonRawTransaction` shape as {@link getWalletSyncData} — i.e. each
   * carries the raw `transaction` (vout/extra) so the engine can scan it for
   * owned outputs. Lets a wallet surface INCOMING pending funds before they mine.
   * `height`/`blockHash` are zeroed for pool entries (not yet in a block).
   */
  getTransactionsPool(): Promise<DaemonRawTransaction[]>;
}

/** Default per-request timeout (matches the legacy `NodeWorker.timeout`). */
export const DEFAULT_TIMEOUT_MS = 10_000;

const JSON_HEADERS: Readonly<Record<string, string>> = { "Content-Type": "application/json" };

/**
 * True for loopback / RFC1918-private / CGNAT (Tailscale) hosts, where plain
 * http is acceptable. IP ranges are matched ONLY against a syntactically valid
 * IPv4 dotted-quad (or bracketed IPv6 loopback) — never a prefix of an
 * arbitrary hostname, so a public DNS name like `10.evil.com` or
 * `192.168.x.attacker.com` is NOT treated as private.
 */
function isLocalOrPrivateHost(host: string): boolean {
  let h = host.toLowerCase();
  // Strip a single FQDN trailing dot (`localhost.`, `127.0.0.1.`).
  if (h.endsWith(".")) h = h.slice(0, -1);
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  // IPv6 loopback — `URL.hostname` keeps the brackets (`[::1]`).
  if (h === "::1" || h === "[::1]") return true;
  // IPv4: classify only a true 4-octet address (each octet 0–255).
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m || m.slice(1).some((octet) => Number(octet) > 255)) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  return false;
}

/**
 * Normalize a daemon proxy URL and enforce a trailing slash. `https://` is
 * always accepted. `http://` is accepted only for loopback/private hosts, or
 * for any host when `allowInsecure` is set. Throws on empty / disallowed URLs.
 */
export function normalizeNodeUrl(url: string, opts: { allowInsecure?: boolean } = {}): string {
  const trimmed = url.trim();
  if (!trimmed) {
    throw new Error("Node URL is required.");
  }
  const ensureSlash = (u: string) => (u.endsWith("/") ? u : `${u}/`);
  if (/^https:\/\//i.test(trimmed)) {
    return ensureSlash(trimmed);
  }
  if (/^http:\/\//i.test(trimmed)) {
    let host: string;
    try {
      host = new URL(trimmed).hostname;
    } catch {
      throw new Error("Node URL is not a valid URL.");
    }
    if (opts.allowInsecure || isLocalOrPrivateHost(host)) {
      return ensureSlash(trimmed);
    }
    throw new Error(
      "Node URL must start with https:// for a public host (set allowInsecure to permit http).",
    );
  }
  throw new Error("Node URL must start with https:// or http://");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A daemon response is considered OK only when `status === "OK"`. */
function assertStatusOk(body: Record<string, unknown>, context: string): void {
  if (body.status !== "OK") {
    const status = typeof body.status === "string" ? body.status : "unknown";
    throw new Error(`Daemon ${context} returned a non-OK status (${status}).`);
  }
}

/**
 * Map one raw daemon transaction entry (the shared shape returned by both
 * `get_raw_transactions_by_heights` and `getrawtransactionspool`) into a
 * {@link DaemonRawTransaction}. Pool entries simply carry height 0 + a zero block hash.
 */
function mapRawTransaction(rawTx: Record<string, unknown>): DaemonRawTransaction {
  const outputIndexes = Array.isArray(rawTx.output_indexes)
    ? rawTx.output_indexes.map((value) => Number(value))
    : [];
  return {
    transaction: rawTx.transaction,
    timestamp: Number(rawTx.timestamp) || 0,
    outputIndexes,
    height: Number(rawTx.height) || 0,
    blockHash: typeof rawTx.block_hash === "string" ? rawTx.block_hash : "",
    hash: typeof rawTx.hash === "string" ? rawTx.hash : "",
    fee: Number(rawTx.fee) || 0,
  };
}

export function createDaemonClient(opts: DaemonClientOptions): DaemonClient {
  const base = normalizeNodeUrl(opts.nodeUrl, { allowInsecure: opts.allowInsecure });
  const fetchImpl = opts.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("No fetch implementation available; pass `fetch` in options.");
  }
  const timeoutMs =
    typeof opts.timeoutMs === "number" && opts.timeoutMs > 0 ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;

  /** Issue one request, parse JSON, and surface friendly errors on failure/timeout. */
  async function request(
    path: string,
    method: "GET" | "POST",
    body?: unknown,
  ): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await fetchImpl(`${base}${path}`, {
        method,
        headers: JSON_HEADERS,
        body: method === "POST" ? JSON.stringify(body ?? {}) : undefined,
        signal: controller.signal,
      });
    } catch (error: unknown) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Daemon request to "${path}" timed out after ${timeoutMs}ms.`);
      }
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`Daemon request to "${path}" failed: ${reason}`);
    } finally {
      clearTimeout(timeoutId);
    }

    if (!response.ok) {
      throw new Error(`Daemon request to "${path}" returned HTTP ${response.status}.`);
    }

    let parsed: unknown;
    try {
      parsed = await response.json();
    } catch {
      throw new Error(`Daemon response for "${path}" was not valid JSON.`);
    }

    if (!isRecord(parsed)) {
      throw new Error(`Daemon response for "${path}" was not a JSON object.`);
    }
    return parsed;
  }

  async function getHeight(): Promise<number> {
    const body = await request("getheight", "GET");
    assertStatusOk(body, "getheight");
    const height = Number.parseInt(String(body.height), 10);
    if (!Number.isFinite(height) || height < 0) {
      throw new Error("Daemon getheight returned an invalid height.");
    }
    return height;
  }

  async function getInfo(): Promise<DaemonInfo> {
    const body = await request("getinfo", "GET");
    assertStatusOk(body, "getinfo");
    const num = (value: unknown): number => {
      const n = Number(value);
      return Number.isFinite(n) ? n : 0;
    };
    return {
      height: num(body.height),
      difficulty: num(body.difficulty),
      txPoolSize: num(body.transactions_pool_size),
      incomingConnections: num(body.incoming_connections_count),
      outgoingConnections: num(body.outgoing_connections_count),
      whitePeerlistSize: num(body.white_peerlist_size),
      greyPeerlistSize: num(body.grey_peerlist_size),
      altBlocksCount: num(body.alt_blocks_count),
      startTime: num(body.start_time),
      version: typeof body.version === "string" ? body.version : "",
      status: typeof body.status === "string" ? body.status : "",
    };
  }

  async function getNodeFeeAddress(): Promise<string> {
    const body = await request("feeaddress", "GET");
    assertStatusOk(body, "feeaddress");
    const feeAddress = body.fee_address;
    // A node with no fee may omit the field or return an empty string.
    if (feeAddress === undefined || feeAddress === null) {
      return "";
    }
    if (typeof feeAddress !== "string") {
      throw new Error("Daemon feeaddress returned a non-string fee address.");
    }
    return feeAddress;
  }

  async function sendRawTransaction(txHex: Hex): Promise<SendRawTransactionResult> {
    if (typeof txHex !== "string" || txHex.length === 0) {
      throw new Error("A non-empty transaction hex string is required.");
    }
    const body = await request("sendrawtransaction", "POST", {
      tx_as_hex: txHex,
      do_not_relay: false,
    });
    if (body.status !== "OK") {
      const status = typeof body.status === "string" ? body.status : "unknown";
      const reason = typeof body.reason === "string" ? ` (${body.reason})` : "";
      throw new Error(`Failed to send raw transaction: ${status}${reason}`);
    }
    return { status: body.status };
  }

  async function getRandomOuts(
    amounts: number[],
    count: number,
  ): Promise<DaemonRandomOutsForAmount[]> {
    if (!Array.isArray(amounts)) {
      throw new Error("`amounts` must be an array.");
    }
    if (!Number.isInteger(count) || count < 0) {
      throw new Error("`count` must be a non-negative integer.");
    }
    const body = await request("getrandom_outs", "POST", {
      amounts,
      outs_count: count,
    });
    assertStatusOk(body, "getrandom_outs");

    const rawOuts = body.outs;
    if (!Array.isArray(rawOuts)) {
      throw new Error("Daemon getrandom_outs response is missing the outs array.");
    }

    return rawOuts.map((entry, index) => {
      if (!isRecord(entry)) {
        throw new Error(`Daemon getrandom_outs entry ${index} is malformed.`);
      }
      const amount = Number(entry.amount);
      if (!Number.isFinite(amount)) {
        throw new Error(`Daemon getrandom_outs entry ${index} has an invalid amount.`);
      }
      const innerOuts = Array.isArray(entry.outs) ? entry.outs : [];
      const outs: DaemonRandomOut[] = innerOuts.map((out, outIndex) => {
        if (!isRecord(out)) {
          throw new Error(`Daemon getrandom_outs out ${index}/${outIndex} is malformed.`);
        }
        const globalIndex = Number(out.global_index);
        const publicKey = out.public_key;
        if (!Number.isFinite(globalIndex) || typeof publicKey !== "string") {
          throw new Error(`Daemon getrandom_outs out ${index}/${outIndex} has invalid fields.`);
        }
        return { globalIndex, publicKey };
      });
      return { amount, outs };
    });
  }

  async function getWalletSyncData(
    startBlock: number,
    endBlock: number,
    includeMinerTxs = true,
  ): Promise<DaemonRawTransaction[]> {
    if (!Number.isInteger(startBlock) || startBlock < 0) {
      throw new Error("`startBlock` must be a non-negative integer.");
    }
    if (!Number.isInteger(endBlock) || endBlock < startBlock) {
      throw new Error("`endBlock` must be an integer >= startBlock.");
    }
    // The daemon treats block 0 as genesis; the legacy client normalizes to 1.
    const normalizedStart = startBlock === 0 ? 1 : startBlock;

    // `range: true` makes the daemon return the HALF-OPEN range `[normalizedStart, endBlock)` —
    // the upper bound is EXCLUDED. Callers that want an inclusive range pass `endBlock = last + 1`.
    const body = await request("get_raw_transactions_by_heights", "POST", {
      heights: [normalizedStart, endBlock],
      include_miner_txs: includeMinerTxs,
      range: true,
    });
    assertStatusOk(body, "get_raw_transactions_by_heights");

    const rawTransactions = body.transactions;
    if (!Array.isArray(rawTransactions)) {
      throw new Error("Daemon get_raw_transactions_by_heights is missing the transactions array.");
    }

    const result: DaemonRawTransaction[] = [];
    for (let i = 0; i < rawTransactions.length; i++) {
      const rawTx = rawTransactions[i];
      if (!isRecord(rawTx)) {
        throw new Error(`Daemon transaction entry ${i} is malformed.`);
      }
      // Skip empty slots rather than fabricating data (matches legacy behavior).
      if (rawTx.transaction === undefined || rawTx.transaction === null) {
        continue;
      }
      result.push(mapRawTransaction(rawTx));
    }
    return result;
  }

  async function getTransactionsPool(): Promise<DaemonRawTransaction[]> {
    // `getrawtransactionspool` returns the same per-entry shape as
    // `get_raw_transactions_by_heights` (transaction/timestamp/output_indexes/
    // height/block_hash/hash/fee) — pool entries simply carry height 0 and a
    // zero block_hash. Parse identically so the caller can scan outputs.
    const body = await request("getrawtransactionspool", "POST", {});
    assertStatusOk(body, "getrawtransactionspool");

    const rawTransactions = body.transactions;
    if (!Array.isArray(rawTransactions)) {
      throw new Error("Daemon getrawtransactionspool is missing the transactions array.");
    }

    const result: DaemonRawTransaction[] = [];
    for (let i = 0; i < rawTransactions.length; i++) {
      const rawTx = rawTransactions[i];
      if (!isRecord(rawTx)) {
        throw new Error(`Daemon pool transaction entry ${i} is malformed.`);
      }
      if (rawTx.transaction === undefined || rawTx.transaction === null) {
        continue;
      }
      result.push(mapRawTransaction(rawTx));
    }
    return result;
  }

  return {
    nodeUrl: base,
    getHeight,
    getInfo,
    getNodeFeeAddress,
    sendRawTransaction,
    getRandomOuts,
    getWalletSyncData,
    getTransactionsPool,
  };
}
