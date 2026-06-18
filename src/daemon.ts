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
  /** Daemon proxy base URL. Must be `https://`; a trailing slash is enforced. */
  nodeUrl: string;
  /** `fetch` implementation to use. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Per-request timeout in milliseconds. Defaults to {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number;
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

/** The typed Conceal daemon client. */
export interface DaemonClient {
  /** Normalized base URL (always `https://…/`). */
  readonly nodeUrl: string;
  /** Current network height. */
  getHeight(): Promise<number>;
  /** Node fee address (`""` when the node charges no fee). */
  getNodeFeeAddress(): Promise<string>;
  /** Submit a raw, hex-encoded transaction for relay. */
  sendRawTransaction(txHex: Hex): Promise<SendRawTransactionResult>;
  /** Fetch `count` random decoy outputs for each requested amount. */
  getRandomOuts(amounts: number[], count: number): Promise<DaemonRandomOutsForAmount[]>;
  /** Fetch raw transactions for the inclusive block range `[startBlock, endBlock]`. */
  getWalletSyncData(
    startBlock: number,
    endBlock: number,
    includeMinerTxs?: boolean,
  ): Promise<DaemonRawTransaction[]>;
}

/** Default per-request timeout (matches the legacy `NodeWorker.timeout`). */
export const DEFAULT_TIMEOUT_MS = 10_000;

const JSON_HEADERS: Readonly<Record<string, string>> = { "Content-Type": "application/json" };

/**
 * Normalize a daemon proxy URL: enforce `https://` and a trailing slash.
 * Throws on empty / non-`https` URLs.
 */
export function normalizeNodeUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) {
    throw new Error("Node URL is required.");
  }
  if (!/^https:\/\//i.test(trimmed)) {
    throw new Error("Node URL must start with https://");
  }
  return trimmed.endsWith("/") ? trimmed : `${trimmed}/`;
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

export function createDaemonClient(opts: DaemonClientOptions): DaemonClient {
  const base = normalizeNodeUrl(opts.nodeUrl);
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
      const outputIndexes = Array.isArray(rawTx.output_indexes)
        ? rawTx.output_indexes.map((value) => Number(value))
        : [];
      result.push({
        transaction: rawTx.transaction,
        timestamp: Number(rawTx.timestamp) || 0,
        outputIndexes,
        height: Number(rawTx.height) || 0,
        blockHash: typeof rawTx.block_hash === "string" ? rawTx.block_hash : "",
        hash: typeof rawTx.hash === "string" ? rawTx.hash : "",
        fee: Number(rawTx.fee) || 0,
      });
    }
    return result;
  }

  return {
    nodeUrl: base,
    getHeight,
    getNodeFeeAddress,
    sendRawTransaction,
    getRandomOuts,
    getWalletSyncData,
  };
}
