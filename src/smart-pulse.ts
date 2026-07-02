// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

import { encodeSmartMessage, parseSmartMessage } from "./messages";

const MODULE = "status";

/** Wire tokens for `{status,<kind>,…}`. */
export type PulseKind = "alive" | "sos" | "sick" | "dnd";

export type PulsePhase = "ok" | "grace" | "overdue";

export interface StatusPulse {
  kind: PulseKind;
  /** Inclusive calendar end date `YYYY-MM-DD` (UTC), when set. */
  until?: string;
  graceDays: number;
}

const KINDS: Record<string, PulseKind> = {
  alive: "alive",
  ok: "alive",
  sos: "sos",
  sick: "sick",
  dnd: "dnd",
};

const DAY_MS = 86_400_000;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function parseKind(raw: string | undefined): PulseKind | null {
  if (!raw || !Object.hasOwn(KINDS, raw)) return null;
  return KINDS[raw] as PulseKind;
}

function parseGrace(raw: string | undefined): number {
  if (!raw) return 0;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

export function untilEndMs(until: string): number | null {
  if (!DATE_RE.test(until)) return null;
  const end = Date.parse(`${until}T23:59:59.999Z`);
  return Number.isFinite(end) ? end : null;
}

export function formatStatusPulse(kind: PulseKind, until?: string, graceDays = 0): string {
  if (until && DATE_RE.test(until)) {
    return graceDays > 0
      ? encodeSmartMessage(MODULE, kind, until, String(graceDays))
      : encodeSmartMessage(MODULE, kind, until);
  }
  return encodeSmartMessage(MODULE, kind);
}

export function parseStatusPulse(body: unknown): StatusPulse | null {
  const parts = parseSmartMessage(body);
  if (!parts || parts[0] !== MODULE) return null;
  const kind = parseKind(parts[1]?.toLowerCase());
  if (!kind) return null;

  let until: string | undefined;
  let graceDays = 0;
  if (parts[2] && DATE_RE.test(parts[2])) {
    until = parts[2];
    graceDays = parseGrace(parts[3]);
  }

  return { kind, until, graceDays };
}

export function isStatusPulse(body: unknown): boolean {
  return parseStatusPulse(body) !== null;
}

export function pulsePhase(pulse: StatusPulse, nowMs: number): PulsePhase {
  if (!pulse.until) return "ok";
  const end = untilEndMs(pulse.until);
  if (end === null) return "ok";
  if (nowMs <= end) return "ok";
  const graceEnd = end + pulse.graceDays * DAY_MS;
  if (nowMs <= graceEnd) return "grace";
  return "overdue";
}

export function defaultUntilDate(daysFromNow: number, now = new Date()): string {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  d.setUTCDate(d.getUTCDate() + daysFromNow);
  return d.toISOString().slice(0, 10);
}
