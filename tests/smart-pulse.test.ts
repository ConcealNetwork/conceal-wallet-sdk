import { describe, expect, it } from "vitest";
import { encodeSmartMessage } from "../src/messages";
import {
  defaultUntilDate,
  formatStatusPulse,
  isStatusPulse,
  parseStatusPulse,
  pulsePhase,
  untilEndMs,
} from "../src/smart-pulse";

describe("status pulse", () => {
  it("round-trips {status,alive,2026-07-02,2}", () => {
    const body = formatStatusPulse("alive", "2026-07-02", 2);
    expect(body).toBe("{status,alive,2026-07-02,2}");
    expect(parseStatusPulse(body)).toEqual({
      kind: "alive",
      until: "2026-07-02",
      graceDays: 2,
    });
  });

  it("parses all kinds and ok alias", () => {
    for (const kind of ["alive", "sos", "sick", "dnd"] as const) {
      expect(parseStatusPulse(formatStatusPulse(kind, "2026-12-01", 1))?.kind).toBe(kind);
    }
    expect(parseStatusPulse("{status,ok}")).toEqual({ kind: "alive", graceDays: 0 });
    expect(encodeSmartMessage("status", "ok")).toBe("{status,alive}");
  });

  it("pulsePhase: ok → grace → overdue", () => {
    const pulse = parseStatusPulse("{status,alive,2026-07-02,2}");
    const end = untilEndMs("2026-07-02");
    if (!pulse || end === null) throw new Error("fixture");
    expect(pulsePhase(pulse, end - 1)).toBe("ok");
    expect(pulsePhase(pulse, end + 1)).toBe("grace");
    expect(pulsePhase(pulse, end + 2 * 86_400_000 + 1)).toBe("overdue");
  });

  it("defaultUntilDate and isStatusPulse", () => {
    expect(defaultUntilDate(14, new Date("2026-01-15T12:00:00.000Z"))).toBe("2026-01-29");
    expect(isStatusPulse("{status,sos}")).toBe(true);
    expect(isStatusPulse("chat")).toBe(false);
  });
});
