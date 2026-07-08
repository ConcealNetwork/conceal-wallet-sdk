import { describe, expect, it } from "vitest";
import { canonVinType, canonVoutType, parseDaemonNum } from "../src/tx-shape";

describe("canonVoutType", () => {
  it("maps symbolic, wire, and numeric deposit/key tags to 02/03", () => {
    expect(canonVoutType("txout_to_key")).toBe("02");
    expect(canonVoutType("02")).toBe("02");
    expect(canonVoutType(2)).toBe("02");
    expect(canonVoutType("txout_to_deposit_key")).toBe("03");
    expect(canonVoutType("03")).toBe("03");
    expect(canonVoutType(3)).toBe("03");
    expect(canonVoutType("ff")).toBeNull();
  });
});

describe("canonVinType", () => {
  it("maps ring and deposit vin tags", () => {
    expect(canonVinType("input_to_key")).toBe("02");
    expect(canonVinType("02")).toBe("02");
    expect(canonVinType("input_to_deposit_key")).toBe("input_to_deposit_key");
    expect(canonVinType("03")).toBe("input_to_deposit_key");
    expect(canonVinType(3)).toBe("input_to_deposit_key");
    expect(canonVinType("ff")).toBeNull();
  });
});

describe("parseDaemonNum", () => {
  it("coerces finite numbers and numeric strings", () => {
    expect(parseDaemonNum(21900)).toBe(21900);
    expect(parseDaemonNum("21900")).toBe(21900);
    expect(parseDaemonNum("1e10")).toBe(1e10);
    expect(parseDaemonNum("")).toBeUndefined();
    expect(parseDaemonNum("nope")).toBeUndefined();
    expect(parseDaemonNum(undefined)).toBeUndefined();
  });
});
