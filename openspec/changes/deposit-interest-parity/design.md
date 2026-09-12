## Context

See proposal.md — Why. Ground truth is `~/project_CPP/conceal-core/src/CryptoNoteCore/Currency.cpp`. Current SDK V2/V3 use Number float64; daemon uses `float`. V1 BigInt path already matches. `recomputeDepositInterest` already delegates to `calculateDepositInterest`.

## Goals / Non-Goals

**Goals:**
- Operational identity with C++ float32 (+ tabled `m8`) for V2/V3.
- Committed goldens + CI failure on drift.
- Documented parity table in `PARITY.md`.

**Non-Goals:**
- Changing daemon consensus.
- Full interest LUT or live RPC for investment.
- Moving primitives into conceal-lib-js this pass.
- Algebraic formula rewrites / exp-by-squaring instead of daemon `pow`.

## Decisions

1. **Float32 via `Math.fround`** after each C++ `float` op; int÷ for `amount4Humans` / `months` / `weeks` / `termQuarters`; final `Math.trunc` for positive interest (= truncating `uint64_t` cast).
2. **`m8` table** for investment (B): generate once from C++ for quarters 1…20 (`DEPOSIT_MAX_TERM_V1`); store float32 bit patterns or decimal literals that round-trip via `Math.fround`; runtime lookup; throw if missing.
3. **No lib-js change** — `Math.fround` is sufficient; dependency order satisfied by not needing upstream.
4. **Fixtures** committed JSON; optional `tools/` regen notes in `PARITY.md`; CI does not compile C++.
5. **Next-wallet** fixture update after SDK tests green, same effort / separate checkout.

## Risks / Trade-offs

- [Risk] Table stale if MQ/`pow` consensus changes → Mitigation: regenerate from C++; document in `PARITY.md`.
- [Risk] `Math.fround` sequence mistyped vs C++ → Mitigation: harness goldens covering edges (`540000000`, tier boundaries, large principals).
- [Risk] Existing wallets stored float64 interest → Mitigation: withdraw recomputes from principal/term/height; stored wrong interest will throw mismatch until resync — prefer fail closed over signing a bad redeem sum. Document in `PARITY.md`.

## Migration Plan

1. Land SDK math + fixtures + tests.
2. Update next-wallet goldens against new SDK.
3. Users with persisted wrong interest: rescan/recompute on open (existing recompute guard).

## Open Questions

None — deferred RPC explicitly out of scope.
