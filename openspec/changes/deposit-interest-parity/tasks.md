## 1. Ground truth artefacts

- [x] 1.1 Generate `m8` float32 values for termQuarters 1…20 from a C++ snippet matching Currency.cpp investment `pow` line; record bit patterns for the table
- [x] 1.2 Generate golden interest corpus (V1/V2/V3 edges including 540000000) via the same harness; write `tests/fixtures/interest-parity.json`
- [x] 1.3 Author `PARITY.md` with per-version C++ vs JS op tables and `pow`/`m8` impossibility mitigation

## 2. SDK interest implementation

- [x] 2.1 Rewrite `calculateInterestV3` to float32 op-for-op mirror (int÷ tiers/months, `Math.fround`, `Math.trunc`)
- [x] 2.2 Rewrite V2 weekly branch likewise
- [x] 2.3 Rewrite V2 investment: qTier + tabled `m8` + remaining float32 ops; throw on missing quarter; leave V1 untouched
- [x] 2.4 Confirm `recomputeDepositInterest` / scan / `buildWithdrawTransaction` share one calculate path (fix only if drifted)

## 3. Tests

- [x] 3.1 Add vitest parity suite loading fixtures; assert exact equality
- [x] 3.2 Update `tests/deposits.test.ts` expectations to daemon values (stop deriving expected via float64 `Math.floor`)
- [x] 3.3 Run `npm run types && npm run lint && npm test` green in SDK

## 4. Downstream

- [ ] 4.1 Update `conceal-next-wallet/tests/interest.test.ts` goldens to daemon-verified values against the new SDK behavior
- [ ] 4.2 Run next-wallet interest tests green (local link or version pin as available)

> **Follow-up (not in this SDK PR):** Daemon float32 expectations are drafted locally in
> `conceal-next-wallet` (`81_666_664`, `140_800_000`, `6_007_192_064`, …) but are not
> committed/PRd yet. Mark 4.1/4.2 done only after that next-wallet change lands against
> a released/pinned SDK that includes this float32 path. Until then the SDK bridge
> (`vitest.next-wallet-interest.config.ts`) can verify locally.

## 5. Product-loop acceptance

- [x] 5.1 Author/run Forge e2e (or spine `notApplicable` if pure library with unit evidence only per spine decision) proving calculate → fixture match → withdraw recompute identity
