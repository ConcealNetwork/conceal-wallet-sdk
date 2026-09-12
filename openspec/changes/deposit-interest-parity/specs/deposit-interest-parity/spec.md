## Purpose

Defines wallet-side deposit interest as an operationally identical port of Conceal daemon `Currency.cpp`, so withdrawal amounts built by the SDK are accepted by the node.

## ADDED Requirements

### Requirement: Interest matches daemon per deposit version
The system MUST compute deposit interest for V1, V2 (investment and weekly), and V3 using the same arithmetic model, operation order, and truncation as `conceal-core` `Currency::calculateInterest*` for the given principal, term, and lock height.

#### Scenario: V3 float32 truncation matches daemon
- **WHEN** interest is computed for amount `20000 * 10^6` atomic units, term `21900 * 6`, and a lock height that selects V3
- **THEN** the result MUST equal `540000000` (daemon float32 path), not a float64 `Math.floor` artifact such as `539999999`

#### Scenario: V2 weekly matches daemon
- **WHEN** interest is computed for a weekly term (`term % 5040 == 0`, not routed to V3)
- **THEN** the result MUST equal the daemon float32 truncating cast for that amount and term

#### Scenario: V1 integer path unchanged
- **WHEN** interest is computed for a term that is not a V2/V3 multiple
- **THEN** the result MUST remain the existing BigInt truncating-divide path (including early-deposit multiplier when `lockHeight <= 12750`)

### Requirement: V2 investment does not depend on runtime Math.pow
For V2 investment terms (`term % 64800 == 0`), the system MUST obtain the daemon `m8` intermediate from a static table keyed by integer `termQuarters` in `1…20`, generated from C++ `(float)(100.0 * pow(1.0 + mq/100.0, termQuarters) - 100.0)`, and MUST NOT call `Math.pow` (or equivalent libm) at runtime for that intermediate.

#### Scenario: Known quarter uses table
- **WHEN** `termQuarters` is between 1 and 20 inclusive
- **THEN** interest computation MUST use the table entry for `m8` and continue the remaining float32 ops as in the daemon

#### Scenario: Unsupported quarter fails closed
- **WHEN** `termQuarters` is outside the table
- **THEN** the system MUST throw (fail closed); daemon RPC fallback is not required in this change

### Requirement: Sync and withdraw use one interest function
Stored deposit interest at scan time and recomputed interest at withdraw-build time MUST come from the same exported calculation entry point so a mismatch indicates data corruption, not internal drift.

#### Scenario: Withdraw recompute agrees with fresh scan interest
- **WHEN** an `OwnedDeposit` was produced by scan using `calculateDepositInterest` and withdraw rebuild calls `recomputeDepositInterest`
- **THEN** both MUST return the identical atomic interest for the same amount, term, and block height

### Requirement: Golden corpus pins daemon truth
The SDK MUST ship committed fixtures of `(version, amount, term, lockHeight) → expectedInterest` derived from a C++ harness mirroring `Currency.cpp`, and automated tests MUST fail if JS diverges from any fixture.

#### Scenario: Parity suite fails on drift
- **WHEN** any golden fixture interest disagrees with `calculateDepositInterest`
- **THEN** the test suite MUST fail

### Requirement: Downstream goldens follow daemon
Consumer golden tests that pin interest values (including next-wallet) MUST be updated to daemon-verified numbers and MUST NOT retain known float64 artifacts once the SDK parity path lands.

#### Scenario: Next-wallet golden updated
- **WHEN** next-wallet interest tests assert V3 `20000 CCX × 1 month` or V2 weekly `50000 CCX × 4 weeks`
- **THEN** expectations MUST be `81666664` and `140800000` respectively (daemon), not prior float64 values
