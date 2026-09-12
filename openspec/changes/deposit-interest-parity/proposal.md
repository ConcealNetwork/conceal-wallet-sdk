## Why

Web-wallet deposit withdrawals can be rejected by the Conceal daemon when JS interest disagrees with `Currency.cpp` by ±1 atomic unit. Current V2/V3 paths use float64 + `Math.floor`; the daemon uses float32 + truncating cast. We need bit-exact operational parity so withdraw outputs always match node validation.

## What Changes

- Rewrite V2/V3 interest computation in the SDK to mirror daemon float32 op order (`Math.fround`), with integer division where C++ uses int÷.
- Replace runtime `Math.pow` on the V2 investment path with a C++-generated precomputed `m8[termQuarters]` table (termQuarters 1…20); throw if missing.
- Leave V1 BigInt path unchanged; keep `calculateDepositInterest` public signature.
- Add `PARITY.md`, golden fixtures from a C++ harness, and CI parity tests.
- Reconcile SDK and next-wallet golden tests to daemon-verified values (drop float64 artifacts).

## Capabilities

### New Capabilities
- `deposit-interest-parity`: Bit-exact deposit interest vs Conceal daemon for V1/V2/V3, including investment `m8` table mitigation and withdraw recompute consistency.

### Modified Capabilities
- (none — no prior openspec specs in this repo)

## Impact

- `src/deposits.ts` (primary); `buildWithdrawTransaction` only if recompute path drifts (expected: already shared).
- Tests: `tests/deposits.test.ts`, new parity fixtures/tests; downstream `conceal-next-wallet/tests/interest.test.ts` after SDK green.
- Docs: `PARITY.md` at SDK root.
- No conceal-lib-js API change; no daemon change; no public API **BREAKING** (numeric results for some V2/V3 cases **will** change to match the chain — intentional).
