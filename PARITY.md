# PARITY.md — C++ ↔ JS Interest Arithmetic Parity

Ground truth: `conceal-core/src/CryptoNoteCore/Currency.cpp`  
Functions: `calculateInterest` (V1 dispatcher) · `calculateInterestV2` (V2i/V2w) · `calculateInterestV3` (V3)

---

## Per-version operation table

### V1 — linear, BigInt

| Step | C++ | JS mirror | Notes |
|---|---|---|---|
| `a = term × RATE_MAX − RATE_MIN_FACTOR` | `uint64_t` multiply | BigInt multiply | exact |
| `b = amount × a` | `mul128` (128-bit product) | BigInt multiply | no overflow |
| `c = b ÷ (100 × DEPOSIT_MAX_TERM)` | `div128_32` (integer quotient, truncates) | BigInt `/` (truncates) | exact |
| early-deposit multiplier (lockHeight ≤ 12750) | `c × 100` integer | BigInt multiply | exact |
| return | `uint64_t cLo` | `Number(bigint)` safe—fits int53 | |

V1 is **exact in JS** via BigInt. No float involved.  
Constants: `DEPOSIT_MAX_TERM = 262800`, `DEPOSIT_MAX_TOTAL_RATE = 4`, `END_MULTIPLIER_BLOCK = 12750`.

---

### V2w — weekly deposits (`term % 5040 == 0`)

| Step | C++ type | JS mirror | Truncation point |
|---|---|---|---|
| `actualAmount = float(amount)` | `float` (float32) | `Math.fround(amount)` | amount → 24-bit mantissa |
| `weeks = float(term / 5040)` | integer div → `float` | `Math.trunc(term / 5040)` then `Math.fround` | exact (small int) |
| `baseInterest = float(0.0696)` | `float` literal | `Math.fround(0.0696)` | nearest float32 |
| `interestPerWeek = float(0.0002)` | `float` literal | `Math.fround(0.0002)` | nearest float32 |
| `interestRate = baseInterest + weeks × interestPerWeek` | float32 add/mul | `Math.fround(…)` at each op | accumulates float32 rounding |
| `interest = actualAmount × ((weeks × interestRate) / 100)` | float32 | `Math.fround` throughout | primary drift source |
| return | `static_cast<uint64_t>(interest)` truncates toward zero | `Math.trunc(interest)` | final truncation |

**Current JS status:** uses float64 → diverges from C++. Float32 rewrite deferred to a later task.

---

### V2i — quarterly investment (`term % 64800 == 0`)

| Step | C++ type | JS mirror | Notes |
|---|---|---|---|
| `amount4Humans = amount / 1_000_000` | integer div | `Math.trunc(amount / 1e6)` (int) | exact |
| `qTier` tier selection | float32 literals | `Math.fround(tierValue)` | 16 tiers, comparisons on integer `amount4Humans` |
| `mq = float(1.4473)` | float32 | `Math.fround(1.4473)` | nearest float32 |
| `termQuarters = float(term / 64800)` | integer div → float | `Math.trunc(term/64800)` then `Math.fround` | exact (small int 1–20) |
| **`m8 = float(100 × pow(1 + mq/100, termQuarters) − 100)`** | `libm pow`, float32 cast | **precomputed `INVESTMENT_M8[quarter]`** | see §Pow mitigation |
| `m5 = termQuarters × 0.5` | float32 | `Math.fround(termQuarters * 0.5)` | |
| `m7 = m8 × (1 + m5 / 100)` | float32 | `Math.fround(m8 * (1 + Math.fround(m5 / 100)))` | |
| `rate = m7 × qTier` | float32 | `Math.fround(m7 * qTier)` | |
| `interest = float(amount) × (rate / 100)` | float32 | `Math.fround(Math.fround(amount) * Math.fround(rate / 100))` | |
| return | `static_cast<uint64_t>(interest)` | `Math.trunc(interest)` | |

---

### V3 — monthly deposits (`term % 21900 == 0`, `lockHeight > 413400`)

| Step | C++ type | JS mirror | Notes |
|---|---|---|---|
| `amount4Humans = amount / COIN` | integer div | `Math.trunc(amount / 1_000_000)` | exact |
| `baseInterest` tier selection | float32 literals (0.029 / 0.039 / 0.049) | `Math.fround(tierValue)` | 3 tiers |
| `months = float(term / 21900)` | integer div → float32 | `Math.trunc(term/21900)` then `Math.fround`; capped at 12 | exact for valid terms |
| `ear = baseInterest + (months − 1) × 0.001` | float32 | `Math.fround(…)` at each op | `0.001` not exact in float32 |
| `eir = (ear / 12) × months` | float32 | `Math.fround(…)` | division-then-multiply order preserved |
| `interest = float(amount) × eir` | float32 | `Math.fround(Math.fround(amount) * eir)` | **primary drift** |
| return | `static_cast<uint64_t>(interest)` | `Math.trunc(interest)` | |

**Canonical divergence example** (load-bearing):  
`amount = 20 000 CCX (2×10¹⁰ atomic)`, `term = 6 months (131 400)`, `lockHeight = 500 000`  
→ C++ float32: **540 000 000** · JS float64: **539 999 999** (one unit off — `0.027` not exact in binary; float32 rounding rounds up, float64 rounds down)

---

## Impossible-in-JS operations and mitigations

### `pow` with `libm` float32 semantics

**Problem:** `Math.pow` in JS uses float64 throughout. `libm powf` (or `(float)pow(...)`) on x86 produces a float32 result that differs from `Math.pow` even after `Math.fround`, because the intermediate exponentiation passes through x87/SSE at 64-bit precision then truncates differently.

**Mitigation:** V2i `m8 = float(100 × pow(1+mq/100, termQuarters) − 100)` is **precomputed** for all valid inputs (termQuarters 1–20) by `tools/interest-parity/gen_m8.cpp` compiled with `g++ -O0 -lm`, which runs the exact C++ expression and captures the float32 bit pattern via `memcpy`. Results are committed to `src/deposits/investment-m8.ts` as `INVESTMENT_M8[quarter]` with hex ground truth.

JS lookup:
```ts
const entry = INVESTMENT_M8.find(e => e.quarter === termQuarters);
if (!entry) throw new RangeError(`termQuarters ${termQuarters} out of range 1–20`);
const m8 = entry.m8;  // already Math.fround'd, bit-identical to C++
```

Throws `RangeError` if `quarter < 1 || quarter > 20`; `DEPOSIT_MAX_TERM_V1 = 64800 × 20` makes 20 the hard maximum.

### `__uint128_t` 128-bit multiply/divide

**Problem:** JS has no native 128-bit integer type.

**Mitigation (V1):** Implemented with BigInt (`BigInt(a) * BigInt(b)`, integer division). Produces bit-identical results — verified by the V1 parity test suite (all GREEN).

**Mitigation (V2i/V2w/V3):** Not needed; these paths use float32 arithmetic, not 128-bit integers.

### `static_cast<float>(amount)` on large uint64

**Problem:** `amount` can exceed 2⁵³; `Math.fround(amount)` truncates to 24-bit mantissa. This is **identical** to C++ `static_cast<float>(amount)` behavior — no special mitigation needed, float32 truncation is intentional and must be preserved.

### RPC deferred

Direct RPC call to daemon `calculateInterestV2` / `calculateInterestV3` is **deferred**. The precomputed table and Math.fround mirrors are the current mitigation for offline / client-side computation.

---

## Stored float64 mismatch note

The daemon stores interest as a uint64 computed from float32 arithmetic. Any value cached in a local wallet database using the current float64 JS path may be off by ±1–8 atomic units (see test comments for known examples). On **withdrawal**, the daemon recomputes interest server-side and **fail-closes** the transaction if the presented interest does not match the recomputed value. Clients should treat locally computed interest as an estimate; the canonical value is always the daemon's.

A wallet resync forces re-fetch of daemon-confirmed interest values and clears stale float64 estimates.

---

## Fixtures and tooling

- **`tests/fixtures/interest-parity.json`** — golden corpus covering all four versions; generated by `tools/interest-parity/gen_interest.cpp` with `g++ -O0 -lm`. **Never edit by hand.**
- **`tests/interest-parity.test.ts`** — parity test suite. V1 GREEN; V2/V3 RED until float32 rewrite.
- **`src/deposits/investment-m8.ts`** — committed `INVESTMENT_M8` table (quarters 1–20) with IEEE-754 hex ground truth.
- **`tools/interest-parity/gen_m8.cpp`** — regenerates the `m8` table.
- **`tools/interest-parity/gen_interest.cpp`** — regenerates `interest-parity.json`.
- See **`tools/interest-parity/README.md`** for compile/run instructions and endianness notes.

Regenerate after any `Currency.cpp` interest logic change:
```bash
cd tools/interest-parity
g++ -O0 -o gen_m8 gen_m8.cpp -lm && ./gen_m8
g++ -O0 -o gen_interest gen_interest.cpp -lm && ./gen_interest > ../../tests/fixtures/interest-parity.json
```
