# tools/interest-parity

Generator that reproduces the **exact** `m8` float32 values from the Conceal
daemon's investment-interest calculation (`Currency.cpp`).

## C++ fragment reproduced (gen_m8.cpp — m8 table)

```cpp
auto mq = static_cast<float>(1.4473);
float termQuarters = term / 64800;   // integer division then to float
auto m8 = (float)(100.0 * pow(1.0 + (mq / 100.0), termQuarters) - 100.0);
```

`DEPOSIT_MAX_TERM_V1 = 64800 * 20`, so `termQuarters` runs 1 – 20.

## Compile & run (gen_m8 — m8 table)

```bash
g++ -O0 -o gen_m8 gen_m8.cpp -lm
./gen_m8
```

Output columns: `quarter,m8_decimal,m8_hex`

The hex column is the IEEE-754 float32 bit pattern obtained via `memcpy`,
identical to what the daemon stores in the blockchain.  These values are
committed verbatim into `src/deposits/investment-m8.ts`.

> **Endianness note:** the JS parity test reads the bit pattern using
> `DataView.getUint32(0, true)` (little-endian), matching x86/x86-64 native
> byte order.  If you regenerate on a big-endian host the hex values will be
> byte-swapped; always cross-check with an x86 build.

---

## Interest corpus generator (gen_interest.cpp — interest-parity.json)

Mirrors the full `calculateInterest` / `calculateInterestV2` / `calculateInterestV3`
functions from `CryptoNoteCore/Currency.cpp` using **float32** arithmetic and
`__uint128_t`-based mul128/div128_32.  The output is a JSON fixture consumed by
`tests/interest-parity.test.ts`.

### Constants used

| Constant | Value | Source |
|---|---|---|
| `COIN` | `1_000_000` | CryptoNoteConfig.h |
| `DEPOSIT_MAX_TERM` | `262800` (12 × 21900) | CryptoNoteConfig.h |
| `DEPOSIT_MIN_TERM_V3` | `21900` (1 month) | CryptoNoteConfig.h |
| `DEPOSIT_HEIGHT_V3` | `413400` | CryptoNoteConfig.h |
| `DEPOSIT_MAX_TOTAL_RATE` | `4` | CryptoNoteConfig.h |
| `END_MULTIPLIER_BLOCK` | `12750` | CryptoNoteConfig.h |
| `MULTIPLIER_FACTOR` | `100` | CryptoNoteConfig.h |

### Compile & run

```bash
cd tools/interest-parity
g++ -O0 -o gen_interest gen_interest.cpp -lm
./gen_interest > ../../tests/fixtures/interest-parity.json
```

**Always use `-O0`** to prevent the compiler from promoting intermediate float32
values to wider registers, which would change results.

### Verify canonical 540000000 case

After regenerating, confirm the daemon-verified edge case is present:

```bash
python3 -c "
import json, sys
data = json.load(open('tests/fixtures/interest-parity.json'))
case = next(c for c in data['cases'] if c['id'] == 'v3-6mo-20k')
assert case['expectedInterest'] == 540000000, f'Expected 540000000, got {case[\"expectedInterest\"]}'
print('OK: v3-6mo-20k =', case['expectedInterest'])
"
```

### When to regenerate

- After updating `CryptoNoteCore/Currency.cpp` interest logic.
- When adding new deposit tiers or term ranges.
- Never edit `tests/fixtures/interest-parity.json` by hand — always derive from C++.
