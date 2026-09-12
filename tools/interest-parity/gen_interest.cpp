// gen_interest.cpp — Generate golden interest fixtures for V1/V2i/V2w/V3
//
// Mirrors CryptoNoteCore/Currency.cpp: calculateInterest, calculateInterestV2, calculateInterestV3.
// Float32 / truncating-cast semantics preserved exactly.
//
// Compile: g++ -O0 -o gen_interest gen_interest.cpp -lm
// Run:     ./gen_interest > ../../tests/fixtures/interest-parity.json
//
// Constants from src/CryptoNoteConfig.h:
//   COIN                        = 1_000_000
//   DEPOSIT_MAX_TERM            = 1 * 12 * 21900 = 262800
//   DEPOSIT_MIN_TERM_V3         = 21900
//   DEPOSIT_HEIGHT_V3           = 413400
//   DEPOSIT_MIN_TOTAL_RATE_FACTOR = 0
//   DEPOSIT_MAX_TOTAL_RATE      = 4
//   MULTIPLIER_FACTOR           = 100
//   END_MULTIPLIER_BLOCK        = 12750

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

// ---- constants ---------------------------------------------------------------
static const uint64_t COIN                         = 1000000ULL;
static const uint32_t DEPOSIT_MAX_TERM             = 262800U;   // 12 * 21900
static const uint32_t DEPOSIT_MIN_TERM_V3          = 21900U;
static const uint32_t DEPOSIT_HEIGHT_V3            = 413400U;
static const uint64_t DEPOSIT_MIN_TOTAL_RATE_FACTOR = 0ULL;
static const uint64_t DEPOSIT_MAX_TOTAL_RATE       = 4ULL;
static const uint64_t MULTIPLIER_FACTOR            = 100ULL;
static const uint32_t END_MULTIPLIER_BLOCK         = 12750U;

// ---- 128-bit helpers (mirrors int-util.h via __uint128_t) --------------------

static uint64_t mul128(uint64_t a, uint64_t b, uint64_t *hi) {
    __uint128_t r = (__uint128_t)a * b;
    *hi = (uint64_t)(r >> 64);
    return (uint64_t)r;
}

static void div128_32(uint64_t dividend_hi, uint64_t dividend_lo,
                      uint32_t divisor,
                      uint64_t *quotient_hi, uint64_t *quotient_lo) {
    __uint128_t n = ((__uint128_t)dividend_hi << 64) | dividend_lo;
    __uint128_t q = n / divisor;
    *quotient_hi = (uint64_t)(q >> 64);
    *quotient_lo = (uint64_t)q;
}

// ---- V3 (monthly deposits, post DEPOSIT_HEIGHT_V3) --------------------------
static uint64_t calculateInterestV3(uint64_t amount, uint32_t term) {
    uint64_t amount4Humans = amount / COIN;

    auto baseInterest = static_cast<float>(0.029);
    if (amount4Humans >= 10000 && amount4Humans < 20000)
        baseInterest = static_cast<float>(0.039);
    if (amount4Humans >= 20000)
        baseInterest = static_cast<float>(0.049);

    auto months = static_cast<float>(term / DEPOSIT_MIN_TERM_V3);  // integer div → float
    if (months > 12.0f)
        months = 12.0f;

    float ear = baseInterest + (months - 1.0f) * 0.001f;
    float eir = (ear / 12.0f) * months;
    float interest = static_cast<float>(amount) * eir;
    return static_cast<uint64_t>(interest);
}

// ---- V2 (investments + weekly) ----------------------------------------------
static uint64_t calculateInterestV2(uint64_t amount, uint32_t term) {
    uint64_t returnVal = 0;

    /* ---- quarterly investments: term % 64800 == 0 ---- */
    if (term % 64800 == 0) {
        uint64_t amount4Humans = amount / 1000000ULL;

        float qTier = 1.0f;
        if (amount4Humans >  110000 && amount4Humans <  180000) qTier = static_cast<float>(1.01);
        if (amount4Humans >= 180000 && amount4Humans <  260000) qTier = static_cast<float>(1.02);
        if (amount4Humans >= 260000 && amount4Humans <  350000) qTier = static_cast<float>(1.03);
        if (amount4Humans >= 350000 && amount4Humans <  450000) qTier = static_cast<float>(1.04);
        if (amount4Humans >= 450000 && amount4Humans <  560000) qTier = static_cast<float>(1.05);
        if (amount4Humans >= 560000 && amount4Humans <  680000) qTier = static_cast<float>(1.06);
        if (amount4Humans >= 680000 && amount4Humans <  810000) qTier = static_cast<float>(1.07);
        if (amount4Humans >= 810000 && amount4Humans <  950000) qTier = static_cast<float>(1.08);
        if (amount4Humans >= 950000 && amount4Humans < 1100000) qTier = static_cast<float>(1.09);
        if (amount4Humans >= 1100000 && amount4Humans < 1260000) qTier = static_cast<float>(1.1);
        if (amount4Humans >= 1260000 && amount4Humans < 1430000) qTier = static_cast<float>(1.11);
        if (amount4Humans >= 1430000 && amount4Humans < 1610000) qTier = static_cast<float>(1.12);
        if (amount4Humans >= 1610000 && amount4Humans < 1800000) qTier = static_cast<float>(1.13);
        if (amount4Humans >= 1800000 && amount4Humans < 2000000) qTier = static_cast<float>(1.14);
        if (amount4Humans >  2000000)                            qTier = static_cast<float>(1.15);

        auto mq = static_cast<float>(1.4473);
        float termQuarters = static_cast<float>(term / 64800);  // integer div → float
        auto m8 = static_cast<float>(100.0 * pow(1.0 + (mq / 100.0), termQuarters) - 100.0);
        float m5 = termQuarters * 0.5f;
        float m7 = m8 * (1.0f + (m5 / 100.0f));
        float rate = m7 * qTier;
        float interest = static_cast<float>(amount) * (rate / 100.0f);
        returnVal = static_cast<uint64_t>(interest);
        return returnVal;
    }

    /* ---- weekly deposits: term % 5040 == 0 ---- */
    if (term % 5040 == 0) {
        auto actualAmount   = static_cast<float>(amount);
        float weeks         = static_cast<float>(term / 5040);  // integer div → float
        auto baseInterest   = static_cast<float>(0.0696);
        auto interestPerWeek = static_cast<float>(0.0002);
        float interestRate  = baseInterest + (weeks * interestPerWeek);
        float interest      = actualAmount * ((weeks * interestRate) / 100.0f);
        returnVal = static_cast<uint64_t>(interest);
        return returnVal;
    }

    return returnVal;
}

// ---- dispatcher (mirrors calculateInterest) ---------------------------------
static uint64_t calculateInterest(uint64_t amount, uint32_t term, uint32_t lockHeight) {
    // V3 monthly
    if (term % DEPOSIT_MIN_TERM_V3 == 0 && lockHeight > DEPOSIT_HEIGHT_V3)
        return calculateInterestV3(amount, term);

    // V2 quarterly investment
    if (term % 64800 == 0)
        return calculateInterestV2(amount, term);

    // V2 weekly
    if (term % 5040 == 0)
        return calculateInterestV2(amount, term);

    // V1 linear (with optional early-deposit multiplier)
    uint64_t a = (uint64_t)term * DEPOSIT_MAX_TOTAL_RATE - DEPOSIT_MIN_TOTAL_RATE_FACTOR;
    uint64_t bHi;
    uint64_t bLo = mul128(amount, a, &bHi);
    uint64_t cHi, cLo;
    div128_32(bHi, bLo, (uint32_t)(100U * DEPOSIT_MAX_TERM), &cHi, &cLo);
    assert(cHi == 0);

    uint64_t interestHi, interestLo;
    if (lockHeight <= END_MULTIPLIER_BLOCK) {
        interestLo = mul128(cLo, MULTIPLIER_FACTOR, &interestHi);
        assert(interestHi == 0);
    } else {
        interestHi = cHi;
        interestLo = cLo;
    }
    return interestLo;
}

// ---- test-case table ---------------------------------------------------------
struct Case {
    const char *id;
    const char *version;
    uint64_t    amount;    // in atomic units (CCX * 1_000_000)
    uint32_t    term;
    uint32_t    lockHeight;
};

static const Case CASES[] = {
    // ---- V3 (lockHeight > 413400, term % 21900 == 0) -------------------------
    // tier < 10000 CCX (baseInterest 0.029)
    { "v3-1mo-5k",    "V3",  5000ULL * COIN, 1*21900, 500000 },
    { "v3-6mo-5k",    "V3",  5000ULL * COIN, 6*21900, 500000 },
    { "v3-12mo-5k",   "V3",  5000ULL * COIN,12*21900, 500000 },
    // tier 10000–20000 CCX (baseInterest 0.039)
    { "v3-1mo-15k",   "V3", 15000ULL * COIN, 1*21900, 500000 },
    { "v3-6mo-15k",   "V3", 15000ULL * COIN, 6*21900, 500000 },
    // tier >= 20000 CCX (baseInterest 0.049) — includes the 540000000 edge case
    { "v3-1mo-20k",   "V3", 20000ULL * COIN, 1*21900, 500000 },
    { "v3-6mo-20k",   "V3", 20000ULL * COIN, 6*21900, 500000 }, // expect 540000000
    { "v3-12mo-20k",  "V3", 20000ULL * COIN,12*21900, 500000 },
    // large amount, max duration
    { "v3-12mo-100k", "V3",100000ULL * COIN,12*21900, 500000 },
    // user/regression: 21256 CCX × 11 mo → 1149.595264 CCX (1_149_595_264 atomic)
    { "v3-11mo-21256","V3", 21256ULL * COIN,11*21900, 500000 },

    // ---- V2i (quarterly investment: term % 64800 == 0; 64800 % 21900 != 0)  --
    // tier 1 (qTier=1.0, amount4Humans <= 110000)
    { "v2i-1q-50k",  "V2i",   50000ULL * COIN,  1*64800, 500000 },
    { "v2i-4q-50k",  "V2i",   50000ULL * COIN,  4*64800, 500000 },
    // tier 2 (180000–260000, qTier=1.02)
    { "v2i-2q-200k", "V2i",  200000ULL * COIN,  2*64800, 500000 },
    // tier 9 (950000–1100000, qTier=1.09)
    { "v2i-4q-1M",   "V2i", 1000000ULL * COIN,  4*64800, 500000 },
    // top tier (> 2000000, qTier=1.15)
    { "v2i-4q-3M",   "V2i", 3000000ULL * COIN,  4*64800, 500000 },

    // ---- V2w (weekly: term % 5040 == 0; 5040 is not a divisor of 64800)  -----
    { "v2w-1wk-50k",  "V2w",  50000ULL * COIN,  1*5040, 500000 },
    { "v2w-4wk-50k",  "V2w",  50000ULL * COIN,  4*5040, 500000 }, // expect ~140800000
    { "v2w-13wk-50k", "V2w",  50000ULL * COIN, 13*5040, 500000 },
    { "v2w-52wk-50k", "V2w",  50000ULL * COIN, 52*5040, 500000 },

    // ---- V1 (lockHeight <= 413400; term not divisible by 21900/64800/5040) ----
    // term=21900 % 5040 = 1740 ≠ 0, % 64800 ≠ 0; with lockHeight < DEPOSIT_HEIGHT_V3 → V1
    { "v1-mult-1k",   "V1",   1000ULL * COIN, 21900, 5000  }, // lockHeight <= 12750: 100× multiplier
    { "v1-nomult-1k", "V1",   1000ULL * COIN, 21900, 20000 }, // lockHeight > 12750: no multiplier
    { "v1-mult-10k",  "V1",  10000ULL * COIN, 21900, 5000  },
    { "v1-nomult-10k","V1",  10000ULL * COIN, 21900, 20000 },
};

// ---- JSON helpers ------------------------------------------------------------
static void print_escaped(const char *s) {
    while (*s) {
        if (*s == '"') printf("\\\"");
        else if (*s == '\\') printf("\\\\");
        else putchar(*s);
        ++s;
    }
}

int main() {
    int n = (int)(sizeof(CASES) / sizeof(CASES[0]));

    printf("{\n");
    printf("  \"source\": \"tools/interest-parity/gen_interest.cpp\",\n");
    printf("  \"cases\": [\n");

    for (int i = 0; i < n; ++i) {
        const Case &c = CASES[i];
        uint64_t expected = calculateInterest(c.amount, c.term, c.lockHeight);

        printf("    { \"id\": \"");
        print_escaped(c.id);
        printf("\", \"version\": \"%s\"", c.version);
        printf(", \"amount\": %llu", (unsigned long long)c.amount);
        printf(", \"term\": %u", c.term);
        printf(", \"lockHeight\": %u", c.lockHeight);
        printf(", \"expectedInterest\": %llu }", (unsigned long long)expected);
        if (i < n - 1) printf(",");
        printf("\n");
    }

    printf("  ]\n");
    printf("}\n");
    return 0;
}
