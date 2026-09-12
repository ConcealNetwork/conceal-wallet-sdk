// gen_m8.cpp — Generate float32 m8 investment values matching Currency.cpp
// Compile: g++ -O0 -o gen_m8 gen_m8.cpp -lm
// Run:     ./gen_m8
//
// Reproduces the exact C++ fragment from conceal-core/src/CryptoNoteCore/Currency.cpp:
//   auto mq = static_cast<float>(1.4473);
//   float termQuarters = term / 64800;   // integer division → then to float
//   auto m8 = (float)(100.0 * pow(1.0 + (mq / 100.0), termQuarters) - 100.0);
//
// DEPOSIT_MAX_TERM_V1 = 64800 * 20, so termQuarters runs 1..20.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

int main() {
    auto mq = static_cast<float>(1.4473);

    printf("quarter,m8_decimal,m8_hex\n");
    for (int q = 1; q <= 20; ++q) {
        // Exactly as in Currency.cpp: integer arithmetic first, then widen to float
        int term = q * 64800;
        float termQuarters = static_cast<float>(term / 64800);  // integer div → float
        auto m8 = static_cast<float>(100.0 * pow(1.0 + (mq / 100.0), termQuarters) - 100.0);

        uint32_t bits = 0;
        std::memcpy(&bits, &m8, sizeof(bits));

        printf("%d,%.10g,0x%08X\n", q, static_cast<double>(m8), bits);
    }
    return 0;
}
