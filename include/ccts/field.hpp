#pragma once
// Prime field F_q arithmetic, q < 2^16 (prototype range).
#include <cstdint>
#include <cassert>

namespace ccts {

struct Field {
    uint32_t q;

    explicit Field(uint32_t q_) : q(q_) { assert(q >= 3); }

    uint32_t add(uint32_t a, uint32_t b) const {
        uint32_t s = a + b;
        return s >= q ? s - q : s;
    }
    uint32_t sub(uint32_t a, uint32_t b) const { return a >= b ? a - b : a + q - b; }
    uint32_t neg(uint32_t a) const { return a == 0 ? 0 : q - a; }
    uint32_t mul(uint32_t a, uint32_t b) const {
        return uint32_t((uint64_t(a) * b) % q);
    }
    uint32_t pow(uint32_t a, uint64_t e) const {
        uint64_t base = a % q, acc = 1;
        while (e) {
            if (e & 1) acc = (acc * base) % q;
            base = (base * base) % q;
            e >>= 1;
        }
        return uint32_t(acc);
    }
    // q prime: Fermat inverse.
    uint32_t inv(uint32_t a) const {
        assert(a % q != 0);
        return pow(a, q - 2);
    }
};

inline bool is_prime(uint32_t n) {
    if (n < 2) return false;
    for (uint32_t d = 2; uint64_t(d) * d <= n; d++)
        if (n % d == 0) return false;
    return true;
}

// Smallest prime strictly greater than n.
inline uint32_t next_prime_above(uint32_t n) {
    uint32_t c = n + 1;
    while (!is_prime(c)) c++;
    return c;
}

} // namespace ccts
