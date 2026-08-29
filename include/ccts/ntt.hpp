#pragma once
// Number-theoretic transform over the Goldilocks prime P = 2^64 - 2^32 + 1.
//
// Used as an exact integer convolution engine: products of polynomials over
// F_q (q < 2^16) are computed by lifting coefficients to Z, convolving mod P,
// and reducing mod q. Exactness holds because every convolution coefficient is
// bounded by n * (q-1)^2 < 2^48 for n <= 2^16, far below P ~ 1.8e19.
//
// P - 1 = 2^32 * (2^32 - 1), so radix-2 transforms exist up to length 2^32.
// 7 is a primitive root modulo P.
#include <cstdint>
#include <vector>
#include <cassert>

namespace ccts::ntt {

inline constexpr uint64_t P = 0xFFFFFFFF00000001ull; // 2^64 - 2^32 + 1
inline constexpr uint64_t PRIMITIVE_ROOT = 7;

inline uint64_t addP(uint64_t a, uint64_t b) {
    uint64_t s = a + b;
    if (s < a || s >= P) s -= P; // wrap or overflow both mean subtract P
    return s;
}
inline uint64_t subP(uint64_t a, uint64_t b) { return a >= b ? a - b : a + (P - b); }
inline uint64_t mulP(uint64_t a, uint64_t b) {
    return uint64_t((unsigned __int128)a * b % P);
}
inline uint64_t powP(uint64_t a, uint64_t e) {
    uint64_t acc = 1;
    while (e) {
        if (e & 1) acc = mulP(acc, a);
        a = mulP(a, a);
        e >>= 1;
    }
    return acc;
}
inline uint64_t invP(uint64_t a) { return powP(a, P - 2); }

// In-place iterative Cooley-Tukey NTT of power-of-two length.
inline void transform(std::vector<uint64_t>& a, bool invert) {
    const size_t n = a.size();
    assert(n && (n & (n - 1)) == 0);
    // bit-reversal permutation
    for (size_t i = 1, j = 0; i < n; i++) {
        size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(a[i], a[j]);
    }
    for (size_t len = 2; len <= n; len <<= 1) {
        uint64_t w = powP(PRIMITIVE_ROOT, (P - 1) / len);
        if (invert) w = invP(w);
        for (size_t i = 0; i < n; i += len) {
            uint64_t wn = 1;
            for (size_t j = 0; j < len / 2; j++) {
                uint64_t u = a[i + j], v = mulP(a[i + j + len / 2], wn);
                a[i + j] = addP(u, v);
                a[i + j + len / 2] = subP(u, v);
                wn = mulP(wn, w);
            }
        }
    }
    if (invert) {
        uint64_t ninv = invP(uint64_t(n));
        for (auto& x : a) x = mulP(x, ninv);
    }
}

// Exact convolution of nonnegative integer sequences (values < 2^16, total
// length <= 2^16, so coefficients < 2^48 < P: no wraparound).
inline std::vector<uint64_t> convolve(const std::vector<uint64_t>& a,
                                      const std::vector<uint64_t>& b) {
    if (a.empty() || b.empty()) return {};
    size_t rlen = a.size() + b.size() - 1, n = 1;
    while (n < rlen) n <<= 1;
    std::vector<uint64_t> fa(a.begin(), a.end()), fb(b.begin(), b.end());
    fa.resize(n, 0);
    fb.resize(n, 0);
    transform(fa, false);
    transform(fb, false);
    for (size_t i = 0; i < n; i++) fa[i] = mulP(fa[i], fb[i]);
    transform(fa, true);
    fa.resize(rlen);
    return fa;
}

} // namespace ccts::ntt
