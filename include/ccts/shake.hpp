#pragma once
// Self-contained SHAKE256 (FIPS 202). Streaming absorb / squeeze.
// Reference prototype code; not constant-time, not hardened.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <array>
#include <string>

namespace ccts {

class Shake256 {
public:
    Shake256() { reset(); }

    void reset() {
        std::memset(state_, 0, sizeof(state_));
        pt_ = 0;
        squeezing_ = false;
    }

    void absorb(const uint8_t* data, size_t len) {
        // absorbing after squeezing started is a usage error in this prototype
        for (size_t i = 0; i < len; i++) {
            reinterpret_cast<uint8_t*>(state_)[pt_++] ^= data[i];
            if (pt_ == RATE) { keccakf(state_); pt_ = 0; }
        }
    }
    void absorb(const std::vector<uint8_t>& v) { absorb(v.data(), v.size()); }
    void absorb(const std::string& s) {
        absorb(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    void absorb_u32(uint32_t x) {
        uint8_t b[4] = {uint8_t(x), uint8_t(x >> 8), uint8_t(x >> 16), uint8_t(x >> 24)};
        absorb(b, 4);
    }

    void finalize() {
        reinterpret_cast<uint8_t*>(state_)[pt_] ^= 0x1F;      // SHAKE domain pad
        reinterpret_cast<uint8_t*>(state_)[RATE - 1] ^= 0x80; // final bit
        keccakf(state_);
        pt_ = 0;
        squeezing_ = true;
    }

    void squeeze(uint8_t* out, size_t len) {
        if (!squeezing_) finalize();
        for (size_t i = 0; i < len; i++) {
            if (pt_ == RATE) { keccakf(state_); pt_ = 0; }
            out[i] = reinterpret_cast<uint8_t*>(state_)[pt_++];
        }
    }
    std::vector<uint8_t> squeeze(size_t len) {
        std::vector<uint8_t> out(len);
        squeeze(out.data(), len);
        return out;
    }

    static std::array<uint8_t, 32> digest32(const std::vector<uint8_t>& data) {
        Shake256 x;
        x.absorb(data);
        std::array<uint8_t, 32> out{};
        x.squeeze(out.data(), 32);
        return out;
    }

private:
    static constexpr size_t RATE = 136; // SHAKE256 rate in bytes
    uint64_t state_[25];
    size_t pt_;
    bool squeezing_;

    static inline uint64_t rotl64(uint64_t x, int s) {
        return (x << s) | (x >> (64 - s));
    }

    static void keccakf(uint64_t st[25]) {
        static const uint64_t RC[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
            0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
            0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
            0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
            0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
        static const int ROTC[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                                     27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
        static const int PILN[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                                     15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
        uint64_t bc[5], t;
        for (int round = 0; round < 24; round++) {
            // Theta
            for (int i = 0; i < 5; i++)
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
            }
            // Rho + Pi
            t = st[1];
            for (int i = 0; i < 24; i++) {
                int j = PILN[i];
                bc[0] = st[j];
                st[j] = rotl64(t, ROTC[i]);
                t = bc[0];
            }
            // Chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) bc[i] = st[j + i];
                for (int i = 0; i < 5; i++)
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
            // Iota
            st[0] ^= RC[round];
        }
    }
};

} // namespace ccts
