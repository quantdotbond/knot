#pragma once
// Deterministic random bit generator: a SHAKE256 stream keyed by a seed.
// Used for key generation, salts, and coin flips so runs are reproducible.
#include "shake.hpp"
#include "field.hpp"
#include <random>

namespace ccts {

class Drbg {
public:
    explicit Drbg(const std::vector<uint8_t>& seed, const std::string& domain = "CCTSv1|drbg") {
        xof_.absorb(domain);
        xof_.absorb_u32(uint32_t(seed.size()));
        xof_.absorb(seed);
        xof_.finalize();
    }

    static Drbg from_system_entropy() {
        std::random_device rd;
        std::vector<uint8_t> seed(32);
        for (auto& b : seed) b = uint8_t(rd());
        return Drbg(seed);
    }

    void fill(uint8_t* out, size_t len) { xof_.squeeze(out, len); }
    std::vector<uint8_t> bytes(size_t len) { return xof_.squeeze(len); }
    uint8_t byte() { uint8_t b; xof_.squeeze(&b, 1); return b; }
    bool bit() { return byte() & 1; }

    // Uniform in [0, bound) via rejection sampling on 16-bit draws (bound <= 65536).
    uint32_t uniform(uint32_t bound) {
        assert(bound >= 1 && bound <= 65536);
        const uint32_t limit = (65536 / bound) * bound;
        for (;;) {
            uint8_t b[2];
            xof_.squeeze(b, 2);
            uint32_t x = uint32_t(b[0]) | (uint32_t(b[1]) << 8);
            if (x < limit) return x % bound;
        }
    }

    uint32_t field_elem(const Field& F) { return uniform(F.q); }
    uint32_t nonzero_field_elem(const Field& F) { return 1 + uniform(F.q - 1); }

private:
    Shake256 xof_;
};

} // namespace ccts
