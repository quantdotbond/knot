#pragma once
// =============================================================================
//  TEST-ONLY DETERMINISTIC ENTROPY  --  NEVER USE IN PRODUCTION
// =============================================================================
//
// The KNOT core (include/ccts/) exposes every randomized operation with an
// explicit `ccts::Drbg&` parameter and provides the production entropy path
// separately (`ccts::Drbg::from_system_entropy()`, used by the span-based
// keygen/sign overloads). That design lets the test layer inject reproducible
// entropy WITHOUT modifying the core: a `ccts::Drbg` constructed from a fixed
// seed is a deterministic SHAKE256 stream.
//
// This header is the only sanctioned way for tests, KAT generators, fuzzers,
// benchmarks and side-channel harnesses to obtain deterministic entropy.
//
//   * The type name and the factory names contain "TestOnly" so a reviewer can
//     grep for every deterministic-entropy site (`grep -rn TestOnly`).
//   * Seeds are derived from human-readable labels. Labels used by the
//     versioned KAT corpus are frozen (see vectors/knot-kat-v1.txt); changing
//     them changes the expected vectors.
//   * Nothing here touches ccts::Drbg::from_system_entropy(). The production
//     randomness implementation is untouched and unwrapped.
//
// Deterministic seeds committed to this repository are non-secret test
// material. They must never be used to generate keys that protect anything.
#include "ccts/rng.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace knot_test {

// A deterministic ccts::Drbg for tests. Constructed from a label string; the
// seed bytes are exactly the label bytes (this matches the convention used by
// the repository's original generator, tests/gen_vectors.cpp, so the existing
// vectors/kat.txt corpus is reproducible through this adapter).
struct TestOnlyDeterministicRng {
    static ccts::Drbg from_label(const std::string& label) {
        return ccts::Drbg(std::vector<uint8_t>(label.begin(), label.end()));
    }
    static ccts::Drbg from_seed_bytes(const std::vector<uint8_t>& seed) {
        return ccts::Drbg(seed);
    }
    // Derive a fresh deterministic stream from (label, index) for randomized
    // repetition (round-trip and property tests).
    static ccts::Drbg from_label_indexed(const std::string& label, uint64_t index) {
        return from_label(label + "#" + std::to_string(index));
    }
};

} // namespace knot_test
