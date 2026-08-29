#pragma once
// Shared scaffolding for KNOT fuzz targets. Each target defines
// LLVMFuzzerTestOneInput; it links either with libFuzzer (clang
// -fsanitize=fuzzer) or with standalone_driver.cpp (any compiler).
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace knot_fuzz {

inline std::vector<uint8_t> to_vec(const uint8_t* d, size_t n) { return std::vector<uint8_t>(d, d + n); }

// A property violation inside a fuzz target is reported by aborting, which
// libFuzzer and the standalone driver both treat as a crash.
[[noreturn]] inline void violation(const char* what) {
    std::fprintf(stderr, "FUZZ PROPERTY VIOLATION: %s\n", what);
    std::abort();
}

// Fixed key material per parameter set, built once per process from the
// deterministic test RNG (test-only material).
struct FixedKey {
    knot_adapter::ParamSet ps;
    ccts::Parameters p;
    ccts::KeyPair kp;
    explicit FixedKey(knot_adapter::ParamSet set) : ps(set), p(knot_adapter::make_params(set)) {
        ccts::Drbg rng = knot_test::TestOnlyDeterministicRng::from_label(
            "fuzz-fixed-key|" + knot_adapter::param_set_name(set));
        kp = knot_adapter::keygen(set, rng);
    }
};

} // namespace knot_fuzz
