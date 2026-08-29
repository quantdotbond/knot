// RAW CORE BOUNDARY: ccts::PublicKey::deserialize on arbitrary bytes.
// The core parser is documented to accept both framings; it is not
// documented to validate lengths. This target exists to make the core's
// behaviour on malformed encodings visible (findings KNOT-CORE-002/-005).
// Exceptions (std::out_of_range from .at()) count as clean rejection.
// The only fuzz-side restriction: k in the header is capped so a hostile
// header cannot request a multi-gigabyte tensor before the parser runs
// (that allocation behaviour is itself finding KNOT-CORE-005).
#include "fuzz_common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size >= 4) {
        uint32_t k = uint32_t(data[0]) | uint32_t(data[1]) << 8 | uint32_t(data[2]) << 16 | uint32_t(data[3]) << 24;
        if (k > 64) return 0;
    }
    auto bytes = knot_fuzz::to_vec(data, size);
    try {
        ccts::PublicKey pk = ccts::PublicKey::deserialize(bytes);
        (void)pk.serialize();
    } catch (const std::exception&) {
        return 0; // clean rejection (std::out_of_range / std::bad_alloc)
    }
    return 0;
}
