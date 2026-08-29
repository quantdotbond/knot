// RAW CORE BOUNDARY: ccts::deserialize_signature_packed on arbitrary bytes
// with fixed tri_chord parameters. Exceptions count as clean rejection.
#include "fuzz_common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const ccts::Parameters p = ccts::Parameters::for_k_tri(8);
    auto bytes = knot_fuzz::to_vec(data, size);
    try {
        ccts::Signature s = ccts::deserialize_signature_packed(bytes, p);
        (void)s;
    } catch (const std::exception&) {
        return 0; // clean rejection (std::out_of_range from .at())
    }
    return 0;
}
