// ADAPTER BOUNDARY: dense signature parsing + verify against a fixed key.
// Never crashes; accepted encodings re-serialize identically; verify on a
// random encoding must be false with overwhelming probability - an accept is
// reported as a violation (a forgery from fuzz input would be a real finding).
#include "fuzz_common.hpp"

static const knot_fuzz::FixedKey& key() {
    static knot_fuzz::FixedKey k({ccts::Mode::chord_structured, 8});
    return k;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto& K = key();
    auto bytes = knot_fuzz::to_vec(data, size);
    auto s = knot_adapter::signature_from_bytes_dense(bytes, K.p);
    if (!s) return 0;
    if (s->serialize() != bytes) knot_fuzz::violation("accepted dense signature does not re-serialize to the input");
    std::vector<uint8_t> msg = {'f', 'u', 'z', 'z'};
    if (ccts::verify(msg, *s, K.kp.pk)) knot_fuzz::violation("random dense signature verified (forgery?)");
    return 0;
}
