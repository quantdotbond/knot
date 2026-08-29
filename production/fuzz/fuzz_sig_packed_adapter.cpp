// ADAPTER BOUNDARY: packed (tri_chord) signature parsing + verify against a
// fixed key. Canonical encodings only; accepted inputs re-serialize identically.
#include "fuzz_common.hpp"

static const knot_fuzz::FixedKey& key() {
    static knot_fuzz::FixedKey k({ccts::Mode::tri_chord, 8});
    return k;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto& K = key();
    auto bytes = knot_fuzz::to_vec(data, size);
    auto s = knot_adapter::signature_from_bytes_packed(bytes, K.p);
    if (!s) return 0;
    if (ccts::serialize_signature_packed(*s, K.p) != bytes)
        knot_fuzz::violation("accepted packed signature does not re-serialize to the input");
    std::vector<uint8_t> msg = {'f', 'u', 'z', 'z'};
    if (ccts::verify(msg, *s, K.kp.pk)) knot_fuzz::violation("random packed signature verified (forgery?)");
    return 0;
}
