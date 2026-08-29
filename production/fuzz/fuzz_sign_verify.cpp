// Message boundary: sign(data) with a deterministic DRBG derived from the
// input, then verify. The property Verify(Sign(m)) == true must hold for
// every message; the wire encoding must round-trip through the adapter.
// Parameter set chosen by the first byte (k=4 sets only, for throughput).
#include "fuzz_common.hpp"

static const std::vector<knot_fuzz::FixedKey>& keys() {
    static std::vector<knot_fuzz::FixedKey> v = [] {
        std::vector<knot_fuzz::FixedKey> out;
        using M = ccts::Mode;
        for (auto ps : {knot_adapter::ParamSet{M::tensor_reference, 4}, {M::chord_tensor, 4},
                        {M::chord_structured, 4}, {M::chord_labeled, 4}, {M::tri_chord, 8}})
            out.emplace_back(ps);
        return out;
    }();
    return v;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    const auto& K = keys()[data[0] % keys().size()];
    std::vector<uint8_t> msg(data + 1, data + size);
    ccts::Drbg rng = knot_test::TestOnlyDeterministicRng::from_seed_bytes(msg);
    ccts::Signature s = ccts::sign(msg, K.kp.sk, rng);
    if (!ccts::verify(msg, s, K.kp.pk)) knot_fuzz::violation("Verify(Sign(m)) == false");
    auto wire = knot_adapter::signature_to_bytes(s, K.p, K.ps.mode);
    if (!knot_adapter::verify_bytes(msg, wire, K.kp.pk, K.ps.mode))
        knot_fuzz::violation("wire signature does not verify");
    std::vector<uint8_t> other = msg; other.push_back(0);
    if (ccts::verify(other, s, K.kp.pk)) knot_fuzz::violation("signature verified an extended message");
    return 0;
}
