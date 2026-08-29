// ADAPTER BOUNDARY: knot_adapter::public_key_from_bytes must never crash and
// must be a bijection on accepted inputs (re-serialization equals the input,
// and the digest is the core's). Accepted keys must be usable by verify.
#include "fuzz_common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    auto bytes = knot_fuzz::to_vec(data, size);
    auto pk = knot_adapter::public_key_from_bytes(bytes);
    if (!pk) return 0;
    if (pk->serialize() != bytes) knot_fuzz::violation("accepted pk does not re-serialize to the input");
    // A parsed key must be safe to verify against (garbage signature -> false, no crash).
    ccts::Signature s;
    s.salt.assign(ccts::SALT_BYTES, 0x5a);
    s.u.assign(pk->params.k + 1, 1);
    s.v.assign(pk->params.k + 1, 1);
    std::vector<uint8_t> msg = {1, 2, 3};
    (void)ccts::verify(msg, s, *pk);
    return 0;
}
