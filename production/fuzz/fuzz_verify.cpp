// verify(message, signature) on fuzzed (message, wire signature) pairs for
// every CI parameter set (selected by the first byte). Layout:
//   [0] parameter-set index  [1..2] message length (LE)  [message]  [signature bytes]
// Never crashes. Accepted-and-verifying inputs are violations unless the
// signature is the fixed key's own signature on that message (unreachable by
// mutation with overwhelming probability).
#include "fuzz_common.hpp"

static const std::vector<knot_fuzz::FixedKey>& keys() {
    static std::vector<knot_fuzz::FixedKey> v = [] {
        std::vector<knot_fuzz::FixedKey> out;
        for (auto ps : knot_adapter::ci_parameter_sets()) out.emplace_back(ps);
        return out;
    }();
    return v;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) return 0;
    const auto& K = keys()[data[0] % keys().size()];
    size_t mlen = size_t(data[1]) | size_t(data[2]) << 8;
    if (3 + mlen > size) return 0;
    std::vector<uint8_t> msg(data + 3, data + 3 + mlen);
    std::vector<uint8_t> sig(data + 3 + mlen, data + size);
    if (knot_adapter::verify_bytes(msg, sig, K.kp.pk, K.ps.mode))
        knot_fuzz::violation("fuzzed (message, signature) verified");
    return 0;
}
