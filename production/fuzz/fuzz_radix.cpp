// Serialization primitives: radix (base-q) coding and fixed-width bit
// packing must be exact bijections for every q in the prototype range.
// Layout: [q lo][q hi][n][values as bytes, each reduced mod q]
#include "fuzz_common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) return 0;
    uint32_t q = uint32_t(data[0]) | uint32_t(data[1]) << 8;
    if (q < 2) return 0;
    size_t n = data[2];
    ccts::Vec v(n);
    for (size_t i = 0; i < n; i++) v[i] = (i + 3 < size ? data[i + 3] * 257u : 0u) % q;
    auto packed = ccts::radix_pack(v, q);
    if (packed.size() != ccts::radix_len(q, n)) knot_fuzz::violation("radix payload length");
    if (ccts::radix_unpack(packed, q, n) != v) knot_fuzz::violation("radix round-trip");
    const uint32_t b = ccts::elem_bits(q);
    ccts::BitWriter bw;
    for (auto e : v) bw.bits(e, b);
    auto buf = bw.finish();
    if (buf.size() != (n * b + 7) / 8) knot_fuzz::violation("bit-packed length");
    ccts::BitReader br(buf);
    for (auto e : v) if (br.bits(b) != e) knot_fuzz::violation("bit-pack round-trip");
    return 0;
}
