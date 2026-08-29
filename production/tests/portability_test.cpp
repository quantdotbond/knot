// KNOT portability invariants: checks that are sensitive to word size,
// endianness and integer promotion. Run natively and under emulation
// (32-bit, big-endian) by scripts/ci.sh; the KAT suite provides the
// end-to-end byte-for-byte evidence, this file pins the primitives.
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <climits>
#include <bit>

using namespace ccts;
using namespace knot_test;
using namespace knot_adapter;

int main() {
    std::printf("sizeof(void*)=%zu sizeof(long)=%zu sizeof(size_t)=%zu big_endian=%d\n",
                sizeof(void*), sizeof(long), sizeof(size_t),
                int(std::endian::native == std::endian::big));
    // SHAKE256 known answers (NIST CAVP examples): output must not depend on host byte order.
    {
        Shake256 x; auto o = x.squeeze(32);
        KCHECK(hex(o) == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f", "SHAKE256('') KAT");
        Shake256 y; y.absorb(std::string("abc")); auto o2 = y.squeeze(32);
        KCHECK(hex(o2) == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739", "SHAKE256('abc') KAT");
        // Streaming absorb in two pieces equals one-shot absorb.
        Shake256 z1, z2; std::vector<uint8_t> a3(200, 0xa3);
        z1.absorb(a3); z2.absorb(a3.data(), 137); z2.absorb(a3.data() + 137, 63);
        KCHECK(z1.squeeze(64) == z2.squeeze(64), "SHAKE256 streaming absorb across the rate boundary");
    }
    // Serialization is little-endian regardless of host.
    {
        ByteWriter w; w.u32(0x04030201u); w.u16(0x0605u); w.elem(0x0807u);
        KCHECK(w.buf == std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8}), "ByteWriter little-endian layout");
        ByteReader r(w.buf);
        KCHECK(r.u32() == 0x04030201u && r.u16() == 0x0605u && r.elem() == 0x0807u, "ByteReader little-endian");
        BitWriter bw; bw.bits(0b101, 3); bw.bits(0b11, 2); bw.bits(0x1ff, 9);
        KCHECK(bw.finish() == std::vector<uint8_t>({0xfd, 0x3f}), "BitWriter LSB-first layout");
        KCHECK(radix_pack({1, 2, 3}, 7) == std::vector<uint8_t>({uint8_t(1 + 2 * 7 + 3 * 49), 0}), "radix_pack known answer");
        KCHECK(radix_len(2053, 514) == 707, "radix_len(2053,514)");
    }
    // Field arithmetic at the top of the prototype range (no 32-bit overflow).
    {
        Field F(65521);
        KCHECK(F.mul(65520, 65520) == 1, "(-1)*(-1) == 1 in F_65521");
        KCHECK(F.mul(F.inv(12345), 12345) == 1, "inverse at large q");
        KCHECK(F.pow(3, 65520) == 1, "Fermat at large q");
        KCHECK(ntt::mulP(ntt::P - 1, ntt::P - 1) == 1, "Goldilocks (-1)^2 == 1");
        KCHECK(ntt::addP(ntt::P - 1, 1) == 0, "Goldilocks wrap");
        auto c = ntt::convolve({65520, 65520}, {65520, 65520});
        KCHECK((c == std::vector<uint64_t>{uint64_t(65520) * 65520, 2 * uint64_t(65520) * 65520, uint64_t(65520) * 65520}),
               "exact integer convolution of 16-bit values");
    }
    // Digest of a fixed key is the recorded one (end-to-end byte-order check;
    // value is the tensor_reference/k=4 vector of vectors/kat.txt).
    {
        Drbg rng = TestOnlyDeterministicRng::from_label("CCTS-KAT-seed-A");
        KeyPair kp = keygen(Parameters::for_k(4), rng, Mode::tensor_reference);
        KCHECK(hex(kp.pk.digest) == "02e47deb52e18ba8fbb1efa715a4a270808c596a9d00e0689a5faa73c901b862",
               "tensor_reference/k=4 pk digest matches the corpus on this host");
    }
    return finish("portability");
}
