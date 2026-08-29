// DIFFERENTIAL: naive vs fast polynomial backend of the preimage sampler on
// fuzz-generated (Lambda, target, coin). Both must agree on success and on
// every output byte, and the preimage must hit the target.
// Layout: [k][coin][bytes seeding a DRBG for Lambda and the target]
#include "fuzz_common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    uint32_t k = 1 + data[0] % 40;
    bool coin = data[1] & 1;
    ccts::Parameters p = ccts::Parameters::for_k(k);
    ccts::Field F(p.q);
    const uint32_t n1 = 2 * k + 1;
    ccts::Drbg rng = knot_test::TestOnlyDeterministicRng::from_seed_bytes(knot_fuzz::to_vec(data + 2, size - 2));
    ccts::Vec c2 = ccts::distinct_column(F, n1, rng), c3 = ccts::distinct_column(F, n1, rng);
    ccts::Vec y0(n1, 0);
    ccts::Vec perm = ccts::random_permutation(n1, rng);
    uint32_t weight = (data[1] >> 1) & 1 ? k + 1 : rng.uniform(n1 + 1); // on-sphere or arbitrary weight
    for (uint32_t t = 0; t < weight && t < n1; t++) y0[perm[t]] = rng.nonzero_field_elem(F);
    ccts::Vec a2, a3, b2, b3;
    bool okn = ccts::vwz_preimage(F, k, c2, c3, y0, coin, a2, a3, ccts::PolyBackend::naive);
    bool okf = ccts::vwz_preimage(F, k, c2, c3, y0, coin, b2, b3, ccts::PolyBackend::fast);
    if (okn != okf) knot_fuzz::violation("backends disagree on success");
    if (okn) {
        if (a2 != b2 || a3 != b3) knot_fuzz::violation("backends disagree on the preimage");
        ccts::Tensor3 phi = ccts::build_vwz(F, k, c2, c3);
        if (ccts::tensor_eval(F, phi, a2, a3) != y0) knot_fuzz::violation("preimage misses the target");
    } else if (ccts::hamming_weight(y0) == k + 1) {
        knot_fuzz::violation("on-sphere target rejected");
    }
    return 0;
}
