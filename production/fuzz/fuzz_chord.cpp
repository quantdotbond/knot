// Chord-diagram layer on arbitrary match arrays. The core documents valid()
// as the precondition for every other method; the fuzzer honours it: only
// diagrams that pass valid() are exercised further, and their rotation
// invariants must hold. Layout: [match bytes (2m of them)] [is_tail bytes (2m)]
#include "fuzz_common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4 || size > 64) return 0;
    size_t m2 = size / 2; // endpoints
    ccts::OrientedChordDiagram D;
    D.base.match.assign(data, data + m2);
    D.is_tail.assign(data + m2, data + 2 * m2);
    for (auto& t : D.is_tail) t &= 1;
    if (!D.base.valid()) return 0;
    auto canon = D.base.canonical_sequence();
    uint32_t loops = D.base.closure_loops();
    uint32_t orbit = D.base.orbit_size();
    if (D.base.endpoints() % orbit != 0) knot_fuzz::violation("orbit size does not divide 2n");
    for (uint32_t r = 1; r < D.base.endpoints(); r++) {
        auto R = D.base.rotated(r);
        if (!R.valid()) knot_fuzz::violation("rotation breaks validity");
        if (R.canonical_sequence() != canon) knot_fuzz::violation("canonical form not rotation-invariant");
        if (R.closure_loops() != loops) knot_fuzz::violation("closure loops not rotation-invariant");
    }
    if (D.valid()) {
        auto oc = D.canonical_sequence();
        if (D.rotated(1).canonical_sequence() != oc) knot_fuzz::violation("oriented canonical form not rotation-invariant");
        (void)D.chord_list();
        if (D.chords() >= 2) (void)ccts::census_digest(D, 2); // documented precondition: degree <= chords
    }
    return 0;
}
