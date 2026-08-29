// KNOT implementation-variant parity
//
// The repository contains ONE portable implementation with two polynomial
// backends for the preimage sampler (naive O(k^2) in poly.hpp; fast NTT-based
// in fastpoly.hpp/ntt.hpp) selected by PolyBackend. The specification requires
// the interpolant to be unique, so the two backends must produce bit-identical
// preimages and signatures. This test establishes that parity on deterministic
// vectors, boundary targets and a randomized corpus, in every mode.
// (Cross-binary parity - debug vs release, GCC vs Clang, x86-64 vs emulated
// architectures - is established by running kat_test in each build; see
// scripts/ci.sh.)
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <cstdlib>

using namespace ccts;
using namespace knot_test;
using namespace knot_adapter;

int main() {
    const bool ext = env_flag("KNOT_EXTENDED");
    // 1. Scheme level: identical DRBG state -> identical signature bytes.
    for (const ParamSet& ps : (ext ? extended_parameter_sets() : ci_parameter_sets())) {
        const std::string name = param_set_name(ps);
        Parameters p = make_params(ps);
        Drbg rng = TestOnlyDeterministicRng::from_label("parity|" + name);
        KeyPair kp = keygen(ps, rng);
        for (int it = 0; it < (ext ? 40 : 10); it++) {
            auto msg = rng.bytes(rng.uniform(128));
            Drbg a = rng, b = rng;
            Signature sn = sign(msg.data(), msg.size(), kp.sk, a, nullptr, PolyBackend::naive);
            Signature sf = sign(msg.data(), msg.size(), kp.sk, b, nullptr, PolyBackend::fast);
            KCHECK(sn.serialize() == sf.serialize(), (name + ": naive == fast signature bytes").c_str());
            KCHECK(verify(msg, sf, kp.pk), (name + ": fast-backend signature verifies").c_str());
            rng = a; // advance
        }
    }
    // 2. Sampler level on boundary targets: weight-(k+1) targets with the
    //    support at the extremes, both coins, several field sizes including
    //    the largest 16-bit prime.
    for (uint32_t k : {1u, 2u, 3u, 8u, 31u, 64u, 127u, 300u}) {
        for (uint32_t q : {next_prime_above(4 * k), 65521u}) {
            Field F(q);
            const uint32_t n1 = 2 * k + 1;
            Drbg rng = TestOnlyDeterministicRng::from_label("parity-sampler|k=" + std::to_string(k) + "|q=" + std::to_string(q));
            Vec c2 = distinct_column(F, n1, rng), c3 = distinct_column(F, n1, rng);
            std::vector<Vec> targets;
            Vec lo(n1, 0), hi(n1, 0), alt(n1, 0);
            for (uint32_t i = 0; i < k + 1; i++) { lo[i] = 1; hi[n1 - 1 - i] = q - 1; }
            for (uint32_t i = 0, c = 0; i < n1 && c < k + 1; i += 2, c++) alt[i] = 1 + (i % (q - 1));
            targets = {lo, hi, alt};
            for (int r = 0; r < 3; r++) {
                Vec y(n1, 0);
                Vec perm = random_permutation(n1, rng);
                for (uint32_t t = 0; t < k + 1; t++) y[perm[t]] = rng.nonzero_field_elem(F);
                targets.push_back(y);
            }
            for (auto& y0 : targets)
                for (int coin = 0; coin < 2; coin++) {
                    Vec a2, a3, b2, b3;
                    bool okn = vwz_preimage(F, k, c2, c3, y0, coin, a2, a3, PolyBackend::naive);
                    bool okf = vwz_preimage(F, k, c2, c3, y0, coin, b2, b3, PolyBackend::fast);
                    KCHECK(okn && okf, "both backends find a preimage");
                    KCHECK(a2 == b2 && a3 == b3, ("k=" + std::to_string(k) + " q=" + std::to_string(q) + ": preimages bit-identical").c_str());
                    if (k <= 64) {
                        Tensor3 phi = build_vwz(F, k, c2, c3);
                        KCHECK(tensor_eval(F, phi, b2, b3) == y0, "preimage hits the target");
                    }
                }
            // Off-sphere target: both backends must agree on rejection.
            Vec bad(n1, 1);
            Vec x2, x3;
            KCHECK(!vwz_preimage(F, k, c2, c3, bad, false, x2, x3, PolyBackend::naive) &&
                   !vwz_preimage(F, k, c2, c3, bad, false, x2, x3, PolyBackend::fast),
                   "both backends reject an off-sphere target");
        }
    }
    // 3. Serialization variants: the dense and packed signature encodings of
    //    the same signature decode to the same (salt, u, v) and both verify.
    {
        ParamSet ps{Mode::tri_chord, 8};
        Parameters p = make_params(ps);
        Drbg rng = TestOnlyDeterministicRng::from_label("parity-serialization");
        KeyPair kp = keygen(ps, rng);
        for (int it = 0; it < 10; it++) {
            auto msg = rng.bytes(40);
            Signature s = sign(msg, kp.sk, rng);
            auto dense = signature_from_bytes_dense(s.serialize(), p);
            auto packed = signature_from_bytes_packed(serialize_signature_packed(s, p), p);
            KCHECK(dense && packed && dense->u == packed->u && dense->v == packed->v && dense->salt == packed->salt,
                   "dense and packed signature encodings agree");
            KCHECK(dense && verify(msg, *dense, kp.pk) && packed && verify(msg, *packed, kp.pk),
                   "both decoded signatures verify");
        }
        // TRI packed pk vs the dense tensor it restricts: published slices equal fx (x) fy.
        Field F(p.q);
        Tensor3 phi = build_vwz(F, p.k, kp.sk.c2, kp.sk.c3);
        Mat X1 = monomial_matrix(2 * p.k + 1, kp.sk.x1_perm, kp.sk.x1_diag);
        Tensor3 psi = twist(F, phi, X1, kp.sk.X2, kp.sk.X3);
        bool ok = true;
        for (uint32_t idx = 0; idx < p.sup.t; idx++)
            for (uint32_t b = 0; b < p.k + 1; b++)
                for (uint32_t c = 0; c < p.k + 1; c++)
                    ok = ok && psi.at(kp.pk.sup.I[idx], b, c) == F.mul(kp.pk.fx[idx][b], kp.pk.fy[idx][c]);
        KCHECK(ok, "TRI factored public key equals the restriction of the dense tensor");
    }
    return finish(ext ? "parity-extended" : "parity");
}
