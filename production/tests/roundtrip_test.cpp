// KNOT round-trip property tests: Verify(pk, m, Sign(sk, m)) == true across
// parameter sets, keys, message lengths and both polynomial backends, plus
// serialization round trips. Randomized via the deterministic test RNG so a
// failure is reproducible from (parameter set, iteration).
//   KNOT_ITER=<n>      iterations per parameter set (default 20)
//   KNOT_EXTENDED=1    use the extended parameter sets (nightly)
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <cstdlib>

using namespace ccts;
using namespace knot_test;
using namespace knot_adapter;

int main() {
    const int iters = int(env_long("KNOT_ITER", 20));
    const bool ext = env_flag("KNOT_EXTENDED");
    auto sets = ext ? extended_parameter_sets() : ci_parameter_sets();
    for (const ParamSet& ps : sets) {
        const std::string name = param_set_name(ps);
        Parameters p = make_params(ps);
        Field F(p.q);
        KeyPair kp;
        std::vector<uint8_t> pk_bytes;
        std::optional<PublicKey> pk_rt;
        for (int it = 0; it < iters; it++) {
            Drbg rng = TestOnlyDeterministicRng::from_label_indexed("roundtrip|" + name, uint64_t(it));
            if (it % 5 == 0) { // fresh key every 5 iterations
                kp = keygen(ps, rng);
                pk_bytes = kp.pk.serialize();
                pk_rt = public_key_from_bytes(pk_bytes);
                KCHECK(pk_rt.has_value(), (name + ": pk parses").c_str());
                KCHECK(pk_rt && pk_rt->serialize() == pk_bytes, (name + ": pk serialization is a bijection").c_str());
                KCHECK(pk_rt && pk_rt->digest == kp.pk.digest, (name + ": pk digest stable through bytes").c_str());
            }
            // message of random length in [0, 300]
            uint32_t len = rng.uniform(301);
            std::vector<uint8_t> msg = rng.bytes(len);
            // Both backends from an identical DRBG state must give identical signatures.
            Drbg rng_naive = rng, rng_fast = rng;
            Signature s = sign(msg.data(), msg.size(), kp.sk, rng_naive, nullptr, PolyBackend::naive);
            Signature sf = sign(msg.data(), msg.size(), kp.sk, rng_fast, nullptr, PolyBackend::fast);
            KCHECK(s.serialize() == sf.serialize(), (name + ": naive/fast backend signatures identical").c_str());
            rng = rng_naive; // continue from the advanced state
            KCHECK(verify(msg, s, kp.pk), (name + ": verify(sign) == true").c_str());
            KCHECK(pk_rt && verify(msg, s, *pk_rt), (name + ": verifies with re-parsed pk").c_str());
            // canonical projective form of the signature components
            auto canonical = [&](const Vec& v) { size_t i = 0; while (i < v.size() && v[i] == 0) i++; return i < v.size() && v[i] == 1; };
            KCHECK(canonical(s.u) && canonical(s.v), (name + ": u, v canonical").c_str());
            KCHECK(s.salt.size() == SALT_BYTES, (name + ": salt length").c_str());
            // wire round trip
            auto wire = signature_to_bytes(s, p, ps.mode);
            auto back = signature_from_bytes(wire, p, ps.mode);
            KCHECK(back && back->salt == s.salt && back->u == s.u && back->v == s.v,
                   (name + ": signature wire round-trip").c_str());
            KCHECK(back && signature_to_bytes(*back, p, ps.mode) == wire, (name + ": signature encoding is a bijection").c_str());
            // repeated signatures on the same message differ (fresh salt) and all verify
            Signature s2 = sign(msg, kp.sk, rng);
            KCHECK(s2.salt != s.salt, (name + ": fresh salt per signature").c_str());
            KCHECK(verify(msg, s2, kp.pk), (name + ": second signature verifies").c_str());
        }
    }
    return finish(ext ? "roundtrip-extended" : "roundtrip");
}
