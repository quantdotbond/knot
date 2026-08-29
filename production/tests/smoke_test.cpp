// KNOT smoke test: every public primitive operation, every mode, expected
// success and failure semantics. External to the core; uses the adapter.
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <cstring>

using namespace ccts;
using namespace knot_test;
using namespace knot_adapter;

int main() {
    for (const ParamSet& ps : ci_parameter_sets()) {
        const std::string name = param_set_name(ps);
        Drbg rng = TestOnlyDeterministicRng::from_label("smoke|" + name);
        Parameters p = make_params(ps);

        // keygen
        KeyPair kp = keygen(ps, rng);
        KCHECK(kp.pk.params.k == ps.k && kp.pk.params.q == p.q, (name + ": keygen parameters").c_str());
        KCHECK(kp.sk.pk_digest == kp.pk.digest, (name + ": sk binds pk digest").c_str());
        KCHECK(kp.pk.serialize().size() > 8, (name + ": pk serializes").c_str());
        KCHECK(kp.sk.serialize().size() > 8, (name + ": sk serializes").c_str());

        // sign / verify
        auto msg = bytes_of("KNOT smoke message");
        Signature s = sign(msg, kp.sk, rng);
        KCHECK(verify(msg, s, kp.pk), (name + ": sign/verify").c_str());

        // wire round trip through the adapter
        auto wire = signature_to_bytes(s, p, ps.mode);
        auto back = signature_from_bytes(wire, p, ps.mode);
        KCHECK(back.has_value(), (name + ": signature bytes parse").c_str());
        KCHECK(back && back->salt == s.salt && back->u == s.u && back->v == s.v,
               (name + ": signature bytes round-trip exactly").c_str());
        KCHECK(verify_bytes(msg, wire, kp.pk, ps.mode), (name + ": verify from bytes").c_str());

        // pk round trip
        auto pkb = kp.pk.serialize();
        auto pk2 = public_key_from_bytes(pkb);
        KCHECK(pk2.has_value(), (name + ": pk bytes parse").c_str());
        KCHECK(pk2 && pk2->digest == kp.pk.digest, (name + ": pk digest reproduced").c_str());
        KCHECK(pk2 && verify(msg, s, *pk2), (name + ": verify with deserialized pk").c_str());

        // modified message
        auto msg2 = msg; msg2[0] ^= 0x01;
        KCHECK(!verify(msg2, s, kp.pk), (name + ": modified message rejected").c_str());
        // invalid signature (bit flip in each component)
        Signature t = s; t.salt[3] ^= 0x80;
        KCHECK(!verify(msg, t, kp.pk), (name + ": flipped salt rejected").c_str());
        t = s; t.u[1] = Field(p.q).add(t.u[1], 1);
        KCHECK(!verify(msg, t, kp.pk), (name + ": modified u rejected").c_str());
        t = s; t.v[t.v.size() - 1] = Field(p.q).add(t.v[t.v.size() - 1], 1);
        KCHECK(!verify(msg, t, kp.pk), (name + ": modified v rejected").c_str());
        // wrong key
        Drbg rng2 = TestOnlyDeterministicRng::from_label("smoke-other|" + name);
        KeyPair other = keygen(ps, rng2);
        KCHECK(!verify(msg, s, other.pk), (name + ": wrong key rejected").c_str());
        // empty message signs and verifies
        std::vector<uint8_t> empty;
        Signature se = sign(empty, kp.sk, rng);
        KCHECK(verify(empty, se, kp.pk), (name + ": empty message").c_str());
        KCHECK(!verify(msg, se, kp.pk), (name + ": empty-message signature does not verify other message").c_str());
    }

    // Production entropy path (system randomness): exercised once, on one
    // parameter set, to prove the non-deterministic API works end to end.
    {
        Parameters p = Parameters::for_k(4);
        KeyPair kp = keygen(p);
        std::string m = "system entropy path";
        std::span<const std::byte> ms(reinterpret_cast<const std::byte*>(m.data()), m.size());
        Signature s = sign(ms, kp.sk);
        KCHECK(verify(ms, s, kp.pk), "system-entropy keygen/sign/verify");
        Signature s2 = sign(ms, kp.sk);
        KCHECK(s.salt != s2.salt, "system-entropy signatures use fresh salts");
    }
    return finish("smoke");
}
