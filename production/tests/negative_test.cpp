// KNOT negative tests: explicit rejection behaviour for malformed and
// adversarial inputs at the public boundaries (verify, signature parsing,
// public-key parsing). Expectations are derived from the documented API
// (scheme.hpp comments, project README), not assumed.
//
// Behaviours that the current core exhibits but that a production verifier
// should not are recorded as KNOWN DEVIATIONS: they are asserted with
// KNOWN_DEVIATION(...) so that (a) the deviation is exercised on every run and
// (b) if the core is ever changed to reject them, the test reports XPASS and
// forces the registry (metadata/findings/) to be updated. They never count as
// passes in the summary.
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"

using namespace ccts;
using namespace knot_test;
using namespace knot_adapter;

static int g_known = 0, g_xpass = 0;
// `still_deviates` must be true while the finding is open.
static void known_deviation(bool still_deviates, const char* finding, const char* what) {
    if (still_deviates) { g_known++; return; }
    g_xpass++;
    std::printf("XPASS: %s no longer reproduces (%s) - update metadata/findings and this test\n", finding, what);
}
#define KNOWN_DEVIATION(cond, finding, what) known_deviation((cond), (finding), (what))

int main() {
    for (const ParamSet& ps : ci_parameter_sets()) {
        const std::string name = param_set_name(ps);
        Parameters p = make_params(ps);
        Field F(p.q);
        Drbg rng = TestOnlyDeterministicRng::from_label("negative|" + name);
        KeyPair kp = keygen(ps, rng);
        auto msg = bytes_of("negative test message for " + name);
        Signature s = sign(msg, kp.sk, rng);
        KCHECK(verify(msg, s, kp.pk), (name + ": baseline signature verifies").c_str());
        auto wire = signature_to_bytes(s, p, ps.mode);
        const uint32_t n23 = ps.k + 1;

        // --- bit flips at every bit of the wire signature ---------------------
        {
            int accepted = 0;
            for (size_t i = 0; i < wire.size(); i++)
                for (int b = 0; b < 8; b++) {
                    auto w = wire; w[i] ^= uint8_t(1u << b);
                    if (verify_bytes(msg, w, kp.pk, ps.mode)) accepted++;
                }
            KCHECK(accepted == 0, (name + ": every single-bit flip of the signature is rejected").c_str());
        }
        // --- truncation / extension ------------------------------------------
        {
            bool any = false;
            for (size_t n = 0; n < wire.size(); n++) {
                std::vector<uint8_t> w(wire.begin(), wire.begin() + long(n));
                any = any || signature_from_bytes(w, p, ps.mode).has_value();
            }
            KCHECK(!any, (name + ": every truncated signature encoding is rejected").c_str());
            auto w = wire; w.push_back(0);
            KCHECK(!signature_from_bytes(w, p, ps.mode), (name + ": appended byte rejected").c_str());
            w = wire; w.insert(w.end(), 64, 0xff);
            KCHECK(!signature_from_bytes(w, p, ps.mode), (name + ": appended 64 bytes rejected").c_str());
            std::vector<uint8_t> z(wire.size(), 0);
            KCHECK(!signature_from_bytes(z, p, ps.mode) || !verify_bytes(msg, z, kp.pk, ps.mode),
                   (name + ": all-zero signature bytes rejected").c_str());
            std::vector<uint8_t> e;
            KCHECK(!signature_from_bytes(e, p, ps.mode), (name + ": empty signature rejected").c_str());
        }
        // --- structural checks on the Signature object (verify's own checks) --
        {
            Signature t = s; t.salt.resize(SALT_BYTES - 1);
            KCHECK(!verify(msg, t, kp.pk), (name + ": short salt rejected").c_str());
            t = s; t.salt.push_back(0);
            KCHECK(!verify(msg, t, kp.pk), (name + ": long salt rejected").c_str());
            t = s; t.u.pop_back();
            KCHECK(!verify(msg, t, kp.pk), (name + ": short u rejected").c_str());
            t = s; t.v.push_back(1);
            KCHECK(!verify(msg, t, kp.pk), (name + ": long v rejected").c_str());
            t = s; t.u.assign(n23, 0);
            KCHECK(!verify(msg, t, kp.pk), (name + ": all-zero u rejected").c_str());
            t = s; t.v.assign(n23, 0);
            KCHECK(!verify(msg, t, kp.pk), (name + ": all-zero v rejected").c_str());
            t = s; t.u[0] = p.q;
            KCHECK(!verify(msg, t, kp.pk), (name + ": u element == q rejected").c_str());
            t = s; t.v[1] = 0xFFFF;
            KCHECK(!verify(msg, t, kp.pk), (name + ": v element 0xFFFF rejected").c_str());
            t = s; t.u.assign(n23, 1); t.v.assign(n23, 1);
            KCHECK(!verify(msg, t, kp.pk), (name + ": all-one u, v rejected").c_str());
            t = s; std::swap(t.u, t.v);
            KCHECK(!verify(msg, t, kp.pk), (name + ": swapped u/v rejected").c_str());
            // wrong message / wrong key / message prefix / message extension
            auto m2 = msg; m2.push_back('x');
            KCHECK(!verify(m2, s, kp.pk), (name + ": extended message rejected").c_str());
            std::vector<uint8_t> m3(msg.begin(), msg.end() - 1);
            KCHECK(!verify(m3, s, kp.pk), (name + ": truncated message rejected").c_str());
            std::vector<uint8_t> empty;
            KCHECK(!verify(empty, s, kp.pk), (name + ": empty message rejected").c_str());
            Drbg r2 = TestOnlyDeterministicRng::from_label("negative-other|" + name);
            KeyPair other = keygen(ps, r2);
            KCHECK(!verify(msg, s, other.pk), (name + ": other key rejected").c_str());
            // signature from another key of the same parameters on the same message
            Signature so = sign(msg, other.sk, r2);
            KCHECK(!verify(msg, so, kp.pk), (name + ": other key's signature rejected").c_str());
        }
        // --- public key encodings --------------------------------------------
        {
            auto pkb = kp.pk.serialize();
            bool any = false;
            for (size_t n = 0; n < pkb.size(); n += (pkb.size() > 512 ? 7u : 1u)) {
                std::vector<uint8_t> w(pkb.begin(), pkb.begin() + long(n));
                any = any || public_key_from_bytes(w).has_value();
            }
            KCHECK(!any, (name + ": truncated pk encodings rejected").c_str());
            auto w = pkb; w.push_back(0);
            KCHECK(!public_key_from_bytes(w), (name + ": pk with appended byte rejected").c_str());
            // Flip a bit anywhere -> either rejected at parse or the signature no longer verifies
            int accepted = 0;
            for (size_t i = 0; i < pkb.size(); i += (pkb.size() > 512 ? 13u : 1u)) {
                auto x = pkb; x[i] ^= 0x01;
                auto pk2 = public_key_from_bytes(x);
                if (pk2 && verify(msg, s, *pk2)) accepted++;
            }
            KCHECK(accepted == 0, (name + ": bit-flipped pk never verifies the signature").c_str());
            // header tampering: k or q changed
            auto h = pkb; h[0] ^= 1;
            KCHECK(!public_key_from_bytes(h), (name + ": pk with altered k rejected").c_str());
            h = pkb; h[4] ^= 1;
            KCHECK(!public_key_from_bytes(h), (name + ": pk with altered q rejected").c_str());
            std::vector<uint8_t> z(pkb.size(), 0);
            KCHECK(!public_key_from_bytes(z), (name + ": all-zero pk rejected").c_str());
            std::vector<uint8_t> ff(pkb.size(), 0xff);
            KCHECK(!public_key_from_bytes(ff), (name + ": all-0xff pk rejected").c_str());
        }
        // --- KNOWN DEVIATIONS (documented core findings) ---------------------
        {
            // KNOT-CORE-003: verify does not enforce canonical projective form of
            // u and v: any nonzero scalar multiple of a valid u (or v) verifies.
            Signature t = s;
            uint32_t lam = 2 % p.q; if (lam == 0 || lam == 1) lam = p.q - 1;
            for (auto& e : t.u) e = F.mul(e, lam);
            KNOWN_DEVIATION(verify(msg, t, kp.pk), "KNOT-CORE-003", (name + ": scaled u accepted").c_str());
            t = s;
            for (auto& e : t.v) e = F.mul(e, p.q - 1);
            KNOWN_DEVIATION(verify(msg, t, kp.pk), "KNOT-CORE-003", (name + ": negated v accepted").c_str());
            // The adapter's *dense* wire parser cannot detect this (the encoding is
            // canonical bytes for a non-canonical vector); it is a verifier property.
            if (uses_packed_signature(ps.mode)) {
                // KNOT-CORE-004: the raw packed deserializer accepts non-canonical
                // radix payloads (integer + q^n encodes to different bytes, same u||v).
                const size_t n = size_t(2) * n23;
                Vec uv = s.u; uv.insert(uv.end(), s.v.begin(), s.v.end());
                auto payload = radix_pack(uv, p.q);
                // add q^n: compute q^n as little-endian bytes and add
                std::vector<uint8_t> qn = radix_pack_raw(Vec(n + 1, 0), p.q); (void)qn;
                std::vector<uint8_t> big(payload.size() + 8, 0); // room to check overflow
                // big = payload + q^n, where q^n = radix_pack_raw of e_n (digit 1 at position n)
                Vec e_n(n + 1, 0); e_n[n] = 1;
                auto qn_bytes = radix_pack_raw(e_n, p.q);
                unsigned carry = 0;
                for (size_t i = 0; i < big.size(); i++) {
                    unsigned a = i < payload.size() ? payload[i] : 0;
                    unsigned b = i < qn_bytes.size() ? qn_bytes[i] : 0;
                    unsigned sum = a + b + carry; big[i] = uint8_t(sum); carry = sum >> 8;
                }
                bool fits = true;
                for (size_t i = payload.size(); i < big.size(); i++) fits = fits && big[i] == 0;
                if (fits) {
                    big.resize(payload.size());
                    ByteWriter w; w.bytes(s.salt); w.bytes(big);
                    Signature raw = deserialize_signature_packed(w.buf, p);
                    KNOWN_DEVIATION(raw.u == s.u && raw.v == s.v && verify(msg, raw, kp.pk),
                                    "KNOT-CORE-004", (name + ": non-canonical radix payload accepted by raw core parser").c_str());
                    KCHECK(!signature_from_bytes(w.buf, p, ps.mode),
                           (name + ": adapter rejects non-canonical radix payload").c_str());
                }
            }
        }
    }
    std::printf("known deviations exercised: %d, unexpected passes: %d\n", g_known, g_xpass);
    if (g_xpass) { KCHECK(false, "a known deviation no longer reproduces: update metadata/findings and this test"); }
    return finish("negative");
}
