// Generates the versioned KNOT known-answer corpus vectors/knot-kat-v1.txt.
//
// Every vector records: parameter set, the frozen deterministic seed label,
// message, full serialized public key, secret key and signature (wire format
// of the mode), pk digest, and a second signature produced by the continuing
// DRBG stream. All entropy is TestOnlyDeterministicRng (non-production test
// material). Regenerate ONLY for a deliberate corpus revision:
//   make -C production kat-regen   (bumps nothing automatically; review the diff)
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <cstdio>

using namespace ccts;
using namespace knot_test;
using namespace knot_adapter;

int main(int argc, char** argv) {
    const char* out = argc > 1 ? argv[1] : "vectors/knot-kat-v1.txt";
    const char* core_digest = argc > 2 ? argv[2] : "unknown";
    FILE* f = std::fopen(out, "w");
    if (!f) { std::perror(out); return 1; }
    std::fprintf(f, "# KNOT known-answer vectors\n");
    std::fprintf(f, "corpus_version = 1\n");
    std::fprintf(f, "generator = production/tools/gen_kat.cpp\n");
    std::fprintf(f, "core_tree_digest_sha256 = %s\n", core_digest);
    std::fprintf(f, "specification = repository documents; unversioned\n");
    std::fprintf(f, "entropy = TestOnlyDeterministicRng::from_label(seed) -- NON-PRODUCTION TEST MATERIAL\n");
    std::fprintf(f, "drbg_usage = one DRBG per vector: keygen, then sign(message), then sign(message2)\n");
    std::fprintf(f, "sig_format = dense for all modes except tri_chord (packed)\n\n");

    const std::string msg1_s = "KNOT known-answer vector message";
    const std::vector<uint8_t> msg1(msg1_s.begin(), msg1_s.end());
    const std::vector<uint8_t> msg2; // empty message
    unsigned idx = 0;
    for (const ParamSet& ps : ci_parameter_sets()) {
        char seed[64];
        std::snprintf(seed, sizeof seed, "KNOT-KAT-v1-%03u", ++idx);
        Parameters p = make_params(ps);
        Drbg rng = TestOnlyDeterministicRng::from_label(seed);
        KeyPair kp = keygen(ps, rng);
        Signature s1 = sign(msg1, kp.sk, rng);
        Signature s2 = sign(msg2, kp.sk, rng);
        bool ok = verify(msg1, s1, kp.pk) && verify(msg2, s2, kp.pk);
        std::fprintf(f, "[vector]\nname = %s/seed=%s\nmode = %s\nk = %u\nq = %u\n",
                     param_set_name(ps).c_str(), seed, mode_name(ps.mode), ps.k, p.q);
        if (ps.mode == Mode::tri_chord) std::fprintf(f, "tri_t = %u\ntri_w = %u\n", p.sup.t, p.sup.w);
        if (ps.mode == Mode::chord_labeled) std::fprintf(f, "label_N = %u\n", p.label_N);
        std::fprintf(f, "seed = %s\n", seed);
        std::fprintf(f, "message_hex = %s\n", hex(msg1).c_str());
        std::fprintf(f, "message2_hex = %s\n", hex(msg2).c_str());
        std::fprintf(f, "pk_digest = %s\n", hex(kp.pk.digest).c_str());
        std::fprintf(f, "pk_hex = %s\n", hex(kp.pk.serialize()).c_str());
        std::fprintf(f, "sk_hex = %s\n", hex(kp.sk.serialize()).c_str());
        std::fprintf(f, "sig_format = %s\n", uses_packed_signature(ps.mode) ? "packed" : "dense");
        std::fprintf(f, "sig_hex = %s\n", hex(signature_to_bytes(s1, p, ps.mode)).c_str());
        std::fprintf(f, "sig2_hex = %s\n", hex(signature_to_bytes(s2, p, ps.mode)).c_str());
        std::fprintf(f, "verifies = %s\n\n", ok ? "true" : "false");
    }
    std::fclose(f);
    std::printf("wrote %s (%u vectors)\n", out, idx);
    return 0;
}
