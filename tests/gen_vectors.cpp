// Generates deterministic example vectors for all three modes at k=4 and k=8.
#include "ccts/scheme.hpp"
#include <cstdio>
#include <string>

using namespace ccts;

static std::string hex(const std::vector<uint8_t>& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (auto x : b) { s += d[x >> 4]; s += d[x & 15]; }
    return s;
}

static const char* mode_name(Mode m) {
    switch (m) {
        case Mode::tensor_reference: return "tensor_reference";
        case Mode::chord_tensor:     return "chord_tensor";
        case Mode::chord_structured: return "chord_structured";
        case Mode::chord_labeled:    return "chord_labeled";
        case Mode::tri_chord:        return "tri_chord";
    }
    return "?";
}

static void emit(FILE* f, Mode mode, uint32_t k, const char* seed_str) {
    Parameters p = mode == Mode::chord_structured ? Parameters::for_k_structured(k)
                 : mode == Mode::chord_labeled    ? Parameters::for_k_labeled(k)
                 : mode == Mode::tri_chord        ? Parameters::for_k_tri(k)
                                                  : Parameters::for_k(k);
    std::vector<uint8_t> seed(seed_str, seed_str + std::string(seed_str).size());
    Drbg rng(seed);
    KeyPair kp = keygen(p, rng, mode);
    std::string msg_s = "CCTS deterministic example vector";
    std::vector<uint8_t> msg(msg_s.begin(), msg_s.end());
    Signature sig = sign(msg, kp.sk, rng);
    bool ok = verify(msg, sig, kp.pk);

    fprintf(f, "mode = %s\n", mode_name(mode));
    fprintf(f, "k = %u\nq = %u\nseed = \"%s\"\nmessage = \"%s\"\n", p.k, p.q, seed_str, msg_s.c_str());
    fprintf(f, "pk_digest = %s\n", hex(std::vector<uint8_t>(kp.pk.digest.begin(), kp.pk.digest.end())).c_str());
    fprintf(f, "pk_bytes = %zu\nsk_bytes = %zu\nsig_bytes = %zu\n",
            kp.pk.serialize().size(), kp.sk.serialize().size(), sig.serialize().size());
    fprintf(f, "salt = %s\n", hex(sig.salt).c_str());
    fprintf(f, "u =");
    for (auto e : sig.u) fprintf(f, " %u", e);
    fprintf(f, "\nv =");
    for (auto e : sig.v) fprintf(f, " %u", e);
    fprintf(f, "\nverifies = %s\n", ok ? "true" : "false");
    fprintf(f, "signature_hex = %s\n", hex(sig.serialize()).c_str());
    if (mode == Mode::tri_chord) {
        // tri_chord wire format: bit-packed (TRI design notes Sec. 7.5 Tier 1).
        auto packed = serialize_signature_packed(sig, p);
        fprintf(f, "sig_bytes_packed = %zu\n", packed.size());
        fprintf(f, "signature_packed_hex = %s\n", hex(packed).c_str());
    }
    fprintf(f, "\n");
}

int main() {
    FILE* f = fopen("vectors/kat.txt", "w");
    if (!f) { perror("vectors/kat.txt"); return 1; }
    fprintf(f, "# CCTS deterministic example vectors (research prototype, toy parameters)\n\n");
    emit(f, Mode::tensor_reference, 4, "CCTS-KAT-seed-A");
    emit(f, Mode::tensor_reference, 8, "CCTS-KAT-seed-B");
    emit(f, Mode::chord_tensor, 4, "CCTS-KAT-seed-A");
    emit(f, Mode::chord_tensor, 8, "CCTS-KAT-seed-B");
    emit(f, Mode::chord_structured, 4, "CCTS-KAT-seed-A");
    emit(f, Mode::chord_structured, 8, "CCTS-KAT-seed-B");
    emit(f, Mode::chord_labeled, 4, "CCTS-KAT-seed-A");
    emit(f, Mode::chord_labeled, 8, "CCTS-KAT-seed-B");
    // tri_chord needs k+1+m <= 2k+1, which the default margin rule first
    // satisfies at k = 8 in the toy range (k = 4 would need t = 10 > 9).
    emit(f, Mode::tri_chord, 8, "CCTS-KAT-seed-A");
    emit(f, Mode::tri_chord, 12, "CCTS-KAT-seed-B");
    fclose(f);
    printf("wrote vectors/kat.txt\n");
    return 0;
}
