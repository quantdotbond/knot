// CCTS benchmark harness.
// Measures keygen / sign / verify latency across parameter sets and modes,
// with warmup, multiple independently generated keys, steady_clock timing,
// and per-sample CSV output. Also records serialized sizes, signing retries,
// keygen retries, and peak RSS per configuration.
#include "ccts/scheme.hpp"
#include <chrono>
#include <cstdio>
#include <string>
#include <sys/resource.h>

using namespace ccts;
using Clock = std::chrono::steady_clock;

static long peak_rss_kb() {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss;
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

int main() {
    const uint32_t ks[] = {8, 16, 32, 48};
    const Mode modes[] = {Mode::tensor_reference, Mode::chord_tensor,
                          Mode::chord_structured, Mode::chord_labeled,
                          Mode::tri_chord};
    const int KEYS = 3;
    const int KEYGEN_SAMPLES_PER_KEYSLOT = 20; // 3 x 20 = 60 keygen samples
    const int SIGN_SAMPLES = 40;               // per key -> 120 total
    const int VERIFY_SAMPLES = 40;             // per key -> 120 total
    const int WARMUP = 5;

    FILE* ft = fopen("results/timings.csv", "w");
    FILE* fs = fopen("results/sizes.csv", "w");
    FILE* fm = fopen("results/meta.csv", "w");
    if (!ft || !fs || !fm) { perror("results csv"); return 1; }
    fprintf(ft, "mode,k,q,op,key_index,sample_index,nanoseconds\n");
    fprintf(fs, "mode,k,q,pk_bytes,sk_bytes,sig_bytes\n");
    fprintf(fm, "mode,k,q,keygen_retries_total,sign_retries_total,peak_rss_kb\n");

    std::vector<uint8_t> message;
    for (int i = 0; i < 512; i++) message.push_back(uint8_t(i * 37));

    for (Mode mode : modes) {
        for (uint32_t k : ks) {
            Parameters p = mode == Mode::chord_structured ? Parameters::for_k_structured(k)
                         : mode == Mode::chord_labeled    ? Parameters::for_k_labeled(k)
                         : mode == Mode::tri_chord        ? Parameters::for_k_tri(k)
                                                          : Parameters::for_k(k);
            std::string seed_s = std::string("bench-seed-") + mode_name(mode) + "-k" + std::to_string(k);
            Drbg rng(std::vector<uint8_t>(seed_s.begin(), seed_s.end()));

            uint64_t keygen_retries = 0, sign_retries = 0;

            // Warmup keygen.
            for (int w = 0; w < 2; w++) (void)keygen(p, rng, mode);

            std::vector<KeyPair> kps;
            for (int key = 0; key < KEYS; key++) {
                for (int s = 0; s < KEYGEN_SAMPLES_PER_KEYSLOT; s++) {
                    auto t0 = Clock::now();
                    KeyPair kp = keygen(p, rng, mode);
                    auto t1 = Clock::now();
                    keygen_retries += kp.keygen_retries;
                    long long ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
                    fprintf(ft, "%s,%u,%u,keygen,%d,%d,%lld\n", mode_name(mode), k, p.q, key, s, ns);
                    if (s == KEYGEN_SAMPLES_PER_KEYSLOT - 1) kps.push_back(std::move(kp));
                }
            }

            // Sizes from the last key of the first slot.
            {
                Drbg srng(std::vector<uint8_t>(seed_s.begin(), seed_s.end()), "sizes");
                Signature sg = sign(message.data(), message.size(), kps[0].sk, srng);
                // tri_chord's wire format is packed (TRI design notes Sec. 7.5).
                size_t sig_bytes = mode == Mode::tri_chord
                                       ? serialize_signature_packed(sg, p).size()
                                       : sg.serialize().size();
                fprintf(fs, "%s,%u,%u,%zu,%zu,%zu\n", mode_name(mode), k, p.q,
                        kps[0].pk.serialize().size(), kps[0].sk.serialize().size(),
                        sig_bytes);
            }

            // Sign.
            for (int key = 0; key < KEYS; key++) {
                for (int w = 0; w < WARMUP; w++)
                    (void)sign(message.data(), message.size(), kps[key].sk, rng);
                for (int s = 0; s < SIGN_SAMPLES; s++) {
                    uint32_t r = 0;
                    auto t0 = Clock::now();
                    Signature sg = sign(message.data(), message.size(), kps[key].sk, rng, &r);
                    auto t1 = Clock::now();
                    sign_retries += r;
                    (void)sg;
                    long long ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
                    fprintf(ft, "%s,%u,%u,sign,%d,%d,%lld\n", mode_name(mode), k, p.q, key, s, ns);
                }
            }

            // Verify (fresh signatures; assert validity outside the timed region).
            for (int key = 0; key < KEYS; key++) {
                std::vector<Signature> sigs;
                for (int s = 0; s < VERIFY_SAMPLES; s++)
                    sigs.push_back(sign(message.data(), message.size(), kps[key].sk, rng));
                for (int w = 0; w < WARMUP; w++)
                    (void)verify(message.data(), message.size(), sigs[0], kps[key].pk);
                for (int s = 0; s < VERIFY_SAMPLES; s++) {
                    auto t0 = Clock::now();
                    bool ok = verify(message.data(), message.size(), sigs[s], kps[key].pk);
                    auto t1 = Clock::now();
                    if (!ok) { fprintf(stderr, "verify failed in bench!\n"); return 1; }
                    long long ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
                    fprintf(ft, "%s,%u,%u,verify,%d,%d,%lld\n", mode_name(mode), k, p.q, key, s, ns);
                }
            }

            fprintf(fm, "%s,%u,%u,%llu,%llu,%ld\n", mode_name(mode), k, p.q,
                    (unsigned long long)keygen_retries, (unsigned long long)sign_retries,
                    peak_rss_kb());
            fprintf(stderr, "done: %s k=%u\n", mode_name(mode), k);
        }
    }
    fclose(ft); fclose(fs); fclose(fm);

    // Naive-vs-fast preimage sampler microbenchmark -> results/interp.csv.
    // Times vwz_preimage directly (no basis change, no hashing) on a random
    // non-degenerate Lambda and a random weight-(k+1) sphere target, at sizes
    // well beyond the scheme benchmarks, to locate the backend crossover.
    FILE* fi = fopen("results/interp.csv", "w");
    if (!fi) { perror("results/interp.csv"); return 1; }
    fprintf(fi, "backend,k,q,sample,nanoseconds\n");
    const uint32_t iks[] = {32, 64, 128, 256, 512, 1024, 2048, 4096, 8192};
    for (uint32_t k : iks) {
        Parameters p = Parameters::for_k(k);
        const Field F(p.q);
        const uint32_t n1 = 2 * k + 1;
        std::string seed_s = "interp-bench-k" + std::to_string(k);
        Drbg rng(std::vector<uint8_t>(seed_s.begin(), seed_s.end()));
        Vec c2 = distinct_column(F, n1, rng);
        Vec c3 = distinct_column(F, n1, rng);
        Vec y0(n1, 0); // weight-(k+1) target, random support
        Vec perm = random_permutation(n1, rng);
        for (uint32_t t = 0; t < k + 1; t++) y0[perm[t]] = rng.nonzero_field_elem(F);

        const int SAMPLES = k >= 2048 ? 3 : 7;
        for (PolyBackend be : {PolyBackend::naive, PolyBackend::fast}) {
            const char* bname = be == PolyBackend::naive ? "naive" : "fast";
            Vec w2, w3;
            (void)vwz_preimage(F, k, c2, c3, y0, false, w2, w3, be); // warmup
            for (int s = 0; s < SAMPLES; s++) {
                auto t0 = Clock::now();
                bool ok = vwz_preimage(F, k, c2, c3, y0, false, w2, w3, be);
                auto t1 = Clock::now();
                if (!ok) { fprintf(stderr, "interp bench preimage failed!\n"); return 1; }
                long long ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
                fprintf(fi, "%s,%u,%u,%d,%lld\n", bname, k, p.q, s, ns);
            }
        }
        fprintf(stderr, "done: interp k=%u\n", k);
    }
    fclose(fi);
    printf("wrote results/timings.csv, results/sizes.csv, results/meta.csv, results/interp.csv\n");
    return 0;
}
