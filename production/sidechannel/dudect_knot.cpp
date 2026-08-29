// dudect-style statistical timing test for KNOT
//
// Methodology (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant
// time?", DATE 2017): measure the execution time of an operation on two input
// classes, many times, in random interleaved order; apply Welch's t-test
// (uncropped plus a cropped-percentile family to reduce tail noise). |t| above
// 4.5 with enough samples is evidence of a timing difference.
//
// PASSING THIS TEST IS NOT A PROOF OF CONSTANT-TIME EXECUTION. Failing it is
// evidence of a timing side channel under the tested configuration only.
//
// Experiments, per parameter set:
//   sign        class 0 = fixed secret key A, class 1 = key B (same parameters),
//               message fixed, identical DRBG stream -> secret-key-dependent timing.
//   verify      class 0 = valid signature, class 1 = salt-bit-flipped signature
//               -> early-reject vs full-check timing (public data; informational).
//   verify-msg  class 0 = 64-byte 0x00 message, class 1 = 64-byte 0xff message,
//               each with its own valid signature -> content-dependent timing.
// Environment: KNOT_DUDECT_SAMPLES (per class, default 2000),
//              KNOT_DUDECT_SETS (comma-separated "<mode>/k=<k>"),
//              KNOT_DUDECT_JSON (output record path).
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace ccts;
using namespace knot_adapter;
using namespace knot_test;

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static inline uint64_t cycles() { unsigned aux; return __rdtscp(&aux); }
static const char* CLOCK_NAME = "rdtscp";
#elif defined(__aarch64__)
static inline uint64_t cycles() { uint64_t v; asm volatile("mrs %0, cntvct_el0" : "=r"(v)); return v; }
static const char* CLOCK_NAME = "cntvct_el0";
#else
static inline uint64_t cycles() {
    return uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count());
}
static const char* CLOCK_NAME = "steady_clock_ns";
#endif

struct TTest {
    double mean[2] = {0, 0}, m2[2] = {0, 0}, n[2] = {0, 0};
    void push(double x, int c) { n[c]++; double d = x - mean[c]; mean[c] += d / n[c]; m2[c] += d * (x - mean[c]); }
    double t() const {
        if (n[0] < 2 || n[1] < 2) return 0;
        double v0 = m2[0] / (n[0] - 1), v1 = m2[1] / (n[1] - 1);
        double den = std::sqrt(v0 / n[0] + v1 / n[1]);
        return den > 0 ? (mean[0] - mean[1]) / den : 0;
    }
};

struct Result { std::string op, set; double t_uncropped, t_max; size_t n; const char* verdict; };
static const double LEAK_THRESHOLD = 4.5;

template <class F>
static Result experiment(const char* op, const std::string& set, size_t n_each, F&& run_class) {
    Drbg sched = TestOnlyDeterministicRng::from_label("dudect-schedule|" + std::string(op) + "|" + set);
    std::vector<uint8_t> classes(2 * n_each);
    for (size_t i = 0; i < n_each; i++) { classes[2 * i] = 0; classes[2 * i + 1] = 1; }
    for (size_t i = classes.size(); i-- > 1;) std::swap(classes[i], classes[sched.uniform(uint32_t(i + 1))]);
    std::vector<std::pair<uint64_t, int>> samples;
    samples.reserve(classes.size());
    for (uint8_t c : classes) {
        uint64_t t0 = cycles();
        run_class(c);
        uint64_t t1 = cycles();
        samples.push_back({t1 - t0, c});
    }
    std::vector<uint64_t> all;
    all.reserve(samples.size());
    for (auto& s : samples) all.push_back(s.first);
    std::sort(all.begin(), all.end());
    TTest full;
    for (auto& s : samples) full.push(double(s.first), s.second);
    double tmax = std::fabs(full.t());
    for (double pct : {0.5, 0.7, 0.8, 0.9, 0.95, 0.99}) {
        uint64_t cut = all[size_t(pct * double(all.size() - 1))];
        TTest tt;
        for (auto& s : samples) if (s.first <= cut) tt.push(double(s.first), s.second);
        tmax = std::max(tmax, std::fabs(tt.t()));
    }
    Result r{op, set, std::fabs(full.t()), tmax, samples.size(),
             tmax > LEAK_THRESHOLD ? "timing-difference-detected" : "no-difference-detected"};
    std::printf("  %-10s %-24s n=%zu  |t|=%.2f  max|t|=%.2f  -> %s\n", op, set.c_str(), samples.size(),
                r.t_uncropped, r.t_max, r.verdict);
    return r;
}

int main() {
    size_t n_each = size_t(env_long("KNOT_DUDECT_SAMPLES", 2000));
    std::vector<ParamSet> sets = {{Mode::tensor_reference, 8}, {Mode::chord_structured, 8}, {Mode::tri_chord, 8}};
    if (const char* e = std::getenv("KNOT_DUDECT_SETS")) {
        sets.clear();
        std::string s = e;
        size_t pos = 0;
        while (pos <= s.size()) {
            size_t c = s.find(',', pos); if (c == std::string::npos) c = s.size();
            std::string item = s.substr(pos, c - pos); pos = c + 1;
            size_t sl = item.find("/k=");
            auto m = mode_from_name(item.substr(0, sl));
            if (m && sl != std::string::npos) sets.push_back({*m, uint32_t(std::stoul(item.substr(sl + 3)))});
        }
    }
    std::printf("dudect-style timing test: clock=%s samples/class=%zu threshold |t|>%.1f\n", CLOCK_NAME, n_each, LEAK_THRESHOLD);
    std::printf("NOTE: a 'no-difference-detected' verdict is not a constant-time proof.\n");
    std::vector<Result> results;
    for (auto& ps : sets) {
        std::string name = param_set_name(ps);
        Drbg rng = TestOnlyDeterministicRng::from_label("dudect|" + name);
        KeyPair A = keygen(ps, rng), B = keygen(ps, rng);
        auto msg = bytes_of("dudect fixed message");
        Drbg base = rng;
        results.push_back(experiment("sign", name, n_each, [&](int c) {
            Drbg r = base; // both classes consume an identical randomness stream
            Signature s = sign(msg.data(), msg.size(), c ? B.sk : A.sk, r);
            asm volatile("" : : "r"(s.u.data()) : "memory");
        }));
        Signature good = sign(msg, A.sk, rng), bad = good; bad.salt[0] ^= 1;
        results.push_back(experiment("verify", name, n_each, [&](int c) {
            bool ok = verify(msg, c ? bad : good, A.pk);
            asm volatile("" : : "r"(ok) : "memory");
        }));
        std::vector<uint8_t> m0(64, 0x00), m1(64, 0xff);
        Signature sig0 = sign(m0, A.sk, rng), sig1 = sign(m1, A.sk, rng);
        results.push_back(experiment("verify-msg", name, n_each, [&](int c) {
            bool ok = verify(c ? m1 : m0, c ? sig1 : sig0, A.pk);
            asm volatile("" : : "r"(ok) : "memory");
        }));
    }
    if (const char* path = std::getenv("KNOT_DUDECT_JSON")) {
        FILE* f = std::fopen(path, "w");
        if (f) {
            std::fprintf(f, "{\"record\":\"timing-test\",\"method\":\"dudect-welch-t\",\"clock\":\"%s\","
                            "\"samples_per_class\":%zu,\"threshold_abs_t\":%.1f,\"results\":[", CLOCK_NAME, n_each, LEAK_THRESHOLD);
            for (size_t i = 0; i < results.size(); i++)
                std::fprintf(f, "%s{\"op\":\"%s\",\"parameter_set\":\"%s\",\"n\":%zu,\"abs_t\":%.3f,\"max_abs_t\":%.3f,\"verdict\":\"%s\"}",
                             i ? "," : "", results[i].op.c_str(), results[i].set.c_str(), results[i].n,
                             results[i].t_uncropped, results[i].t_max, results[i].verdict);
            std::fprintf(f, "],\"disclaimer\":\"statistical test; not a constant-time proof\"}\n");
            std::fclose(f);
        }
    }
    int detected = 0;
    for (auto& r : results) if (std::strcmp(r.verdict, "timing-difference-detected") == 0) detected++;
    std::printf("timing differences detected in %d of %zu experiments\n", detected, results.size());
    // Exit 0 = harness ran. Verdicts are evidence; scripts/ci.sh applies the
    // policy of the production-readiness report (secret-dependent sign timing is a
    // documented core finding, KNOT-CORE-007, and does not gate PRs).
    return 0;
}
