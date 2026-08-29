// KNOT reproducible micro-benchmark.
//
// Wraps the existing benchmark statistics (bench/bench_main.cpp, results/)
// with the additional evidence a production benchmark record needs:
//   * median / p95 / p99 latency, operations per second, CPU cycles (rdtscp
//     on x86-64, cntvct on AArch64; "unavailable" elsewhere)
//   * sizes: public key, secret key, signature (wire format of the mode)
//   * stack high-water mark of each operation (painted-stack probe, own thread)
//   * heap: bytes allocated and peak live bytes per operation (global
//     operator new/delete accounting in this translation unit)
//   * environment metadata is merged by scripts/bench_summary.py from
//     ci-artifacts/build-metadata.json; a record without it is invalid.
// Output: JSON on stdout (or KNOT_BENCH_JSON path). Deterministic inputs.
//   KNOT_BENCH_SAMPLES (default 50), KNOT_BENCH_SETS ("<mode>/k=<k>,...")
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <new>
#include <pthread.h>

using namespace ccts;
using namespace knot_adapter;
using namespace knot_test;

// ---- heap accounting -------------------------------------------------------
// Replacement global allocation functions backed by malloc/free. GCC's
// -Wmismatched-new-delete does not understand replaced operators and flags the
// free() inside operator delete; suppressed for this block only.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
static std::atomic<size_t> g_alloc_bytes{0}, g_live_bytes{0}, g_peak_live{0}, g_alloc_count{0};
static bool g_track = false;
void* operator new(size_t n) {
    void* p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    if (g_track) {
        g_alloc_bytes += n; g_alloc_count++;
        size_t live = (g_live_bytes += n);
        size_t peak = g_peak_live.load();
        while (live > peak && !g_peak_live.compare_exchange_weak(peak, live)) {}
    }
    return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, size_t n) noexcept { if (g_track && p) g_live_bytes -= n; std::free(p); }
void* operator new[](size_t n) { return operator new(n); }
void operator delete[](void* p) noexcept { operator delete(p); }
void operator delete[](void* p, size_t n) noexcept { operator delete(p, n); }
#pragma GCC diagnostic pop

struct HeapStats { size_t bytes, count, peak; };
template <class F> static HeapStats heap_measure(F&& f) {
    g_alloc_bytes = 0; g_alloc_count = 0; g_live_bytes = 0; g_peak_live = 0;
    g_track = true; f(); g_track = false;
    return {g_alloc_bytes.load(), g_alloc_count.load(), g_peak_live.load()};
}

// ---- cycle counter ---------------------------------------------------------
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static inline uint64_t cycles() { unsigned aux; return __rdtscp(&aux); }
static const char* CYCLE_SOURCE = "rdtscp";
#elif defined(__aarch64__)
static inline uint64_t cycles() { uint64_t v; asm volatile("mrs %0, cntvct_el0" : "=r"(v)); return v; }
static const char* CYCLE_SOURCE = "cntvct_el0";
#else
static inline uint64_t cycles() { return 0; }
static const char* CYCLE_SOURCE = "unavailable";
#endif

// ---- stack high-water mark --------------------------------------------------
// Run f on a dedicated thread whose stack we allocate and paint; afterwards
// scan for the lowest painted byte overwritten. Approximate (page granular
// at worst), independent of the OS stack size.
static constexpr size_t STACK_SIZE = 16u << 20;
struct StackJob { void (*fn)(void*); void* arg; };
static void* stack_thread(void* a) { auto* j = static_cast<StackJob*>(a); j->fn(j->arg); return nullptr; }
template <class F> static size_t stack_measure(F&& f) {
    static const uint8_t PAINT = 0xA5;
    std::vector<uint8_t> stack(STACK_SIZE);
    std::memset(stack.data(), PAINT, STACK_SIZE);
    F* fp = &f;
    StackJob job{[](void* p) { (*static_cast<F*>(p))(); }, fp};
    pthread_attr_t attr; pthread_attr_init(&attr);
    pthread_attr_setstack(&attr, stack.data(), STACK_SIZE);
    pthread_t th;
    if (pthread_create(&th, &attr, stack_thread, &job) != 0) return 0;
    pthread_join(th, nullptr);
    pthread_attr_destroy(&attr);
    size_t low = 0;
    while (low < STACK_SIZE && stack[low] == PAINT) low++;
    // Guard/TLS setup at the top consumes some; report used bytes.
    return STACK_SIZE - low;
}

struct Stats { double median, p95, p99, mean, min; double ops_per_s; uint64_t cyc_median; };
static Stats stats(std::vector<double> ns, std::vector<uint64_t> cyc) {
    std::sort(ns.begin(), ns.end()); std::sort(cyc.begin(), cyc.end());
    auto pct = [&](double p) { return ns[std::min(ns.size() - 1, size_t(p * double(ns.size())))]; };
    double sum = 0; for (double x : ns) sum += x;
    Stats s{pct(0.5), pct(0.95), pct(0.99), sum / double(ns.size()), ns.front(), 0, cyc[cyc.size() / 2]};
    s.ops_per_s = 1e9 / s.median;
    return s;
}

int main() {
    const int samples = int(env_long("KNOT_BENCH_SAMPLES", 50));
    std::vector<ParamSet> sets;
    for (Mode m : {Mode::tensor_reference, Mode::chord_tensor, Mode::chord_structured, Mode::chord_labeled, Mode::tri_chord})
        for (uint32_t k : {8u, 16u, 32u}) sets.push_back({m, k});
    if (const char* e = std::getenv("KNOT_BENCH_SETS")) {
        sets.clear();
        std::string s = e; size_t pos = 0;
        while (pos <= s.size()) {
            size_t c = s.find(',', pos); if (c == std::string::npos) c = s.size();
            std::string item = s.substr(pos, c - pos); pos = c + 1;
            size_t sl = item.find("/k=");
            auto m = mode_from_name(item.substr(0, sl));
            if (m && sl != std::string::npos) sets.push_back({*m, uint32_t(std::stoul(item.substr(sl + 3)))});
        }
    }
    FILE* file = nullptr; // owned output file when KNOT_BENCH_JSON is set
    if (const char* path = std::getenv("KNOT_BENCH_JSON")) { file = std::fopen(path, "w"); if (!file) { std::perror(path); return 1; } }
    FILE* out = file ? file : stdout;
    std::vector<uint8_t> message(512);
    for (size_t i = 0; i < message.size(); i++) message[i] = uint8_t(i * 37);
    std::fprintf(out, "{\"record\":\"microbenchmark\",\"record_version\":1,\"samples\":%d,\"cycle_source\":\"%s\","
                      "\"message_bytes\":%zu,\"warmup\":5,\"results\":[", samples, CYCLE_SOURCE, message.size());
    bool first = true;
    for (const ParamSet& ps : sets) {
        Parameters p = make_params(ps);
        Drbg rng = TestOnlyDeterministicRng::from_label("bench|" + param_set_name(ps));
        struct Op { const char* name; std::vector<double> ns; std::vector<uint64_t> cyc; };
        Op ops[3] = {{"keygen", {}, {}}, {"sign", {}, {}}, {"verify", {}, {}}};
        KeyPair kp;
        for (int w = 0; w < 5; w++) kp = keygen(ps, rng);
        for (int s = 0; s < samples; s++) {
            auto t0 = std::chrono::steady_clock::now(); uint64_t c0 = cycles();
            KeyPair k2 = keygen(ps, rng);
            uint64_t c1 = cycles(); auto t1 = std::chrono::steady_clock::now();
            ops[0].ns.push_back(double(std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()));
            ops[0].cyc.push_back(c1 - c0);
            if (s == samples - 1) kp = std::move(k2);
        }
        std::vector<Signature> sigs;
        for (int w = 0; w < 5; w++) (void)sign(message, kp.sk, rng);
        for (int s = 0; s < samples; s++) {
            auto t0 = std::chrono::steady_clock::now(); uint64_t c0 = cycles();
            Signature sg = sign(message, kp.sk, rng);
            uint64_t c1 = cycles(); auto t1 = std::chrono::steady_clock::now();
            ops[1].ns.push_back(double(std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()));
            ops[1].cyc.push_back(c1 - c0);
            sigs.push_back(std::move(sg));
        }
        for (int w = 0; w < 5; w++) (void)verify(message, sigs[0], kp.pk);
        for (int s = 0; s < samples; s++) {
            auto t0 = std::chrono::steady_clock::now(); uint64_t c0 = cycles();
            bool ok = verify(message, sigs[size_t(s)], kp.pk);
            uint64_t c1 = cycles(); auto t1 = std::chrono::steady_clock::now();
            if (!ok) { std::fprintf(stderr, "verify failed in bench\n"); if (file) std::fclose(file); return 1; }
            ops[2].ns.push_back(double(std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()));
            ops[2].cyc.push_back(c1 - c0);
        }
        // sizes
        size_t pk_b = kp.pk.serialize().size(), sk_b = kp.sk.serialize().size();
        size_t sig_b = signature_to_bytes(sigs[0], p, ps.mode).size();
        // resources
        Drbg r2 = rng;
        size_t st_keygen = stack_measure([&] { Drbg r = r2; (void)keygen(ps, r); });
        size_t st_sign = stack_measure([&] { Drbg r = r2; (void)sign(message, kp.sk, r); });
        size_t st_verify = stack_measure([&] { (void)verify(message, sigs[0], kp.pk); });
        HeapStats h_keygen = heap_measure([&] { Drbg r = r2; (void)keygen(ps, r); });
        HeapStats h_sign = heap_measure([&] { Drbg r = r2; (void)sign(message, kp.sk, r); });
        HeapStats h_verify = heap_measure([&] { (void)verify(message, sigs[0], kp.pk); });
        std::fprintf(out, "%s{\"parameter_set\":\"%s\",\"mode\":\"%s\",\"k\":%u,\"q\":%u,"
                          "\"sizes\":{\"public_key\":%zu,\"secret_key\":%zu,\"signature\":%zu,\"signature_format\":\"%s\"},"
                          "\"stack_bytes\":{\"keygen\":%zu,\"sign\":%zu,\"verify\":%zu},"
                          "\"heap\":{\"keygen\":{\"bytes\":%zu,\"allocations\":%zu,\"peak_live\":%zu},"
                          "\"sign\":{\"bytes\":%zu,\"allocations\":%zu,\"peak_live\":%zu},"
                          "\"verify\":{\"bytes\":%zu,\"allocations\":%zu,\"peak_live\":%zu}},\"ops\":{",
                     first ? "" : ",", param_set_name(ps).c_str(), mode_name(ps.mode), ps.k, p.q, pk_b, sk_b, sig_b,
                     uses_packed_signature(ps.mode) ? "packed" : "dense", st_keygen, st_sign, st_verify,
                     h_keygen.bytes, h_keygen.count, h_keygen.peak, h_sign.bytes, h_sign.count, h_sign.peak,
                     h_verify.bytes, h_verify.count, h_verify.peak);
        first = false;
        for (int i = 0; i < 3; i++) {
            Stats st = stats(ops[i].ns, ops[i].cyc);
            std::fprintf(out, "%s\"%s\":{\"n\":%zu,\"median_ns\":%.0f,\"p95_ns\":%.0f,\"p99_ns\":%.0f,\"mean_ns\":%.0f,"
                              "\"min_ns\":%.0f,\"ops_per_s\":%.1f,\"median_cycles\":%llu}",
                         i ? "," : "", ops[i].name, ops[i].ns.size(), st.median, st.p95, st.p99, st.mean, st.min,
                         st.ops_per_s, (unsigned long long)st.cyc_median);
        }
        std::fprintf(out, "}}");
        std::fflush(out);
        std::fprintf(stderr, "bench: %s done\n", param_set_name(ps).c_str());
    }
    std::fprintf(out, "]}\n");
    if (file) std::fclose(file);
    return 0;
}
