// Standalone driver for the fuzz targets (no libFuzzer required).
//
//   <target>_standalone [-runs=N] [-seed=S] [-max_len=L] <dir-or-file>...
//
// 1. Replays every file in the given directories/files (seed + regression
//    corpora) through LLVMFuzzerTestOneInput.
// 2. If -runs=N is given, performs N additional mutation rounds: picks a
//    corpus entry, applies byte flips / truncation / insertion / random
//    bytes, and runs it. Any crash aborts the process; the offending input is
//    written to ./crash-<hash> before the abort is re-raised so it can be
//    added to the regression corpus.
// This is coverage-blind; the libFuzzer build (clang) is the real fuzzer.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
namespace fs = std::filesystem;

static std::vector<uint8_t> g_current;
static void dump_current(int sig) {
    uint64_t h = 1469598103934665603ull;
    for (auto b : g_current) { h ^= b; h *= 1099511628211ull; }
    char name[64];
    std::snprintf(name, sizeof name, "crash-%016llx", (unsigned long long)h);
    FILE* f = std::fopen(name, "wb");
    if (f) { std::fwrite(g_current.data(), 1, g_current.size(), f); std::fclose(f); }
    std::fprintf(stderr, "standalone driver: signal %d on input of %zu bytes, saved as %s\n", sig, g_current.size(), name);
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}

static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static uint64_t next() { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17; return g_rng; }

static void run_one(const std::vector<uint8_t>& in) {
    g_current = in;
    LLVMFuzzerTestOneInput(in.data(), in.size());
}

int main(int argc, char** argv) {
    long runs = 0, max_len = 4096;
    std::vector<std::string> paths;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a.rfind("-runs=", 0) == 0) runs = std::atol(a.c_str() + 6);
        else if (a.rfind("-seed=", 0) == 0) g_rng ^= uint64_t(std::atoll(a.c_str() + 6)) * 0x2545F4914F6CDD1Dull;
        else if (a.rfind("-max_len=", 0) == 0) max_len = std::atol(a.c_str() + 9);
        else if (a[0] == '-') { std::fprintf(stderr, "ignoring option %s\n", a.c_str()); }
        else paths.push_back(a);
    }
    for (int s : {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL}) std::signal(s, dump_current);

    std::vector<std::vector<uint8_t>> corpus;
    for (auto& p : paths) {
        std::vector<fs::path> files;
        if (fs::is_directory(p)) { for (auto& e : fs::recursive_directory_iterator(p)) if (e.is_regular_file()) files.push_back(e.path()); }
        else if (fs::is_regular_file(p)) files.push_back(p);
        std::sort(files.begin(), files.end());
        for (auto& f : files) {
            std::ifstream in(f, std::ios::binary);
            std::vector<uint8_t> b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            corpus.push_back(b);
        }
    }
    std::vector<uint8_t> empty;
    run_one(empty);
    for (auto& c : corpus) run_one(c);
    std::printf("replayed %zu corpus inputs\n", corpus.size());
    if (corpus.empty()) corpus.push_back({0, 1, 2, 3, 4, 5, 6, 7});
    for (long r = 0; r < runs; r++) {
        std::vector<uint8_t> x = corpus[next() % corpus.size()];
        int nmut = 1 + int(next() % 4);
        for (int m = 0; m < nmut; m++) {
            switch (next() % 6) {
                case 0: if (!x.empty()) x[next() % x.size()] ^= uint8_t(1u << (next() % 8)); break;
                case 1: if (!x.empty()) x[next() % x.size()] = uint8_t(next()); break;
                case 2: if (!x.empty()) x.resize(next() % x.size()); break;
                case 3: if (long(x.size()) < max_len) x.insert(x.begin() + long(next() % (x.size() + 1)), uint8_t(next())); break;
                case 4: if (x.size() >= 4) { size_t i = next() % (x.size() - 3); uint32_t v = uint32_t(next() % 5) ? uint32_t(next()) : 0xFFFFFFFFu; std::memcpy(&x[i], &v, 4); } break;
                default: { size_t n = next() % 64; x.clear(); for (size_t i = 0; i < n; i++) x.push_back(uint8_t(next())); } break;
            }
        }
        if (long(x.size()) > max_len) x.resize(size_t(max_len));
        run_one(x);
    }
    if (runs) std::printf("completed %ld mutation runs without a crash\n", runs);
    return 0;
}
