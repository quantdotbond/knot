#pragma once
// Shared helpers for the production test layer: check macros with a
// machine-readable summary, hex coding, byte helpers. No dependency on the
// core beyond what individual tests include.
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

namespace knot_test {

struct Summary {
    int pass = 0, fail = 0;
    std::vector<std::string> failures;
    std::string suite;
    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
};
inline Summary& summary() { static Summary s; return s; }

inline void check(bool cond, const char* what, const char* file, int line) {
    if (cond) { summary().pass++; return; }
    summary().fail++;
    std::string msg = std::string(what) + " (" + file + ":" + std::to_string(line) + ")";
    summary().failures.push_back(msg);
    std::printf("FAIL: %s\n", msg.c_str());
}
#define KCHECK(cond, what) ::knot_test::check((cond), (what), __FILE__, __LINE__)

inline std::string json_escape(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else o += c;
    }
    return o;
}

// Print the summary; if KNOT_TEST_JSON is set, also write a JSON record there.
inline int finish(const char* suite_name) {
    Summary& s = summary();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - s.t0).count();
    std::printf("%s: %d checks passed, %d failed (%lld ms)\n", suite_name, s.pass, s.fail,
                (long long)ms);
    if (const char* path = std::getenv("KNOT_TEST_JSON")) {
        FILE* f = std::fopen(path, "w");
        if (f) {
            std::fprintf(f, "{\"record\":\"test-result\",\"suite\":\"%s\",\"passed\":%d,\"failed\":%d,"
                            "\"duration_ms\":%lld,\"status\":\"%s\",\"failures\":[",
                         suite_name, s.pass, s.fail, (long long)ms, s.fail ? "fail" : "pass");
            for (size_t i = 0; i < s.failures.size(); i++)
                std::fprintf(f, "%s\"%s\"", i ? "," : "", json_escape(s.failures[i]).c_str());
            std::fprintf(f, "]}\n");
            std::fclose(f);
        }
    }
    return s.fail ? 1 : 0;
}

inline std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
inline std::string hex(const std::vector<uint8_t>& v) { return hex(v.data(), v.size()); }
template <size_t N> std::string hex(const std::array<uint8_t, N>& a) { return hex(a.data(), N); }

inline bool unhex(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int a = nib(s[i]), b = nib(s[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back(uint8_t(a << 4 | b));
    }
    return true;
}

// Integer from the environment with a default; strtol with full validation.
inline long env_long(const char* name, long dflt) {
    const char* v = std::getenv(name);
    if (!v || !*v) return dflt;
    char* end = nullptr;
    long x = std::strtol(v, &end, 10);
    return (end && *end == '\0') ? x : dflt;
}
inline bool env_flag(const char* name) { return env_long(name, 0) != 0; }

inline std::vector<uint8_t> bytes_of(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace knot_test
