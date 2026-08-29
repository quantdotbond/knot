// Valgrind-memcheck based secret-dependency detection for KNOT in the style
// of ctgrind: secret key material is marked UNDEFINED with
// VALGRIND_MAKE_MEM_UNDEFINED; memcheck then reports every conditional
// branch and every memory access whose address depends on undefined (=
// secret) data. Each report is a secret-dependent branch or secret-indexed
// access on the executed path.
//
//   valgrind --error-exitcode=99 --track-origins=no ./ctgrind_knot [<mode>/k=<k>]
//
// A run with zero reports is NOT a proof of constant-time execution: memcheck
// does not model variable-latency instructions (division, some multiplies)
// and only covers executed paths. Without Valgrind headers the binary still
// builds and runs (marking calls become no-ops).
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <cstdlib>
#include <cstring>
#if __has_include(<valgrind/memcheck.h>)
#include <valgrind/memcheck.h>
#define HAVE_MEMCHECK 1
#else
#define HAVE_MEMCHECK 0
#define VALGRIND_MAKE_MEM_UNDEFINED(p, n) ((void)0)
#define VALGRIND_MAKE_MEM_DEFINED(p, n) ((void)0)
#define RUNNING_ON_VALGRIND 0
#endif

using namespace ccts;
using namespace knot_adapter;
using namespace knot_test;

template <class T> static void mark_secret(std::vector<T>& v) {
    if (!v.empty()) VALGRIND_MAKE_MEM_UNDEFINED(v.data(), v.size() * sizeof(T));
}
template <class T> static void mark_public(std::vector<T>& v) {
    if (!v.empty()) VALGRIND_MAKE_MEM_DEFINED(v.data(), v.size() * sizeof(T));
}

int main(int argc, char** argv) {
    std::string set = argc > 1 ? argv[1] : "tensor_reference/k=8";
    size_t sl = set.find("/k=");
    auto m = mode_from_name(set.substr(0, sl));
    if (!m || sl == std::string::npos) { std::fprintf(stderr, "unknown parameter set %s\n", set.c_str()); return 2; }
    ParamSet ps{*m, uint32_t(std::stoul(set.substr(sl + 3)))};
    Drbg rng = TestOnlyDeterministicRng::from_label("ctgrind|" + set);
    KeyPair kp = keygen(ps, rng);
    auto msg = bytes_of("ctgrind message");
    std::printf("ctgrind harness: %s, memcheck headers %s, under valgrind: %d\n",
                set.c_str(), HAVE_MEMCHECK ? "present" : "absent", int(RUNNING_ON_VALGRIND));

    // Secret material: Lambda columns, X1 monomial, X2/X3 and inverses, chord
    // data. Public-key data stays defined. The DRBG stream (salt, coins) is
    // treated as public randomness for this experiment.
    SecretKey& sk = kp.sk;
    mark_secret(sk.c2); mark_secret(sk.c3);
    mark_secret(sk.x1_diag); mark_secret(sk.x1_perm);
    mark_secret(sk.X2.a); mark_secret(sk.X3.a); mark_secret(sk.X2inv.a); mark_secret(sk.X3inv.a);
    mark_secret(sk.chord_canonical); mark_secret(sk.chord_labels); mark_secret(sk.chord_census);
    if (sk.gen_g) VALGRIND_MAKE_MEM_UNDEFINED(&sk.gen_g, sizeof sk.gen_g);
    if (sk.rot) VALGRIND_MAKE_MEM_UNDEFINED(&sk.rot, sizeof sk.rot);

    Signature s = sign(msg.data(), msg.size(), sk, rng);
    mark_public(s.u); mark_public(s.v); mark_public(s.salt);
    bool ok = verify(msg, s, kp.pk);
    std::printf("signature verifies: %d\n", int(ok));
    return ok ? 0 : 1;
}
