// CCTS test suite. Covers the validation checklist from the project spec.
#include "ccts/scheme.hpp"
#include <cstdio>
#include <string>

using namespace ccts;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, name)                                                     \
    do {                                                                      \
        if (cond) { g_pass++; }                                               \
        else { g_fail++; std::printf("FAIL: %s (line %d)\n", name, __LINE__); } \
    } while (0)

static std::vector<uint8_t> msg_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

static std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}

// ---------------------------------------------------------------- SHAKE256
static void test_shake() {
    // Known-answer: SHAKE256(""), first 32 bytes.
    Shake256 x;
    auto out = x.squeeze(32);
    CHECK(hex(out.data(), 32) ==
              "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
          "SHAKE256 empty-input KAT");
    // Known-answer: SHAKE256("abc"), first 32 bytes.
    Shake256 y;
    y.absorb(std::string("abc"));
    auto out2 = y.squeeze(32);
    CHECK(hex(out2.data(), 32) ==
              "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
          "SHAKE256 'abc' KAT");
}

// ------------------------------------------------------------- field / matrix
static void test_field_and_matrix() {
    Field F(131);
    Drbg rng(msg_bytes("field-test-seed"));
    for (int t = 0; t < 200; t++) {
        uint32_t a = rng.field_elem(F), b = rng.field_elem(F), c = rng.field_elem(F);
        CHECK(F.mul(a, F.add(b, c)) == F.add(F.mul(a, b), F.mul(a, c)), "distributivity");
        CHECK(F.sub(F.add(a, b), b) == a, "add/sub inverse");
        if (a) CHECK(F.mul(a, F.inv(a)) == 1, "multiplicative inverse");
    }
    for (int t = 0; t < 20; t++) {
        auto [M, _] = sample_invertible(F, 9, rng);
        auto Minv = mat_inverse(F, M);
        CHECK(Minv.has_value(), "sampled matrix invertible");
        CHECK(mat_mul(F, M, *Minv) == Mat::identity(9), "M * M^-1 = I");
        CHECK(mat_mul(F, *Minv, M) == Mat::identity(9), "M^-1 * M = I");
    }
    // Singular matrix rejected.
    Mat S(3, 3); // zero matrix
    CHECK(!mat_inverse(F, S).has_value(), "singular matrix has no inverse");
}

// ----------------------------------------------------- tensor transform logic
static void test_tensor_transforms() {
    Field F(67);
    Drbg rng(msg_bytes("tensor-test-seed"));
    uint32_t k = 4, n1 = 2 * k + 1, n23 = k + 1;

    Vec c2 = distinct_column(F, n1, rng), c3 = distinct_column(F, n1, rng);
    Tensor3 phi = build_vwz(F, k, c2, c3);

    Mat X1(n1, n1);
    Vec x1d(n1);
    for (uint32_t i = 0; i < n1; i++) { x1d[i] = rng.nonzero_field_elem(F); X1.at(i, i) = x1d[i]; }
    auto [X2, r2] = sample_invertible(F, n23, rng);
    auto [X3, r3] = sample_invertible(F, n23, rng);
    (void)r2; (void)r3;

    Tensor3 psi = twist(F, phi, X1, X2, X3);

    // Twist by inverses recovers phi (transformation consistency).
    Mat X1inv(n1, n1);
    for (uint32_t i = 0; i < n1; i++) X1inv.at(i, i) = F.inv(x1d[i]);
    Tensor3 back = twist(F, psi, X1inv, *mat_inverse(F, X2), *mat_inverse(F, X3));
    CHECK(back == phi, "twist(twist(phi,X),X^-1) == phi");

    // Evaluation identity before/after basis change:
    // f1_psi(u, v) = X1^T f1_phi(X2 u, X3 v); X1 diagonal so X1^T = X1.
    for (int t = 0; t < 25; t++) {
        Vec u(n23), v(n23);
        for (auto& e : u) e = rng.field_elem(F);
        for (auto& e : v) e = rng.field_elem(F);
        Vec lhs = tensor_eval(F, psi, u, v);
        Vec rhs = tensor_eval(F, phi, mat_vec(F, X2, u), mat_vec(F, X3, v));
        for (uint32_t i = 0; i < n1; i++) rhs[i] = F.mul(rhs[i], x1d[i]);
        CHECK(lhs == rhs, "evaluation identity under basis change");
    }

    // Multilinear form agrees with evaluation contraction.
    Vec w1(n1);
    for (auto& e : w1) e = rng.field_elem(F);
    Vec u(n23), v(n23);
    for (auto& e : u) e = rng.field_elem(F);
    for (auto& e : v) e = rng.field_elem(F);
    uint32_t lhs = multilinear_form(F, psi, w1, u, v);
    Vec X1w1(n1);
    for (uint32_t i = 0; i < n1; i++) X1w1[i] = F.mul(x1d[i], w1[i]);
    uint32_t rhs = multilinear_form(F, phi, X1w1, mat_vec(F, X2, u), mat_vec(F, X3, v));
    CHECK(lhs == rhs, "f_psi(w1,u,v) = f_phi(X1w1,X2u,X3v)");
}

// ------------------------------------------------------------------- chords
static void test_chords() {
    Drbg rng(msg_bytes("chord-test-seed"));
    for (int t = 0; t < 30; t++) {
        ChordDiagram d = ChordDiagram::random(6, rng);
        CHECK(d.valid(), "random diagram valid");
        auto canon = d.canonical_sequence();
        for (uint32_t r = 0; r < d.endpoints(); r++) {
            CHECK(d.rotated(r).canonical_sequence() == canon,
                  "canonical encoding rotation-invariant");
            CHECK(d.rotated(r).closure_loops() == d.closure_loops(),
                  "closure loop count rotation-invariant");
        }
        CHECK(d.endpoints() % d.orbit_size() == 0, "orbit size divides 2n");
        // Serialization is stable across rotations.
        CHECK(d.rotated(3).canonical_bytes() == d.canonical_bytes(),
              "canonical bytes stable");
    }
    // Hand-checked examples on 4 endpoints.
    ChordDiagram cross{{2, 3, 0, 1}};   // crossing chords: 0-2, 1-3
    ChordDiagram nested{{1, 0, 3, 2}};  // adjacent chords: 0-1, 2-3
    CHECK(cross.canonical_sequence() == std::vector<uint32_t>({0, 1, 0, 1}),
          "crossing diagram canonical [0,1,0,1]");
    CHECK(nested.canonical_sequence() == std::vector<uint32_t>({0, 0, 1, 1}),
          "nested diagram canonical [0,0,1,1]");
    CHECK(cross.orbit_size() == 1, "crossing diagram fixed by all rotations (orbit 1)");
    CHECK(nested.orbit_size() == 2, "nested diagram orbit size 2");
    // Closure convention: loops = cycles of sigma = shift o match.
    // Crossing: single 4-cycle. Nested [1,0,3,2]: cycles (0 2)(1)(3) -> 3 loops.
    CHECK(cross.closure_loops() == 1, "crossing closure has 1 loop");
    CHECK(nested.closure_loops() == 3, "nested closure has 3 loops");
    Field F(37);
    CHECK(cross.closure_value(F, 2) == 2, "closure value d^loops (crossing)");
    CHECK(nested.closure_value(F, 2) == 8, "closure value d^loops (nested)");
}

// ------------------------------------------------- sign / verify / tampering
static void run_scheme_tests(Mode mode, const char* label) {
    Parameters p = (mode == Mode::chord_structured) ? Parameters::for_k_structured(8)
                 : (mode == Mode::chord_labeled)    ? Parameters::for_k_labeled(8)
                 : (mode == Mode::tri_chord)        ? Parameters::for_k_tri(8)
                                                    : Parameters::for_k(8);
    Drbg rng(msg_bytes(std::string("scheme-seed-") + label));
    KeyPair kp = keygen(p, rng, mode);
    Field F(p.q);

    auto m1 = msg_bytes("the treaty of chord diagrams"), m2 = msg_bytes("a different message");
    for (int t = 0; t < 20; t++) {
        Signature s = sign(m1, kp.sk, rng);
        CHECK(verify(m1, s, kp.pk), (std::string(label) + ": sign/verify roundtrip").c_str());
        CHECK(!verify(m2, s, kp.pk), (std::string(label) + ": reject wrong message").c_str());

        Signature bad_salt = s;
        bad_salt.salt[0] ^= 1;
        CHECK(!verify(m1, bad_salt, kp.pk), (std::string(label) + ": reject tampered salt").c_str());

        Signature bad_u = s;
        bad_u.u[t % bad_u.u.size()] = F.add(bad_u.u[t % bad_u.u.size()], 1);
        CHECK(!verify(m1, bad_u, kp.pk), (std::string(label) + ": reject tampered u").c_str());

        Signature bad_v = s;
        bad_v.v[(t + 3) % bad_v.v.size()] = F.add(bad_v.v[(t + 3) % bad_v.v.size()], 1);
        CHECK(!verify(m1, bad_v, kp.pk), (std::string(label) + ": reject tampered v").c_str());
    }

    // Multiple independent keys: cross-verification must fail (pk binding in hash).
    Drbg rng2(msg_bytes(std::string("scheme-seed2-") + label));
    KeyPair kp2 = keygen(p, rng2, mode);
    Signature s = sign(m1, kp.sk, rng);
    CHECK(verify(m1, s, kp.pk), "own-key verify");
    CHECK(!verify(m1, s, kp2.pk), "cross-key verify rejected");

    // Repeated randomized signatures of the same message all verify, and with a
    // fixed salt the two SamplePre3DB coins give exactly the two preimages of
    // the paper's Lemma 5. (The fixed-salt block assumes the full-sphere hash;
    // tri_chord's fixed-salt preimage multiplicity is tested separately in
    // test_tri_offsupport_coins.)
    {
        std::vector<std::vector<uint8_t>> serialized;
        for (int t = 0; t < 10; t++) {
            Signature st = sign(m1, kp.sk, rng);
            CHECK(verify(m1, st, kp.pk), "repeated randomized signature verifies");
            serialized.push_back(st.serialize());
        }
        if (mode == Mode::tri_chord) return;
        // Fixed salt, both coins, manually:
        Vec y = hash_to_sphere(p, kp.pk.digest, m1.data(), m1.size(), s.salt);
        Vec y0(2 * p.k + 1);
        for (uint32_t i = 0; i < y0.size(); i++) {
            uint32_t a = kp.sk.x1_perm.empty() ? i : kp.sk.x1_perm[i];
            y0[i] = F.mul(y[a], F.inv(kp.sk.x1_diag[i]));
        }
        std::vector<std::vector<uint8_t>> pre;
        for (int coin = 0; coin < 2; coin++) {
            Vec w2, w3;
            CHECK(vwz_preimage(F, p.k, kp.sk.c2, kp.sk.c3, y0, coin, w2, w3),
                  "fixed-salt preimage exists for both coins");
            Signature sc;
            sc.salt = s.salt;
            sc.u = mat_vec(F, kp.sk.X2inv, w2);
            sc.v = mat_vec(F, kp.sk.X3inv, w3);
            projectivize(F, sc.u);
            projectivize(F, sc.v);
            CHECK(verify(m1, sc, kp.pk), "both coin preimages verify");
            pre.push_back(sc.serialize());
        }
        CHECK(pre[0] != pre[1], "the two coin preimages are distinct (Lemma 5)");
    }
}

// -------------------------------------------------------------- determinism
static void test_determinism() {
    auto once = [&](Mode m) {
        Parameters p = (m == Mode::chord_structured) ? Parameters::for_k_structured(8)
                     : (m == Mode::chord_labeled)    ? Parameters::for_k_labeled(8)
                     : (m == Mode::tri_chord)        ? Parameters::for_k_tri(8)
                                                     : Parameters::for_k(8);
        Drbg rng(msg_bytes("determinism-seed"));
        KeyPair kp = keygen(p, rng, m);
        auto msg = msg_bytes("deterministic vector message");
        Signature s = sign(msg, kp.sk, rng);
        ByteWriter w;
        w.bytes(kp.pk.serialize());
        w.bytes(kp.sk.serialize());
        w.bytes(s.serialize());
        return w.buf;
    };
    CHECK(once(Mode::tensor_reference) == once(Mode::tensor_reference),
          "tensor_reference deterministic under fixed seed");
    CHECK(once(Mode::chord_tensor) == once(Mode::chord_tensor),
          "chord_tensor deterministic under fixed seed");
    CHECK(once(Mode::chord_structured) == once(Mode::chord_structured),
          "chord_structured deterministic under fixed seed");
    CHECK(once(Mode::chord_labeled) == once(Mode::chord_labeled),
          "chord_labeled deterministic under fixed seed");
    CHECK(once(Mode::tensor_reference) != once(Mode::chord_tensor),
          "modes derive different keys from the same seed");
    CHECK(once(Mode::chord_tensor) != once(Mode::chord_structured),
          "structured mode derives different keys from the same seed");
    CHECK(once(Mode::chord_structured) != once(Mode::chord_labeled),
          "labeled mode derives different keys from the same seed");
    CHECK(once(Mode::tri_chord) == once(Mode::tri_chord),
          "tri_chord deterministic under fixed seed");
    CHECK(once(Mode::tri_chord) != once(Mode::chord_structured),
          "tri mode derives different keys from the same seed");
}

// -------------------------- chord layer preserves the preimage algorithm ----
static void test_chord_preserves_preimage() {
    Parameters p = Parameters::for_k(6);
    Drbg rng(msg_bytes("chord-preserve-seed"));
    // Explicit diagram path.
    Drbg drng(msg_bytes("diagram-seed"));
    ChordDiagram d = ChordDiagram::random(p.k, drng);
    KeyPair kp = keygen(p, rng, Mode::chord_tensor, &d);
    Field F(p.q);
    // Lambda columns still have distinct entries (non-degeneracy preserved).
    auto distinct = [](const Vec& c) {
        for (size_t i = 0; i < c.size(); i++)
            for (size_t j = i + 1; j < c.size(); j++)
                if (c[i] == c[j]) return false;
        return true;
    };
    CHECK(distinct(kp.sk.c2) && distinct(kp.sk.c3),
          "chord-derived Lambda columns distinct");
    auto msg = msg_bytes("chord-derived key signs correctly");
    for (int t = 0; t < 30; t++) {
        Signature s = sign(msg, kp.sk, rng);
        CHECK(verify(msg, s, kp.pk), "chord_tensor preimage method preserved");
    }
}

// ------------------------- small-parameter enumeration of the target set ----
static void test_enumeration_small() {
    // k = 2, q = 11: enumerate every canonical sphere target and confirm the
    // preimage sampler hits it exactly (both coins).
    uint32_t k = 2;
    Parameters p;
    p.k = k;
    p.q = 11;
    Field F(p.q);
    Drbg rng(msg_bytes("enum-seed"));
    KeyPair kp = keygen(p, rng, Mode::tensor_reference);
    uint32_t n1 = 2 * k + 1;

    uint32_t targets = 0, hits = 0;
    // All supports of size k+1 = 3 among 5 indices; canonical first value 1.
    for (uint32_t a = 0; a < n1; a++)
        for (uint32_t b = a + 1; b < n1; b++)
            for (uint32_t c = b + 1; c < n1; c++)
                for (uint32_t vb = 1; vb < p.q; vb++)
                    for (uint32_t vc = 1; vc < p.q; vc++) {
                        Vec y(n1, 0);
                        y[a] = 1; y[b] = vb; y[c] = vc;
                        targets++;
                        Vec y0(n1);
                        for (uint32_t i = 0; i < n1; i++)
                            y0[i] = F.mul(y[i], F.inv(kp.sk.x1_diag[i]));
                        bool both = true;
                        for (int coin = 0; coin < 2; coin++) {
                            Vec w2, w3;
                            if (!vwz_preimage(F, k, kp.sk.c2, kp.sk.c3, y0, coin, w2, w3)) { both = false; break; }
                            Vec u = mat_vec(F, kp.sk.X2inv, w2);
                            Vec v = mat_vec(F, kp.sk.X3inv, w3);
                            Vec w = tensor_eval(F, kp.pk.psi, u, v);
                            projectivize(F, w);
                            Vec ycan = y; // already canonical
                            if (w != ycan) { both = false; break; }
                        }
                        if (both) hits++;
                    }
    std::printf("  enumeration: %u/%u canonical sphere targets hit by both coins\n", hits, targets);
    CHECK(targets == 1000, "enumeration covers |supports| * (q-1)^2 = 1000 targets");
    CHECK(hits == targets, "preimage method reaches the entire target set");
}

// ---------------- essential sanity check: linear forgery attempt ------------
// Fix u at random and try to solve P(u, .) = y linearly for v, with y a random
// sphere target. In boundary format this is 2k+1 equations in k+1 unknowns:
// overdetermined and expected inconsistent. As a negative control, the same
// attack against a cubic (k+1)^3 random tensor (square system) succeeds.
static void test_linear_forgery_sanity() {
    Parameters p = Parameters::for_k(6);
    Field F(p.q);
    Drbg rng(msg_bytes("sanity-seed"));
    KeyPair kp = keygen(p, rng, Mode::tensor_reference);
    uint32_t n1 = 2 * p.k + 1, n23 = p.k + 1;

    uint32_t boundary_success = 0, trials = 200;
    for (uint32_t t = 0; t < trials; t++) {
        Vec u(n23);
        for (auto& e : u) e = rng.field_elem(F);
        if (is_zero_vec(u)) continue;
        // Random canonical sphere target.
        std::vector<uint8_t> salt = rng.bytes(SALT_BYTES);
        auto m = msg_bytes("forgery-target");
        Vec y = hash_to_sphere(p, kp.pk.digest, m.data(), m.size(), salt);
        // Build A v = y with A[i][l] = sum_j psi[i][j][l] u[j].
        Mat A(n1, n23);
        for (uint32_t i = 0; i < n1; i++)
            for (uint32_t l = 0; l < n23; l++) {
                uint32_t acc = 0;
                for (uint32_t j = 0; j < n23; j++)
                    acc = F.add(acc, F.mul(kp.pk.psi.at(i, j, l), u[j]));
                A.at(i, l) = acc;
            }
        // The attacker may also exploit projective scaling: try all q-1 scalings
        // of the target (equivalently absorb the scale into v).
        bool found = false;
        for (uint32_t s = 1; s < F.q && !found; s++) {
            Vec ys(n1);
            for (uint32_t i = 0; i < n1; i++) ys[i] = F.mul(y[i], s);
            auto sol = solve_linear(F, A, ys);
            if (sol && !is_zero_vec(*sol)) found = true;
        }
        if (found) boundary_success++;
    }
    std::printf("  linear forgery vs boundary format: %u/%u fixed-u attempts succeed\n",
                boundary_success, trials);
    CHECK(boundary_success == 0,
          "boundary-format sphere targets resist fix-u-solve-v linear forgery");

    // Negative control: cubic format (k+1)^3, unconstrained target -> square
    // linear system, generically solvable.
    Tensor3 cubic(n23, n23, n23);
    for (auto& e : cubic.a) e = rng.field_elem(F);
    uint32_t cubic_success = 0, ctrials = 100;
    for (uint32_t t = 0; t < ctrials; t++) {
        Vec u(n23), y(n23);
        for (auto& e : u) e = rng.field_elem(F);
        for (auto& e : y) e = rng.field_elem(F);
        Mat A(n23, n23);
        for (uint32_t i = 0; i < n23; i++)
            for (uint32_t l = 0; l < n23; l++) {
                uint32_t acc = 0;
                for (uint32_t j = 0; j < n23; j++)
                    acc = F.add(acc, F.mul(cubic.at(i, j, l), u[j]));
                A.at(i, l) = acc;
            }
        if (solve_linear(F, A, y)) cubic_success++;
    }
    std::printf("  linear forgery vs cubic control: %u/%u attempts succeed\n",
                cubic_success, ctrials);
    CHECK(cubic_success > ctrials * 9 / 10,
          "cubic-format control confirms the attack works without the constraint");
}

// ------------------------------------------------ fast polynomial arithmetic
static void test_fastpoly() {
    // NTT known answer: (1 + 2X + 3X^2) * (4 + 5X) = 4 + 13X + 22X^2 + 15X^3.
    {
        auto c = ntt::convolve({1, 2, 3}, {4, 5});
        CHECK((c == std::vector<uint64_t>{4, 13, 22, 15}), "NTT convolution KAT");
    }
    Field F(65521); // largest 16-bit prime: room for large point sets
    Drbg rng(msg_bytes("fastpoly-seed"));
    auto rand_poly = [&](size_t n) {
        Vec p(n);
        for (auto& e : p) e = rng.field_elem(F);
        return p;
    };
    auto naive_mul = [&](const Vec& a, const Vec& b) {
        if (a.empty() || b.empty()) return Vec{};
        Vec c(a.size() + b.size() - 1, 0);
        for (size_t i = 0; i < a.size(); i++)
            for (size_t j = 0; j < b.size(); j++)
                c[i + j] = F.add(c[i + j], F.mul(a[i], b[j]));
        return c;
    };
    // Multiplication across the schoolbook/NTT threshold, odd sizes, embedded zeros.
    for (size_t na : {1u, 7u, 47u, 48u, 129u, 500u}) {
        for (size_t nb : {1u, 5u, 49u, 300u}) {
            Vec a = rand_poly(na), b = rand_poly(nb);
            if (na > 3) a[na / 2] = 0;
            CHECK(fp_mul(F, a, b) == naive_mul(a, b), "fp_mul matches schoolbook");
        }
    }
    // Division with remainder: a = q*b + r, deg r < deg b, both regimes.
    for (auto [na, nb] : std::vector<std::pair<size_t, size_t>>{
             {10, 4}, {80, 20}, {500, 90}, {1000, 501}, {40, 40}, {30, 100}}) {
        Vec a = rand_poly(na), b = rand_poly(nb);
        b.back() = 1 + rng.uniform(F.q - 1); // nonzero leading coeff
        Vec q, r;
        fp_divrem(F, a, b, q, r);
        Vec qb = naive_mul(q, b);
        Vec recon(std::max(qb.size(), r.size()), 0);
        for (size_t i = 0; i < recon.size(); i++)
            recon[i] = F.add(i < qb.size() ? qb[i] : 0, i < r.size() ? r[i] : 0);
        CHECK(fp_trim(recon) == fp_trim(a), "fp_divrem reconstructs a = q*b + r");
        CHECK(fp_trim(r).size() < fp_trim(b).size(), "fp_divrem remainder degree bound");
    }
    // Series inverse: a * inv(a) = 1 mod X^n.
    {
        Vec a = rand_poly(200);
        a[0] = 1 + rng.uniform(F.q - 1);
        Vec t = fp_series_inv(F, a, 200);
        Vec at = fp_mul_trunc(F, a, t, 200);
        bool ok = at[0] == 1;
        for (size_t i = 1; i < at.size(); i++) ok = ok && at[i] == 0;
        CHECK(ok, "Newton series inverse");
    }
    // Distinct evaluation points for multipoint / interpolation tests.
    auto distinct_points = [&](size_t n) {
        std::vector<bool> used(F.q, false);
        Vec xs;
        while (xs.size() < n) {
            uint32_t e = rng.field_elem(F);
            if (!used[e]) { used[e] = true; xs.push_back(e); }
        }
        return xs;
    };
    for (size_t n : {5u, 40u, 333u, 1024u}) {
        Vec xs = distinct_points(n);
        Vec f = rand_poly(n);
        Vec ev = fp_multipoint(F, f, xs);
        bool ok = true;
        for (size_t i = 0; i < n; i++) ok = ok && ev[i] == poly_eval(F, f, xs[i]);
        CHECK(ok, "fast multipoint evaluation matches Horner");
        // from_roots agreement
        CHECK(fp_from_roots(F, xs) == poly_from_roots(F, xs),
              "fast product tree matches naive from_roots");
        // interpolation agreement: the interpolant is unique, so bit-identical
        Vec ys = rand_poly(n);
        CHECK(fp_interpolate(F, xs, ys) == lagrange_interpolate(F, xs, ys),
              "fast interpolation is bit-identical to Lagrange");
    }
}

// Backend independence of the trapdoor sampler: fast and naive preimages are
// bit-identical (hence signatures and KAT vectors are backend-independent).
static void test_fast_backend_matches_naive() {
    Drbg rng(msg_bytes("backend-seed"));
    for (uint32_t k : {8u, 64u, 300u}) {
        Parameters p = Parameters::for_k(k);
        Field F(p.q);
        uint32_t n1 = 2 * k + 1;
        // distinct columns
        auto col = [&]() {
            std::vector<bool> used(F.q, false);
            Vec c;
            while (c.size() < n1) {
                uint32_t e = rng.field_elem(F);
                if (!used[e]) { used[e] = true; c.push_back(e); }
            }
            return c;
        };
        Vec c2 = col(), c3 = col();
        for (int trial = 0; trial < 5; trial++) {
            // sphere target: weight exactly k+1
            Vec y0(n1, 0);
            std::vector<uint32_t> idx(n1);
            for (uint32_t i = 0; i < n1; i++) idx[i] = i;
            for (uint32_t i = n1; i-- > 1;) std::swap(idx[i], idx[rng.uniform(i + 1)]);
            for (uint32_t t = 0; t < k + 1; t++) y0[idx[t]] = 1 + rng.uniform(F.q - 1);
            for (int coin = 0; coin < 2; coin++) {
                Vec w2n, w3n, w2f, w3f;
                CHECK(vwz_preimage(F, k, c2, c3, y0, coin, w2n, w3n, PolyBackend::naive),
                      "naive preimage exists");
                CHECK(vwz_preimage(F, k, c2, c3, y0, coin, w2f, w3f, PolyBackend::fast),
                      "fast preimage exists");
                CHECK(w2n == w2f && w3n == w3f,
                      "fast and naive preimages are bit-identical");
                // and it actually hits the target
                Tensor3 phi = build_vwz(F, k, c2, c3);
                if (k <= 8) CHECK(tensor_eval(F, phi, w2f, w3f) == y0,
                                  "preimage hits the target");
            }
        }
    }
    std::printf("  fast/naive backend agreement verified up to k=300\n");
}

// -------------------------------------------- structured chord layer & orbit
static void test_element_of_order() {
    Drbg rng(msg_bytes("order-seed"));
    for (uint32_t k : {2u, 8u, 16u, 32u}) {
        Parameters p = Parameters::for_k_structured(k);
        Field F(p.q);
        uint32_t n = 4 * k + 2;
        CHECK((p.q - 1) % n == 0, "for_k_structured: (4k+2) | (q-1)");
        CHECK(is_prime(p.q) && p.q > 4 * k, "for_k_structured: valid prime > 4k");
        uint32_t g = element_of_order(F, n, &rng);
        CHECK(F.pow(g, n) == 1, "g^n = 1");
        bool proper = true;
        for (uint32_t d : prime_factors(n))
            if (F.pow(g, n / d) == 1) proper = false;
        CHECK(proper, "g has exact order n");
    }
}

static void test_oriented_chords() {
    Drbg rng(msg_bytes("oriented-seed"));
    for (int t = 0; t < 20; t++) {
        uint32_t m = 5 + rng.uniform(12); // chords
        auto D = OrientedChordDiagram::random(m, rng);
        CHECK(D.valid(), "random oriented diagram is valid");
        uint32_t r = 1 + rng.uniform(2 * m - 1);
        auto Dr = D.rotated(r);
        CHECK(Dr.valid(), "rotation preserves validity");
        CHECK(D.closure_loops() == Dr.closure_loops(), "closure loops rotation-invariant");
        CHECK(D.canonical_sequence() == Dr.canonical_sequence(),
              "oriented canonical form rotation-invariant");
        CHECK(D.orbit_size() == Dr.orbit_size(), "orbit size rotation-invariant");
        CHECK((2 * m) % D.orbit_size() == 0, "orbit size divides 2m");
        // chord_list is a perfect tail/head split
        auto list = D.chord_list();
        CHECK(list.size() == m, "chord_list has one row per chord");
    }
}

// GPV-style subdiagram census: rotation invariance and completeness.
static void test_subdiagram_census() {
    Drbg rng(msg_bytes("census-seed"));
    auto binom = [](uint64_t n, uint64_t j) {
        uint64_t r = 1;
        for (uint64_t i = 0; i < j; i++) r = r * (n - i) / (i + 1);
        return r;
    };
    for (uint32_t m : {5u, 9u, 17u}) {
        for (int t = 0; t < 3; t++) {
            auto D = OrientedChordDiagram::random(m, rng);
            for (uint32_t deg : {1u, 2u, 3u}) {
                auto c0 = subdiagram_census(D, deg);
                uint64_t total = 0;
                for (auto& [type, cnt] : c0) { (void)type; total += cnt; }
                CHECK(total == binom(m, deg), "census counts every subset exactly once");
                uint32_t r = 1 + rng.uniform(2 * m - 1);
                CHECK(subdiagram_census(D.rotated(r), deg) == c0,
                      "subdiagram census is rotation-invariant");
            }
            CHECK(census_digest(D, 2) == census_digest(D.rotated(3), 2),
                  "census digest is rotation-invariant");
        }
    }
    // The census separates diagrams the coarser invariants may not: crossing
    // vs non-crossing pair have different degree-2 censuses.
    OrientedChordDiagram cross, nest;
    cross.base.match = {2, 3, 0, 1}; cross.is_tail = {1, 1, 0, 0};
    nest.base.match = {3, 2, 1, 0};  nest.is_tail = {1, 1, 0, 0};
    CHECK(subdiagram_census(cross, 2) != subdiagram_census(nest, 2),
          "census distinguishes crossing from nested pair");
}

// Labeled (cyclotomic) chord diagrams: product-group invariants and the
// automatic-distinctness lemma.
static void test_labeled_chords() {
    Drbg rng(msg_bytes("labeled-seed"));
    for (uint32_t k : {3u, 8u}) {
        Parameters p = Parameters::for_k_labeled(k);
        Field F(p.q);
        uint32_t m = 2 * k + 1, circle = 2 * m, N = p.label_N;
        CHECK(std::gcd(circle, N) == 1, "label modulus coprime to circle");
        CHECK((p.q - 1) % (circle * N) == 0, "both subgroups embed in F_q^*");
        for (int t = 0; t < 5; t++) {
            auto LD = LabeledChordDiagram::random(m, N, rng);
            CHECK(LD.valid(), "random labeled diagram is valid");
            uint32_t r = 1 + rng.uniform(circle - 1), d = rng.uniform(N);
            auto LDrd = LD.rotated(r).shifted(d);
            CHECK(LDrd.valid(), "product action preserves validity");
            CHECK(LD.canonical_sequence() == LDrd.canonical_sequence(),
                  "labeled canonical form invariant under Z/2m x Z/N");
            CHECK(LD.orbit_size() == LDrd.orbit_size(), "labeled orbit size invariant");
            CHECK((circle * N) % LD.orbit_size() == 0, "orbit size divides 2m*N");
            CHECK(LD.closure_loops() == LDrd.closure_loops(),
                  "closure loops invariant under product action");
            // Distinctness lemma: columns distinct with no rejection needed.
            uint32_t g = element_of_order(F, circle, &rng);
            uint32_t h = element_of_order(F, N, &rng);
            Vec c2, c3;
            lambda_from_labeled_diagram(F, LDrd, g, h, c2, c3);
            auto distinct = [](const Vec& c) {
                for (size_t i = 0; i < c.size(); i++)
                    for (size_t j = i + 1; j < c.size(); j++)
                        if (c[i] == c[j]) return false;
                return true;
            };
            CHECK(distinct(c2) && distinct(c3),
                  "DISTINCTNESS LEMMA: labeled Lambda columns automatically distinct");
        }
    }
}

// THE EXTENDED EQUIVARIANCE THEOREM (chord.hpp): the product action
// (rotation r, label shift delta) on a labeled diagram acts on the VWZ tensor
// as the monomial twist (P_pi, diag(v^j), diag(v^l)) with v = g^{-r} h^{delta}.
static void test_labeled_equivariance() {
    Drbg rng(msg_bytes("labeled-equivariance-seed"));
    uint32_t checked = 0;
    for (uint32_t k : {3u, 8u}) {
        Parameters p = Parameters::for_k_labeled(k);
        Field F(p.q);
        uint32_t m = 2 * k + 1, circle = 2 * m, N = p.label_N;
        for (int trial = 0; trial < 3; trial++) {
            auto LD = LabeledChordDiagram::random(m, N, rng);
            uint32_t g = element_of_order(F, circle, &rng);
            uint32_t h = element_of_order(F, N, &rng);
            Vec c2, c3;
            lambda_from_labeled_diagram(F, LD, g, h, c2, c3);
            Tensor3 phi = build_vwz(F, k, c2, c3);
            for (auto [r, d] : {std::pair<uint32_t, uint32_t>{1, 1},
                                {k, N - 1}, {circle - 1, 0}, {0, 1}}) {
                auto LDrd = LD.rotated(r).shifted(d);
                Vec c2r, c3r;
                lambda_from_labeled_diagram(F, LDrd, g, h, c2r, c3r);
                Tensor3 phir = build_vwz(F, k, c2r, c3r);

                // Row permutation as in the unlabeled theorem: chord with tail
                // t sits at rotated tail (t - r) mod circle.
                auto listD = LD.D.chord_list();
                auto listDr = LDrd.D.chord_list();
                std::vector<int32_t> row_of_tail(circle, -1);
                for (uint32_t j = 0; j < listDr.size(); j++)
                    row_of_tail[listDr[j].first] = int32_t(j);
                Vec pi(m), ones(m, 1);
                uint32_t v = F.mul(F.pow(g, circle - (r % circle)), F.pow(h, d));
                bool rows_match = true;
                for (uint32_t i = 0; i < m; i++) {
                    uint32_t t_rot = (listD[i].first + circle - r) % circle;
                    int32_t j = row_of_tail[t_rot];
                    CHECK(j >= 0, "rotated tail found (labeled)");
                    pi[i] = uint32_t(j);
                    rows_match = rows_match &&
                        c2r[pi[i]] == F.mul(v, c2[i]) &&
                        c3r[pi[i]] == F.mul(v, c3[i]);
                }
                CHECK(rows_match, "product action scales Lambda rows by g^{-r} h^{delta}");

                Mat X1 = monomial_matrix(m, pi, ones);
                Mat X2(k + 1, k + 1), X3(k + 1, k + 1);
                uint32_t vj = 1;
                for (uint32_t j = 0; j <= k; j++) {
                    X2.at(j, j) = vj;
                    X3.at(j, j) = vj;
                    vj = F.mul(vj, v);
                }
                CHECK(twist(F, phi, X1, X2, X3) == phir,
                      "EXTENDED EQUIVARIANCE: product action = monomial twist (exact)");
                checked++;
            }
        }
    }
    std::printf("  labeled equivariance verified exactly on %u (diagram, r, delta) tuples\n",
                checked);
}

static void test_labeled_lambda_properties() {
    Drbg rng(msg_bytes("labeled-props-seed"));
    for (uint32_t k : {4u, 8u}) {
        Parameters p = Parameters::for_k_labeled(k);
        Field F(p.q);
        uint32_t circle = 4 * k + 2, N = p.label_N;
        KeyPair kp = keygen(p, rng, Mode::chord_labeled);
        auto distinct = [](const Vec& c) {
            for (size_t i = 0; i < c.size(); i++)
                for (size_t j = i + 1; j < c.size(); j++)
                    if (c[i] == c[j]) return false;
            return true;
        };
        CHECK(distinct(kp.sk.c2) && distinct(kp.sk.c3),
              "labeled Lambda columns distinct (WZ non-degeneracy)");
        bool subgroup = true;
        for (auto e : kp.sk.c2) subgroup = subgroup && F.pow(e, circle * N) == 1;
        for (auto e : kp.sk.c3) subgroup = subgroup && F.pow(e, circle * N) == 1;
        CHECK(subgroup, "labeled Lambda entries lie in the order-(4k+2)N subgroup");
        CHECK(!kp.sk.x1_perm.empty(), "labeled mode uses monomial X1");
        CHECK(kp.sk.label_N == N && kp.sk.gen_h != 0, "label metadata recorded");
        CHECK(F.pow(kp.sk.gen_h, N) == 1 && kp.sk.gen_h != 1, "gen_h has order N");
        CHECK(!kp.sk.chord_census.empty(), "census digest recorded");
        auto msg = msg_bytes("labeled smoke");
        Signature s = sign(msg, kp.sk, rng);
        CHECK(verify(msg, s, kp.pk), "labeled-mode signature verifies");
    }
}

// THE EQUIVARIANCE THEOREM (chord.hpp): rotation of the oriented diagram acts
// on the structured VWZ tensor as an explicit monomial x diagonal twist.
static void test_rotation_equivariance() {
    Drbg rng(msg_bytes("equivariance-seed"));
    uint32_t checked = 0;
    for (uint32_t k : {3u, 8u}) {
        Parameters p = Parameters::for_k_structured(k);
        Field F(p.q);
        uint32_t m = 2 * k + 1, circle = 2 * m;
        for (int trial = 0; trial < 3; trial++) {
            auto D = OrientedChordDiagram::random(m, rng);
            uint32_t g = element_of_order(F, circle, &rng);
            Vec c2, c3;
            lambda_from_diagram(F, D, g, c2, c3);
            Tensor3 phi = build_vwz(F, k, c2, c3);
            for (uint32_t r : {1u, k, circle - 1}) {
                auto Dr = D.rotated(r);
                Vec c2r, c3r;
                lambda_from_diagram(F, Dr, g, c2r, c3r);
                Tensor3 phir = build_vwz(F, k, c2r, c3r);

                // Row permutation pi: chord with tail t sits at rotated tail
                // (t - r) mod circle. Rows are sorted by tail on both sides.
                auto listD = D.chord_list();
                auto listDr = Dr.chord_list();
                std::vector<int32_t> row_of_tail(circle, -1);
                for (uint32_t j = 0; j < listDr.size(); j++)
                    row_of_tail[listDr[j].first] = int32_t(j);
                Vec pi(m), ones(m, 1);
                bool rows_match = true;
                uint32_t s = F.pow(g, circle - (r % circle)); // s = g^{-r}
                for (uint32_t i = 0; i < m; i++) {
                    uint32_t t_rot = (listD[i].first + circle - r) % circle;
                    int32_t j = row_of_tail[t_rot];
                    CHECK(j >= 0, "rotated tail found");
                    pi[i] = uint32_t(j);
                    // Row-level identity: entries scale by s = g^{-r}.
                    rows_match = rows_match &&
                        c2r[pi[i]] == F.mul(s, c2[i]) &&
                        c3r[pi[i]] == F.mul(s, c3[i]);
                }
                CHECK(rows_match, "rotation scales Lambda rows by g^{-r}");

                // Tensor-level identity: phi<Lambda(rot_r D)> equals the twist
                // of phi<Lambda(D)> by (P_pi, diag(s^j), diag(s^l)).
                Mat X1 = monomial_matrix(m, pi, ones);
                Mat X2(k + 1, k + 1), X3(k + 1, k + 1);
                uint32_t sj = 1;
                for (uint32_t j = 0; j <= k; j++) {
                    X2.at(j, j) = sj;
                    X3.at(j, j) = sj;
                    sj = F.mul(sj, s);
                }
                CHECK(twist(F, phi, X1, X2, X3) == phir,
                      "EQUIVARIANCE: rotation = monomial/diagonal twist (exact)");
                checked++;
            }
        }
    }
    std::printf("  rotation equivariance verified exactly on %u (diagram, r) pairs\n",
                checked);
}

// Corollary at scheme level: keys generated from rotated diagrams (same
// randomness) have publicly isomorphic tensors, via an explicitly computable
// composition twist psi_B = psi_A^{(X1^-1 P X1, X2^-1 D2 X2, X3^-1 D3 X3)}.
static void test_orbit_corollary_scheme_level() {
    uint32_t k = 6;
    Parameters p = Parameters::for_k_structured(k);
    Field F(p.q);
    uint32_t m = 2 * k + 1, circle = 2 * m;

    Drbg drng(msg_bytes("orbit-diagram-seed"));
    auto D = OrientedChordDiagram::random(m, drng);
    uint32_t r = 5;
    auto Dr = D.rotated(r);

    Drbg r1(msg_bytes("orbit-keygen-seed"));
    KeyPair A = keygen(p, r1, Mode::chord_structured, nullptr, &D);
    Drbg r2(msg_bytes("orbit-keygen-seed"));
    KeyPair B = keygen(p, r2, Mode::chord_structured, nullptr, &Dr);
    CHECK(A.sk.gen_g == B.sk.gen_g && A.sk.rot == B.sk.rot,
          "same seed reproduces same auxiliary secrets");
    CHECK(A.sk.chord_canonical == B.sk.chord_canonical,
          "rotated diagrams share the canonical form stored with the key");
    CHECK(A.sk.chord_loops == B.sk.chord_loops && A.sk.chord_orbit == B.sk.chord_orbit,
          "rotation invariants (loops, orbit size) are equal across rotated keys");

    // Build the phi-level twist for the *effective* rotation between the two
    // Lambda's. Both keys pre-rotate by sk.rot, so the relative rotation is r.
    uint32_t g = A.sk.gen_g;
    auto DA = D.rotated(A.sk.rot), DB = Dr.rotated(B.sk.rot);
    auto listA = DA.chord_list(), listB = DB.chord_list();
    std::vector<int32_t> row_of_tail(circle, -1);
    for (uint32_t j = 0; j < listB.size(); j++)
        row_of_tail[listB[j].first] = int32_t(j);
    Vec pi(m), ones(m, 1);
    uint32_t s = F.pow(g, circle - (r % circle));
    for (uint32_t i = 0; i < m; i++)
        pi[i] = uint32_t(row_of_tail[(listA[i].first + circle - r) % circle]);
    Mat P = monomial_matrix(m, pi, ones);
    Mat D2(k + 1, k + 1), D3(k + 1, k + 1);
    uint32_t sj = 1;
    for (uint32_t j = 0; j <= k; j++) { D2.at(j, j) = sj; D3.at(j, j) = sj; sj = F.mul(sj, s); }

    // psi_B = psi_A twisted by (X1^-1 P X1, X2^-1 D2 X2, X3^-1 D3 X3).
    Mat X1 = monomial_matrix(m, A.sk.x1_perm, A.sk.x1_diag);
    Mat X1inv = *mat_inverse(F, X1);
    Mat M1 = mat_mul(F, mat_mul(F, X1inv, P), X1);
    Mat M2 = mat_mul(F, mat_mul(F, A.sk.X2inv, D2), A.sk.X2);
    Mat M3 = mat_mul(F, mat_mul(F, A.sk.X3inv, D3), A.sk.X3);
    CHECK(twist(F, A.pk.psi, M1, M2, M3) == B.pk.psi,
          "ORBIT COROLLARY: rotated-diagram public keys are explicitly isomorphic");
}

static void test_structured_lambda_properties() {
    Drbg rng(msg_bytes("structured-props-seed"));
    for (uint32_t k : {4u, 8u, 16u}) {
        Parameters p = Parameters::for_k_structured(k);
        Field F(p.q);
        uint32_t circle = 4 * k + 2;
        KeyPair kp = keygen(p, rng, Mode::chord_structured);
        auto distinct = [](const Vec& c) {
            for (size_t i = 0; i < c.size(); i++)
                for (size_t j = i + 1; j < c.size(); j++)
                    if (c[i] == c[j]) return false;
            return true;
        };
        CHECK(distinct(kp.sk.c2) && distinct(kp.sk.c3),
              "structured Lambda columns have distinct entries (WZ non-degeneracy)");
        bool subgroup = true;
        for (auto e : kp.sk.c2) subgroup = subgroup && F.pow(e, circle) == 1;
        for (auto e : kp.sk.c3) subgroup = subgroup && F.pow(e, circle) == 1;
        CHECK(subgroup, "structured Lambda entries lie in the order-(4k+2) subgroup");
        CHECK(!kp.sk.x1_perm.empty(), "structured mode uses monomial X1");
        // signatures under the monomial X1 verify (roundtrip smoke on top of
        // the full run_scheme_tests battery)
        auto msg = msg_bytes("structured smoke");
        Signature s = sign(msg, kp.sk, rng);
        CHECK(verify(msg, s, kp.pk), "structured-mode signature verifies");
    }
}

// ==================== TRI (tri_chord) mode, TRI design notes ====================

// Unit test: dense evaluation == factored evaluation. The
// published factor pairs (fx, fy) must reproduce the corresponding slices of
// the dense twisted tensor exactly - as rank-one outer products and under
// evaluation at random (u, v).
static void test_tri_factored_matches_dense() {
    Parameters p = Parameters::for_k_tri(8);
    Drbg rng(msg_bytes("tri-factored-seed"));
    KeyPair kp = keygen(p, rng, Mode::tri_chord);
    Field F(p.q);
    const uint32_t n1 = 2 * p.k + 1, n23 = p.k + 1;

    CHECK(kp.pk.psi.a.empty(), "tri pk holds no dense tensor");
    CHECK(kp.pk.sup.I.size() == p.sup.t && kp.pk.fx.size() == p.sup.t &&
          kp.pk.fy.size() == p.sup.t, "tri pk publishes exactly t factor pairs");
    for (uint32_t idx = 0; idx < p.sup.t; idx++) {
        size_t nz = 0;
        while (nz < kp.pk.fx[idx].size() && kp.pk.fx[idx][nz] == 0) nz++;
        CHECK(nz < kp.pk.fx[idx].size() && kp.pk.fx[idx][nz] == 1,
              "fx is projectively canonical (first nonzero = 1)");
    }
    bool sorted = true;
    for (uint32_t idx = 1; idx < p.sup.t; idx++)
        sorted = sorted && kp.pk.sup.I[idx - 1] < kp.pk.sup.I[idx];
    CHECK(sorted && kp.pk.sup.I.back() < n1, "support is sorted, distinct, in range");
    CHECK(kp.pk.sup.I == derive_support(kp.sk.support_seed, p.k, p.q, p.sup.t),
          "support re-derives from the stored seed");

    // Rebuild the dense tensor from the secret key (test-only; the scheme
    // itself never does this) and compare slice by slice on the support.
    Tensor3 phi = build_vwz(F, p.k, kp.sk.c2, kp.sk.c3);
    Mat X1 = monomial_matrix(n1, kp.sk.x1_perm, kp.sk.x1_diag);
    Tensor3 psi = twist(F, phi, X1, kp.sk.X2, kp.sk.X3);
    for (uint32_t idx = 0; idx < p.sup.t; idx++) {
        uint32_t a = kp.pk.sup.I[idx];
        bool slice_ok = true;
        for (uint32_t b = 0; b < n23; b++)
            for (uint32_t c = 0; c < n23; c++)
                slice_ok = slice_ok &&
                    psi.at(a, b, c) == F.mul(kp.pk.fx[idx][b], kp.pk.fy[idx][c]);
        CHECK(slice_ok, "published slice equals fx ox fy (rank one, exact)");
    }
    for (int t = 0; t < 25; t++) {
        Vec u(n23), v(n23);
        for (auto& e : u) e = rng.field_elem(F);
        for (auto& e : v) e = rng.field_elem(F);
        Vec full = tensor_eval(F, psi, u, v);
        bool eval_ok = true;
        for (uint32_t idx = 0; idx < p.sup.t; idx++)
            eval_ok = eval_ok && full[kp.pk.sup.I[idx]] ==
                F.mul(dot(F, kp.pk.fx[idx], u), dot(F, kp.pk.fy[idx], v));
        CHECK(eval_ok, "factored evaluation matches dense evaluation");
    }
}

// the margin unit test. At t = k+1 the linearization attack
// (fix u, solve the square linear system for v) MUST forge - the bound
// t >= k+2 is executable knowledge, not prose. Against the real margin
// t = k+1+m the same attack must fail (each attempt succeeds with
// probability ~ q^-m).
static void test_tri_margin_break() {
    Parameters p = Parameters::for_k_tri(8);
    Drbg rng(msg_bytes("tri-margin-seed"));
    KeyPair kp = keygen(p, rng, Mode::tri_chord);
    Field F(p.q);
    const uint32_t n23 = p.k + 1;
    auto m = msg_bytes("tri margin forgery target");

    // The linearization attack against an arbitrary TRI public key: fix u,
    // solve the t x (k+1) system  (fx_idx . u)(fy_idx . v) = y_idx  for v.
    auto attack = [&](const PublicKey& pk, Drbg& arng, Signature* out) -> bool {
        std::vector<uint8_t> salt = arng.bytes(SALT_BYTES);
        Vec y = hash_to_support_sphere(pk.params, pk.sup, pk.digest,
                                       m.data(), m.size(), salt);
        Vec u(n23);
        for (auto& e : u) e = arng.field_elem(F);
        if (is_zero_vec(u)) return false;
        const uint32_t t = pk.sup.t;
        Mat A(t, n23);
        for (uint32_t idx = 0; idx < t; idx++) {
            uint32_t du = dot(F, pk.fx[idx], u);
            for (uint32_t l = 0; l < n23; l++)
                A.at(idx, l) = F.mul(du, pk.fy[idx][l]);
        }
        auto sol = solve_linear(F, A, y);
        if (!sol || is_zero_vec(*sol)) return false;
        Signature s;
        s.salt = salt;
        s.u = u;
        s.v = *sol;
        if (!verify(m.data(), m.size(), s, pk)) return false;
        if (out) *out = s;
        return true;
    };

    // (a) Truncate the support to t = k+1 (digest recomputed over the
    // truncated published data): total break, a few u-trials suffice.
    PublicKey broken = kp.pk;
    broken.sup.t = p.k + 1;
    broken.sup.I.resize(p.k + 1);
    broken.fx.resize(p.k + 1);
    broken.fy.resize(p.k + 1);
    broken.recompute_digest();
    Drbg atk(msg_bytes("tri-margin-attacker"));
    bool forged = false;
    Signature forgery;
    for (int trial = 0; trial < 20 && !forged; trial++)
        forged = attack(broken, atk, &forgery);
    CHECK(forged, "MARGIN BOUND: t = k+1 linearization forgery succeeds (total break)");

    // (b) The real key (t = k+1+m, m >= 1) resists the identical attack.
    uint32_t successes = 0;
    for (int trial = 0; trial < 50; trial++)
        if (attack(kp.pk, atk, nullptr)) successes++;
    std::printf("  tri margin: %u/50 linearization attempts forge at t=k+1+%u\n",
                successes, p.sup.t - (p.k + 1));
    CHECK(successes == 0, "margin t = k+1+m resists the linearization attack");
}

// rotation of the diagram composed with support
// re-derivation. Restriction commutes with rotation (chord.hpp), so the
// sub-diagram visible through the support is a well-defined function of the
// chord subset - independent of which rotation representative generated the
// key - while the support itself, being seed-derived, is identical across the
// two keys and rotation-generic.
static void test_tri_support_equivariance() {
    Parameters p = Parameters::for_k_tri(8);
    Field F(p.q);
    const uint32_t m = 2 * p.k + 1, circle = 2 * m;
    Drbg drng(msg_bytes("tri-equivariance-diagram"));
    auto D = OrientedChordDiagram::random(m, drng);

    // Chord-level lemma: restrict-then-rotate == rotate-then-restrict, up to
    // rotation of the small diagram (equal canonical bytes).
    for (uint32_t r : {1u, 7u, circle - 2}) {
        auto Dr = D.rotated(r);
        auto listD = D.chord_list(), listDr = Dr.chord_list();
        std::vector<int32_t> row_of_tail(circle, -1);
        for (uint32_t j = 0; j < listDr.size(); j++)
            row_of_tail[listDr[j].first] = int32_t(j);
        std::vector<uint32_t> rows = {0, 2, 3, 5, 8, 11, 12, 16};
        std::vector<uint32_t> mapped;
        for (uint32_t i : rows) {
            int32_t j = row_of_tail[(listD[i].first + circle - r) % circle];
            CHECK(j >= 0, "rotated tail found");
            mapped.push_back(uint32_t(j));
        }
        CHECK(D.restricted(rows).canonical_bytes() ==
                  Dr.restricted(mapped).canonical_bytes(),
              "restriction commutes with rotation (canonical bytes)");
    }

    // Scheme level: two tri keys from D and a rotation of D, same seed. The
    // support derivation consumes the same DRBG stream, so I is identical;
    // the visible chord subset, mapped through the rotation's row
    // correspondence, has the same canonical sub-diagram.
    const uint32_t r = 7;
    auto Dr = D.rotated(r);
    Drbg r1(msg_bytes("tri-equivariance-keygen"));
    KeyPair A = keygen(p, r1, Mode::tri_chord, nullptr, &D);
    Drbg r2(msg_bytes("tri-equivariance-keygen"));
    KeyPair B = keygen(p, r2, Mode::tri_chord, nullptr, &Dr);
    CHECK(A.pk.sup.I == B.pk.sup.I,
          "support re-derivation is diagram-independent (same seed, same I)");
    CHECK(A.sk.rot == B.sk.rot && A.sk.x1_perm == B.sk.x1_perm,
          "same seed reproduces the same auxiliary secrets");

    auto sub_A = tri_visible_subdiagram(A.sk);
    CHECK(sub_A.valid() && sub_A.chords() == p.sup.t,
          "visible sub-diagram is a valid diagram on t chords");

    // Row correspondence between the two effective diagrams (B_eff = A_eff
    // rotated by r), applied to A's visible rows.
    auto& Aeff = A.sk.chord_diagram;
    auto& Beff = B.sk.chord_diagram;
    auto listA = Aeff.chord_list(), listB = Beff.chord_list();
    std::vector<int32_t> row_of_tail(circle, -1);
    for (uint32_t j = 0; j < listB.size(); j++)
        row_of_tail[listB[j].first] = int32_t(j);
    std::vector<uint32_t> ipA(m);
    for (uint32_t i = 0; i < m; i++) ipA[A.sk.x1_perm[i]] = i;
    std::vector<uint32_t> rowsA, rowsB;
    for (uint32_t a : A.pk.sup.I) rowsA.push_back(ipA[a]);
    for (uint32_t i : rowsA) {
        int32_t j = row_of_tail[(listA[i].first + circle - r) % circle];
        CHECK(j >= 0, "rotated tail found (scheme level)");
        rowsB.push_back(uint32_t(j));
    }
    CHECK(Aeff.restricted(rowsA).canonical_bytes() ==
              Beff.restricted(rowsB).canonical_bytes(),
          "visible sub-diagram is rotation-covariant through the support");
    (void)F;
}

// TRI preimage entropy (TRI design notes Sec. 4.2): with the salt fixed, distinct
// off-support extensions and both SamplePre3DB coins give distinct verifying
// signatures - the enlarged coin space that replaces the single Z/2 coin.
static void test_tri_offsupport_coins() {
    Parameters p = Parameters::for_k_tri(8);
    Drbg rng(msg_bytes("tri-coins-seed"));
    KeyPair kp = keygen(p, rng, Mode::tri_chord);
    Field F(p.q);
    const uint32_t n1 = 2 * p.k + 1;
    auto m = msg_bytes("tri fixed-salt preimage multiplicity");

    std::vector<uint8_t> salt = rng.bytes(SALT_BYTES);
    Vec ys = hash_to_support_sphere(p, kp.sk.sup, kp.sk.pk_digest,
                                    m.data(), m.size(), salt);
    std::vector<bool> in_I(n1, false);
    for (size_t idx = 0; idx < kp.sk.sup.I.size(); idx++)
        in_I[kp.sk.sup.I[idx]] = true;

    std::vector<std::vector<uint8_t>> seen;
    for (int ext = 0; ext < 3; ext++) {          // three off-support extensions
        Vec yhat(n1, 0);
        for (size_t idx = 0; idx < kp.sk.sup.I.size(); idx++)
            yhat[kp.sk.sup.I[idx]] = ys[idx];
        uint32_t placed = 0;
        for (uint32_t i = 0; i < n1 && placed < p.k + 1 - p.sup.w; i++)
            if (!in_I[i]) { yhat[i] = 1 + ((ext * 7 + placed) % (p.q - 1)); placed++; }
        CHECK(hamming_weight(yhat) == p.k + 1, "extended target lies on the sphere");
        Vec y0(n1);
        for (uint32_t i = 0; i < n1; i++) {
            uint32_t a = kp.sk.x1_perm.empty() ? i : kp.sk.x1_perm[i];
            y0[i] = F.mul(yhat[a], F.inv(kp.sk.x1_diag[i]));
        }
        for (int coin = 0; coin < 2; coin++) {   // times both SamplePre3DB coins
            Vec w2, w3;
            CHECK(vwz_preimage(F, p.k, kp.sk.c2, kp.sk.c3, y0, coin, w2, w3),
                  "preimage exists for every extension and coin");
            Signature sc;
            sc.salt = salt;
            sc.u = mat_vec(F, kp.sk.X2inv, w2);
            sc.v = mat_vec(F, kp.sk.X3inv, w3);
            projectivize(F, sc.u);
            projectivize(F, sc.v);
            CHECK(verify(m.data(), m.size(), sc, kp.pk),
                  "every (extension, coin) preimage verifies against the support");
            seen.push_back(sc.serialize());
        }
    }
    bool all_distinct = true;
    for (size_t i = 0; i < seen.size(); i++)
        for (size_t j = i + 1; j < seen.size(); j++)
            all_distinct = all_distinct && seen[i] != seen[j];
    CHECK(all_distinct, "the 6 fixed-salt preimages are pairwise distinct");
}

// Packed public key size (TRI design notes Sec. 3.5 + Sec. 7.5 Tier 1): exact
// framing arithmetic and the saving against both the 2-byte factored framing
// and the dense serialization.
static void test_tri_pk_size() {
    Parameters p = Parameters::for_k_tri(8);
    Drbg rng(msg_bytes("tri-size-seed"));
    KeyPair kp = keygen(p, rng, Mode::tri_chord);
    const uint32_t n1 = 2 * p.k + 1, n23 = p.k + 1, t = p.sup.t;
    const uint32_t b = elem_bits(p.q), bnz = elem_bits(p.k + 1);
    size_t bits = 0;
    for (uint32_t idx = 0; idx < t; idx++) {
        uint32_t nz = 0;
        while (kp.pk.fx[idx][nz] == 0) nz++;
        bits += bnz + size_t(p.k - nz) * b + size_t(n23) * b;
    }
    // k,q (8) + tag (1) + t,w (8) + seed (4+32) + packed payload (4 + bits).
    size_t expected = 8 + 1 + 8 + (4 + 32) + 4 + (bits + 7) / 8;
    CHECK(kp.pk.serialize().size() == expected, "packed tri pk framing size is exact");
    size_t v1 = 8 + 1 + 8 + (4 + 2 * t) + size_t(t) * 2 * (4 + 2 * n23);
    size_t dense = 8 + 12 + size_t(2) * n1 * n23 * n23;
    std::printf("  tri pk: %zu B packed vs %zu B 2-byte factored vs %zu B dense (%.1fx)\n",
                expected, v1, dense, double(dense) / double(expected));
    CHECK(expected < v1, "bit packing beats the 2-byte factored framing");
    CHECK(expected * 8 < dense, "packed pk is at least 8x smaller than dense at k=8");
}

// Tier-1 primitives: fixed-width bit packing round-trips exactly at every
// width in the prototype range.
static void test_bitpack_roundtrip() {
    Drbg rng(msg_bytes("bitpack-seed"));
    for (uint32_t q : {3u, 19u, 103u, 1031u, 65521u}) {
        const uint32_t b = elem_bits(q);
        for (size_t n : {1u, 9u, 17u, 100u}) {
            Vec v(n);
            for (auto& e : v) e = rng.uniform(q);
            BitWriter bw;
            for (auto e : v) bw.bits(e, b);
            auto buf = bw.finish();
            CHECK(buf.size() == (size_t(n) * b + 7) / 8, "packed payload size is exact");
            BitReader br(buf);
            bool ok = true;
            for (auto e : v) ok = ok && br.bits(b) == e;
            CHECK(ok, "bit packing round-trips exactly");
        }
    }
    CHECK(elem_bits(103) == 7 && elem_bits(1031) == 11 && elem_bits(65521) == 16,
          "elem_bits known answers");
}

// Public-key serialization round-trip, both framings. For TRI this also
// exercises the seed->support re-derivation and the implicit canonical
// prefix of fx, including the nz > 0 path (a key whose slice has a leading
// zero in x), which occurs for a random key with probability ~ t/q.
static void test_pk_serialization_roundtrip() {
    // Dense framing (tensor_reference).
    {
        Parameters p = Parameters::for_k(6);
        Drbg rng(msg_bytes("pk-roundtrip-dense"));
        KeyPair kp = keygen(p, rng, Mode::tensor_reference);
        PublicKey pk2 = PublicKey::deserialize(kp.pk.serialize());
        CHECK(pk2.psi == kp.pk.psi && pk2.digest == kp.pk.digest,
              "dense pk round-trips with identical tensor and digest");
        auto m = msg_bytes("dense roundtrip message");
        Signature s = sign(m, kp.sk, rng);
        CHECK(verify(m, s, pk2), "signature verifies against deserialized dense pk");
    }
    // TRI packed framing; hunt for a key exercising nz > 0.
    Parameters p = Parameters::for_k_tri(8);
    bool nz_seen = false;
    for (int trial = 0; trial < 300; trial++) {
        Drbg rng(msg_bytes("pk-roundtrip-tri-" + std::to_string(trial)));
        KeyPair kp = keygen(p, rng, Mode::tri_chord);
        bool has_nz = false;
        for (auto& x : kp.pk.fx) has_nz = has_nz || x[0] == 0;
        if (trial > 0 && !has_nz && nz_seen) continue; // full checks: trial 0 + first nz key
        PublicKey pk2 = PublicKey::deserialize(kp.pk.serialize());
        bool fields = pk2.sup.t == kp.pk.sup.t && pk2.sup.w == kp.pk.sup.w &&
                      pk2.sup.I == kp.pk.sup.I &&
                      pk2.support_seed == kp.pk.support_seed;
        for (uint32_t i = 0; i < p.sup.t; i++)
            fields = fields && pk2.fx[i] == kp.pk.fx[i] && pk2.fy[i] == kp.pk.fy[i];
        CHECK(fields, "tri pk round-trips every published field");
        CHECK(pk2.digest == kp.pk.digest, "tri pk digest is reproduced (canonical framing)");
        auto m = msg_bytes("tri roundtrip message");
        Signature s = sign(m, kp.sk, rng);
        CHECK(verify(m, s, pk2), "signature verifies against deserialized tri pk");
        if (has_nz && !nz_seen) {
            nz_seen = true;
            std::printf("  tri pk roundtrip: nz>0 slice found at trial %d\n", trial);
        }
        if (nz_seen && trial > 0) break;
    }
    CHECK(nz_seen, "leading-zero fx slice (implicit-prefix path) exercised");
}

// Radix (base-q) coding: exact round-trips, exact payload lengths, and the
// strict win over fixed-width packing when q sits just above a power of two.
static void test_radix_roundtrip() {
    Drbg rng(msg_bytes("radix-seed"));
    for (uint32_t q : {3u, 19u, 103u, 2053u, 65521u}) {
        for (size_t n : {1u, 9u, 34u, 257u}) {
            Vec v(n);
            for (auto& e : v) e = rng.uniform(q);
            auto packed = radix_pack(v, q);
            CHECK(packed.size() == radix_len(q, n), "radix payload length is exact");
            CHECK(packed.size() <= (n * elem_bits(q) + 7) / 8,
                  "radix coding never exceeds fixed-width packing");
            CHECK(radix_unpack(packed, q, n) == v, "radix coding round-trips exactly");
        }
    }
    // The k = 256 signature payload: 514 elements of F_2053 in 707 bytes
    // (11.004 bits/element) versus 771 fixed-width - the ~731 B signature.
    CHECK(radix_len(2053, 514) == 707, "radix_len(2053, 514) == 707 (731 B signature)");
    CHECK(radix_len(2053, 514) < (514 * elem_bits(2053) + 7) / 8,
          "radix coding strictly beats fixed-width at q = 2053");
}

// Packed signature encoding (the tri_chord wire format) round-trips and its
// size matches the closed form 20 + 4 + radix_len(q, 2(k+1)).
static void test_packed_signature() {
    Parameters p = Parameters::for_k_tri(8);
    Drbg rng(msg_bytes("packed-sig-seed"));
    KeyPair kp = keygen(p, rng, Mode::tri_chord);
    auto m = msg_bytes("packed signature message");
    for (int t = 0; t < 10; t++) {
        Signature s = sign(m, kp.sk, rng);
        auto packed = serialize_signature_packed(s, p);
        size_t expected = (4 + SALT_BYTES) + 4 + radix_len(p.q, size_t(2) * (p.k + 1));
        CHECK(packed.size() == expected, "packed signature size is exact");
        CHECK(packed.size() < s.serialize().size(),
              "packed signature is smaller than the 2-byte framing");
        Signature s2 = deserialize_signature_packed(packed, p);
        CHECK(s2.salt == s.salt && s2.u == s.u && s2.v == s.v,
              "packed signature round-trips exactly");
        CHECK(verify(m, s2, kp.pk), "deserialized packed signature verifies");
    }
}

int main() {
    test_shake();
    test_field_and_matrix();
    test_tensor_transforms();
    test_chords();
    test_fastpoly();
    test_fast_backend_matches_naive();
    test_element_of_order();
    test_oriented_chords();
    test_subdiagram_census();
    test_labeled_chords();
    test_labeled_equivariance();
    test_labeled_lambda_properties();
    test_rotation_equivariance();
    test_orbit_corollary_scheme_level();
    test_structured_lambda_properties();
    run_scheme_tests(Mode::tensor_reference, "tensor_reference");
    run_scheme_tests(Mode::chord_tensor, "chord_tensor");
    run_scheme_tests(Mode::chord_structured, "chord_structured");
    run_scheme_tests(Mode::chord_labeled, "chord_labeled");
    run_scheme_tests(Mode::tri_chord, "tri_chord");
    test_tri_factored_matches_dense();
    test_tri_margin_break();
    test_tri_support_equivariance();
    test_tri_offsupport_coins();
    test_tri_pk_size();
    test_bitpack_roundtrip();
    test_radix_roundtrip();
    test_pk_serialization_roundtrip();
    test_packed_signature();
    test_determinism();
    test_chord_preserves_preimage();
    test_enumeration_small();
    test_linear_forgery_sanity();
    std::printf("\n%d checks passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
