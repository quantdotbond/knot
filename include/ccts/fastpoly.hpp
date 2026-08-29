#pragma once
// Nearly linear time univariate polynomial arithmetic over F_q, implementing
// the "fast variants" of ePrint 2025/624 Sec. 4: subproduct trees, Newton
// power-series inversion, fast division with remainder, fast multipoint
// evaluation (remainder trees), and fast interpolation (von zur Gathen &
// Gerhard, Modern Computer Algebra, Algorithms 10.5 / 10.9 / 10.11).
//
// Multiplication is exact-lift NTT over the Goldilocks prime (ntt.hpp) above a
// schoolbook threshold. All routines produce bit-identical results to the
// naive poly.hpp routines (the interpolant of a set of points is unique), so
// the trapdoor preimage sampler's output is backend-independent.
#include "poly.hpp"
#include "ntt.hpp"
#include <memory>

namespace ccts {

// Below this total size, schoolbook multiplication beats NTT setup cost.
inline constexpr size_t FP_MUL_SCHOOLBOOK_LIMIT = 96;
// Subtree hybrid cutoff: below this many points, direct O(t^2) methods win.
inline constexpr uint32_t FP_TREE_BASE_POINTS = 16;

inline Vec fp_trim(Vec a) {
    while (!a.empty() && a.back() == 0) a.pop_back();
    return a;
}

inline Vec fp_mul(const Field& F, const Vec& a, const Vec& b) {
    if (a.empty() || b.empty()) return {};
    if (a.size() + b.size() < FP_MUL_SCHOOLBOOK_LIMIT) {
        Vec c(a.size() + b.size() - 1, 0);
        for (size_t i = 0; i < a.size(); i++) {
            if (!a[i]) continue;
            for (size_t j = 0; j < b.size(); j++)
                c[i + j] = F.add(c[i + j], F.mul(a[i], b[j]));
        }
        return c;
    }
    std::vector<uint64_t> la(a.begin(), a.end()), lb(b.begin(), b.end());
    auto lc = ntt::convolve(la, lb);
    Vec c(lc.size());
    for (size_t i = 0; i < lc.size(); i++) c[i] = uint32_t(lc[i] % F.q);
    return c;
}

// Truncated product mod X^n.
inline Vec fp_mul_trunc(const Field& F, const Vec& a, const Vec& b, size_t n) {
    Vec c = fp_mul(F, a, b);
    if (c.size() > n) c.resize(n);
    return c;
}

// Power-series inverse of a mod X^n (requires a[0] != 0), by Newton iteration:
// t <- t * (2 - a*t), doubling precision each round.
inline Vec fp_series_inv(const Field& F, const Vec& a, size_t n) {
    assert(!a.empty() && a[0] != 0);
    Vec t{F.inv(a[0])};
    for (size_t m = 1; m < n; m <<= 1) {
        size_t nm = std::min(2 * m, n);
        Vec atrunc(a.begin(), a.begin() + std::min(a.size(), nm));
        Vec at = fp_mul_trunc(F, atrunc, t, nm);
        Vec e(nm, 0);
        e[0] = F.sub(2 % F.q, at.empty() ? 0 : at[0]);
        for (size_t i = 1; i < nm; i++) e[i] = F.neg(i < at.size() ? at[i] : 0);
        t = fp_mul_trunc(F, t, e, nm);
    }
    t.resize(n, 0);
    return t;
}

// Fast division with remainder: a = q*b + r, deg r < deg b, via reversal and
// Newton inversion. Falls back to synthetic long division for small inputs.
inline void fp_divrem(const Field& F, const Vec& a_in, const Vec& b_in,
                      Vec& q, Vec& r) {
    Vec a = fp_trim(a_in), b = fp_trim(b_in);
    assert(!b.empty());
    if (a.size() < b.size()) { q = {}; r = a; return; }
    size_t n = a.size() - 1, m = b.size() - 1, k = n - m + 1;

    if (a.size() < 64 || b.size() < 16) { // schoolbook long division
        r = a;
        q.assign(k, 0);
        uint32_t lead_inv = F.inv(b[m]);
        for (size_t dq = k; dq-- > 0;) { // quotient coefficient of degree dq
            uint32_t c = F.mul(r[dq + m], lead_inv);
            q[dq] = c;
            if (c)
                for (size_t i = 0; i <= m; i++)
                    r[dq + i] = F.sub(r[dq + i], F.mul(c, b[i]));
        }
        r.resize(m);
        r = fp_trim(r);
        return;
    }

    Vec ra(a.rbegin(), a.rend()), rb(b.rbegin(), b.rend());
    Vec irb = fp_series_inv(F, rb, k);
    Vec rq = fp_mul_trunc(F, ra, irb, k);
    q.assign(rq.rbegin(), rq.rend()); // length k, ascending
    Vec bq = fp_mul(F, b, q);
    r.assign(m, 0);
    for (size_t i = 0; i < m; i++)
        r[i] = F.sub(i < a.size() ? a[i] : 0, i < bq.size() ? bq[i] : 0);
    r = fp_trim(r);
}

inline Vec fp_derivative(const Field& F, const Vec& a) {
    if (a.size() <= 1) return {};
    Vec d(a.size() - 1);
    for (size_t i = 1; i < a.size(); i++) d[i - 1] = F.mul(uint32_t(i % F.q), a[i]);
    return d;
}

// ---------------------------------------------------------------------------
// Subproduct tree over evaluation points xs.
// ---------------------------------------------------------------------------
struct SubproductTree {
    Vec poly;                       // prod_{i in [lo, lo+n)} (X - xs[i])
    uint32_t lo = 0, n = 0;
    std::unique_ptr<SubproductTree> left, right;

    static std::unique_ptr<SubproductTree> build(const Field& F, const Vec& xs,
                                                 uint32_t lo, uint32_t n) {
        auto node = std::make_unique<SubproductTree>();
        node->lo = lo;
        node->n = n;
        if (n <= FP_TREE_BASE_POINTS) {
            Vec roots(xs.begin() + lo, xs.begin() + lo + n);
            node->poly = poly_from_roots(F, roots);
            return node;
        }
        uint32_t nl = n / 2;
        node->left = build(F, xs, lo, nl);
        node->right = build(F, xs, lo + nl, n - nl);
        node->poly = fp_mul(F, node->left->poly, node->right->poly);
        return node;
    }
};

// Monic prod (X - roots[i]) via the product tree.
inline Vec fp_from_roots(const Field& F, const Vec& roots) {
    if (roots.size() <= 2 * FP_TREE_BASE_POINTS) return poly_from_roots(F, roots);
    auto tree = SubproductTree::build(F, roots, 0, uint32_t(roots.size()));
    return tree->poly;
}

namespace detail {
inline void multipoint_down(const Field& F, const Vec& f, const SubproductTree& node,
                            const Vec& xs, Vec& out) {
    Vec r;
    if (fp_trim(f).size() >= node.poly.size()) {
        Vec q;
        fp_divrem(F, f, node.poly, q, r);
    } else {
        r = f;
    }
    if (!node.left) { // base block: direct Horner
        for (uint32_t i = node.lo; i < node.lo + node.n; i++)
            out[i] = poly_eval(F, r, xs[i]);
        return;
    }
    multipoint_down(F, r, *node.left, xs, out);
    multipoint_down(F, r, *node.right, xs, out);
}

// Weighted combination sum_{i in node} s_i * (node.poly / (X - xs[i])),
// the workhorse of fast interpolation (vzGG Algorithm 10.9).
inline Vec interp_up(const Field& F, const SubproductTree& node,
                     const Vec& xs, const Vec& s) {
    if (!node.left) { // base block: synthetic division accumulation, O(t^2)
        Vec acc(node.n, 0);
        const size_t t = node.n;
        for (uint32_t i = node.lo; i < node.lo + node.n; i++) {
            // basis = node.poly / (X - xs[i]) by synthetic division
            Vec basis(t, 0);
            uint32_t carry = node.poly[t]; // monic leading coeff
            for (size_t d = t; d-- > 0;) {
                basis[d] = carry;
                carry = F.add(node.poly[d], F.mul(carry, xs[i]));
            }
            for (size_t d = 0; d < t; d++)
                acc[d] = F.add(acc[d], F.mul(s[i], basis[d]));
        }
        return acc;
    }
    Vec cl = interp_up(F, *node.left, xs, s);
    Vec cr = interp_up(F, *node.right, xs, s);
    Vec a = fp_mul(F, cl, node.right->poly);
    Vec b = fp_mul(F, cr, node.left->poly);
    Vec out(node.n, 0);
    for (size_t i = 0; i < out.size(); i++)
        out[i] = F.add(i < a.size() ? a[i] : 0, i < b.size() ? b[i] : 0);
    return out;
}
} // namespace detail

// Evaluate f at every xs[i]; O(n log^2 n).
inline Vec fp_multipoint(const Field& F, const Vec& f, const Vec& xs) {
    Vec out(xs.size(), 0);
    if (xs.empty()) return out;
    if (xs.size() <= 2 * FP_TREE_BASE_POINTS) {
        for (size_t i = 0; i < xs.size(); i++) out[i] = poly_eval(F, f, xs[i]);
        return out;
    }
    auto tree = SubproductTree::build(F, xs, 0, uint32_t(xs.size()));
    detail::multipoint_down(F, f, *tree, xs, out);
    return out;
}

// Unique interpolant of degree < n through (xs[i], ys[i]); O(n log^2 n).
// Bit-identical to lagrange_interpolate (the interpolant is unique).
inline Vec fp_interpolate(const Field& F, const Vec& xs, const Vec& ys) {
    assert(xs.size() == ys.size());
    const size_t n = xs.size();
    if (n <= 2 * FP_TREE_BASE_POINTS) return lagrange_interpolate(F, xs, ys);
    auto tree = SubproductTree::build(F, xs, 0, uint32_t(n));
    Vec dM = fp_derivative(F, tree->poly);
    Vec d(n, 0);
    detail::multipoint_down(F, dM, *tree, xs, d); // d[i] = M'(x_i) = prod_{j!=i}(x_i - x_j)
    Vec s(n);
    for (size_t i = 0; i < n; i++) s[i] = F.mul(ys[i], F.inv(d[i]));
    Vec out = detail::interp_up(F, *tree, xs, s);
    out.resize(n, 0);
    return out;
}

} // namespace ccts
