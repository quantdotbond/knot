#pragma once
// Univariate polynomial helpers over F_q (coefficient vectors, ascending degree).
// Naive O(n^2) algorithms: fine at prototype sizes (paper uses fast variants).
#include "matrix.hpp"

namespace ccts {

// Monic product prod_i (X - roots[i]); returns deg = roots.size() + 1 coefficients.
inline Vec poly_from_roots(const Field& F, const Vec& roots) {
    Vec p{1};
    for (uint32_t r : roots) {
        Vec np(p.size() + 1, 0);
        for (size_t i = 0; i < p.size(); i++) {
            np[i + 1] = F.add(np[i + 1], p[i]);            // X * p
            np[i] = F.sub(np[i], F.mul(r, p[i]));          // -r * p
        }
        p = np;
    }
    return p;
}

inline uint32_t poly_eval(const Field& F, const Vec& coeffs, uint32_t x) {
    uint32_t acc = 0;
    for (size_t i = coeffs.size(); i-- > 0;)
        acc = F.add(F.mul(acc, x), coeffs[i]);
    return acc;
}

// Lagrange interpolation through points (xs[i], ys[i]); xs distinct.
// Returns the unique polynomial of degree < n as n coefficients.
inline Vec lagrange_interpolate(const Field& F, const Vec& xs, const Vec& ys) {
    assert(xs.size() == ys.size());
    size_t n = xs.size();
    Vec result(n, 0);
    Vec master = poly_from_roots(F, xs); // prod (X - x_i), degree n
    for (size_t i = 0; i < n; i++) {
        // basis_i = master / (X - x_i), by synthetic division
        Vec basis(n, 0);
        uint32_t carry = master[n]; // leading coeff = 1
        for (size_t d = n; d-- > 0;) {
            basis[d] = carry;
            carry = F.add(master[d], F.mul(carry, xs[i]));
        }
        // scale: y_i / basis_i(x_i)
        uint32_t denom = poly_eval(F, basis, xs[i]);
        uint32_t s = F.mul(ys[i], F.inv(denom));
        for (size_t d = 0; d < n; d++)
            result[d] = F.add(result[d], F.mul(s, basis[d]));
    }
    return result;
}

} // namespace ccts
