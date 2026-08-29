#pragma once
// Vandermonde-Weyman-Zelevinsky tensors in three-dimensional doubly boundary
// format (2k+1) x (k+1) x (k+1), and the trapdoor preimage sampler
// (SamplePre / SamplePre3DB of ePrint 2025/624).
#include "tensor.hpp"
#include "poly.hpp"
#include "fastpoly.hpp"

namespace ccts {

// Polynomial arithmetic backend for the preimage sampler. `naive` is the
// original O(k^2) code path; `fast` is the nearly linear variant of the paper
// (subproduct trees + fast interpolation, fastpoly.hpp); `autoselect` switches
// on the empirically measured crossover. Both backends return bit-identical
// preimages (the vanishing polynomial and the interpolant are unique), so
// signatures and test vectors are backend-independent.
enum class PolyBackend : uint8_t { naive = 0, fast = 1, autoselect = 2 };

// Crossover measured on the benchmark host (results/interp.csv,
// results/interp_summary.csv): the naive path wins up to k = 2048, the two
// backends tie at k = 4096 (repeat runs straddle break-even), and fast wins
// clearly at k = 8192 (~1.6x). Autoselect switches at the tie point, where
// fast is at worst break-even.
inline constexpr uint32_t FAST_BACKEND_MIN_K = 4096;

inline PolyBackend resolve_backend(PolyBackend b, uint32_t k) {
    if (b != PolyBackend::autoselect) return b;
    return k >= FAST_BACKEND_MIN_K ? PolyBackend::fast : PolyBackend::naive;
}

// phi<Lambda>_{i1,i2,i3} = c2[i1]^{i2} * c3[i1]^{i3}, where c2, c3 are the two
// columns of the defining (2k+1) x 2 matrix Lambda. Columns must have distinct
// entries (Weyman-Zelevinsky non-degeneracy, Prop. 7.3).
inline Tensor3 build_vwz(const Field& F, uint32_t k, const Vec& c2, const Vec& c3) {
    uint32_t n1 = 2 * k + 1, n23 = k + 1;
    assert(c2.size() == n1 && c3.size() == n1);
    Tensor3 T(n1, n23, n23);
    for (uint32_t i = 0; i < n1; i++) {
        Vec p2(n23), p3(n23);
        p2[0] = p3[0] = 1;
        for (uint32_t d = 1; d < n23; d++) {
            p2[d] = F.mul(p2[d - 1], c2[i]);
            p3[d] = F.mul(p3[d - 1], c3[i]);
        }
        for (uint32_t j = 0; j < n23; j++)
            for (uint32_t l = 0; l < n23; l++)
                T.at(i, j, l) = F.mul(p2[j], p3[l]);
    }
    return T;
}

// Trapdoor preimage sampling against phi<Lambda> itself (no basis change):
// given target y0 in F_q^{2k+1} of Hamming weight exactly k+1, find (w2, w3)
// with f1_phi(w2, w3) = y0. `coin` selects which of the two equal-length
// dimensions carries the vanishing polynomial (the SamplePre3DB coin).
//
// coin == false: dimension 3 vanishes on the zero set Z, dimension 2 interpolates.
// coin == true : dimension 2 vanishes on Z, dimension 3 interpolates.
inline bool vwz_preimage(const Field& F, uint32_t k, const Vec& c2, const Vec& c3,
                         const Vec& y0, bool coin, Vec& w2, Vec& w3,
                         PolyBackend backend = PolyBackend::autoselect) {
    const PolyBackend be = resolve_backend(backend, k);
    uint32_t n1 = 2 * k + 1;
    assert(y0.size() == n1);
    // Zero set Z and support Zbar of the target.
    std::vector<uint32_t> Z, Zbar;
    for (uint32_t i = 0; i < n1; i++)
        (y0[i] == 0 ? Z : Zbar).push_back(i);
    if (Zbar.size() != k + 1) return false; // target must lie on the sphere S_{k+1}

    const Vec& cvan = coin ? c2 : c3;   // column of the vanishing dimension
    const Vec& cint = coin ? c3 : c2;   // column of the interpolating dimension

    // Vanishing polynomial: prod_{i in Z} (X - cvan[i]); coefficients are the
    // coordinate vector in the vanishing dimension (degree k -> k+1 coeffs).
    Vec roots;
    roots.reserve(Z.size());
    for (uint32_t i : Z) roots.push_back(cvan[i]);
    Vec wvan = (be == PolyBackend::fast) ? fp_from_roots(F, roots)
                                         : poly_from_roots(F, roots);
    assert(wvan.size() == k + 1);

    // Interpolation constraints on the support: P(cint[i]) = y0[i] / prod_{z in Z}(cvan[i] - cvan[z]).
    // The denominator equals wvan(cvan[i]), so the fast path computes all
    // denominators at once by multipoint evaluation of the vanishing polynomial.
    Vec xs, ys;
    xs.reserve(k + 1);
    ys.reserve(k + 1);
    if (be == PolyBackend::fast) {
        Vec pts;
        pts.reserve(Zbar.size());
        for (uint32_t i : Zbar) pts.push_back(cvan[i]);
        Vec denoms = fp_multipoint(F, wvan, pts);
        for (size_t t = 0; t < Zbar.size(); t++) {
            // denoms[t] != 0 because column entries are distinct.
            xs.push_back(cint[Zbar[t]]);
            ys.push_back(F.mul(y0[Zbar[t]], F.inv(denoms[t])));
        }
    } else {
        for (uint32_t i : Zbar) {
            uint32_t denom = 1;
            for (uint32_t z : Z) denom = F.mul(denom, F.sub(cvan[i], cvan[z]));
            // denom != 0 because column entries are distinct.
            xs.push_back(cint[i]);
            ys.push_back(F.mul(y0[i], F.inv(denom)));
        }
    }
    Vec wint = (be == PolyBackend::fast) ? fp_interpolate(F, xs, ys)
                                         : lagrange_interpolate(F, xs, ys);
    assert(wint.size() == k + 1);

    if (coin) { w2 = wvan; w3 = wint; }
    else      { w2 = wint; w3 = wvan; }
    return true;
}

} // namespace ccts
