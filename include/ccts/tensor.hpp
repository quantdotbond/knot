#pragma once
// Order-three tensors over F_q, basis-change twist (Definition 5 of ePrint 2025/624),
// and tensor evaluation in all but the first dimension.
#include "matrix.hpp"

namespace ccts {

struct Tensor3 {
    uint32_t n1 = 0, n2 = 0, n3 = 0;
    std::vector<uint32_t> a; // flat, index (i,j,l) -> ((i*n2)+j)*n3 + l

    Tensor3() = default;
    Tensor3(uint32_t d1, uint32_t d2, uint32_t d3)
        : n1(d1), n2(d2), n3(d3), a(size_t(d1) * d2 * d3, 0) {}

    uint32_t& at(uint32_t i, uint32_t j, uint32_t l) {
        return a[(size_t(i) * n2 + j) * n3 + l];
    }
    uint32_t at(uint32_t i, uint32_t j, uint32_t l) const {
        return a[(size_t(i) * n2 + j) * n3 + l];
    }
    bool operator==(const Tensor3& o) const {
        return n1 == o.n1 && n2 == o.n2 && n3 == o.n3 && a == o.a;
    }
};

// Tensor evaluation in all but the first dimension:
//   f1_phi(u, v)_{i1} = sum_{i2,i3} phi_{i1,i2,i3} u_{i2} v_{i3}.
inline Vec tensor_eval(const Field& F, const Tensor3& T, const Vec& u, const Vec& v) {
    assert(u.size() == T.n2 && v.size() == T.n3);
    Vec y(T.n1, 0);
    for (uint32_t i = 0; i < T.n1; i++) {
        uint64_t acc = 0;
        for (uint32_t j = 0; j < T.n2; j++) {
            if (!u[j]) continue;
            uint64_t row = 0;
            const uint32_t* base = &T.a[(size_t(i) * T.n2 + j) * T.n3];
            for (uint32_t l = 0; l < T.n3; l++)
                row += uint64_t(base[l]) * v[l] % F.q;
            acc += (row % F.q) * u[j] % F.q;
        }
        y[i] = uint32_t(acc % F.q);
    }
    return y;
}

// Full multilinear form f_phi(w1, w2, w3).
inline uint32_t multilinear_form(const Field& F, const Tensor3& T,
                                 const Vec& w1, const Vec& w2, const Vec& w3) {
    Vec y = tensor_eval(F, T, w2, w3);
    uint64_t acc = 0;
    for (uint32_t i = 0; i < T.n1; i++) acc += uint64_t(y[i]) * w1[i] % F.q;
    return uint32_t(acc % F.q);
}

// Basis-change twist psi = phi^{(X1,X2,X3)}:
//   psi_{a,b,c} = sum_{i,j,l} phi_{i,j,l} X1[i][a] X2[j][b] X3[l][c],
// so that f_psi(w1,w2,w3) = f_phi(X1 w1, X2 w2, X3 w3).
// Computed mode-by-mode for efficiency.
inline Tensor3 twist(const Field& F, const Tensor3& T,
                     const Mat& X1, const Mat& X2, const Mat& X3) {
    assert(X1.rows == T.n1 && X1.cols == T.n1);
    assert(X2.rows == T.n2 && X2.cols == T.n2);
    assert(X3.rows == T.n3 && X3.cols == T.n3);
    // Mode 1: A_{a,j,l} = sum_i T_{i,j,l} X1[i][a]
    Tensor3 A(T.n1, T.n2, T.n3);
    for (uint32_t a = 0; a < T.n1; a++)
        for (uint32_t i = 0; i < T.n1; i++) {
            uint32_t x = X1.at(i, a);
            if (!x) continue;
            const uint32_t* src = &T.a[size_t(i) * T.n2 * T.n3];
            uint32_t* dst = &A.a[size_t(a) * T.n2 * T.n3];
            for (size_t t = 0; t < size_t(T.n2) * T.n3; t++)
                dst[t] = F.add(dst[t], F.mul(x, src[t]));
        }
    // Mode 2: B_{a,b,l} = sum_j A_{a,j,l} X2[j][b]
    Tensor3 B(T.n1, T.n2, T.n3);
    for (uint32_t a = 0; a < T.n1; a++)
        for (uint32_t b = 0; b < T.n2; b++)
            for (uint32_t j = 0; j < T.n2; j++) {
                uint32_t x = X2.at(j, b);
                if (!x) continue;
                const uint32_t* src = &A.a[(size_t(a) * T.n2 + j) * T.n3];
                uint32_t* dst = &B.a[(size_t(a) * T.n2 + b) * T.n3];
                for (uint32_t l = 0; l < T.n3; l++)
                    dst[l] = F.add(dst[l], F.mul(x, src[l]));
            }
    // Mode 3: psi_{a,b,c} = sum_l B_{a,b,l} X3[l][c]
    Tensor3 P(T.n1, T.n2, T.n3);
    for (uint32_t a = 0; a < T.n1; a++)
        for (uint32_t b = 0; b < T.n2; b++) {
            const uint32_t* src = &B.a[(size_t(a) * T.n2 + b) * T.n3];
            uint32_t* dst = &P.a[(size_t(a) * T.n2 + b) * T.n3];
            for (uint32_t l = 0; l < T.n3; l++) {
                uint32_t s = src[l];
                if (!s) continue;
                for (uint32_t c = 0; c < T.n3; c++)
                    dst[c] = F.add(dst[c], F.mul(s, X3.at(l, c)));
            }
        }
    return P;
}

} // namespace ccts
