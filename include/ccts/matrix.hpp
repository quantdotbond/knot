#pragma once
// Dense vectors and matrices over F_q; Gauss-Jordan inversion; invertible sampling.
#include "field.hpp"
#include "rng.hpp"
#include <vector>
#include <optional>

namespace ccts {

using Vec = std::vector<uint32_t>;

struct Mat {
    uint32_t rows = 0, cols = 0;
    std::vector<uint32_t> a; // row-major

    Mat() = default;
    Mat(uint32_t r, uint32_t c) : rows(r), cols(c), a(size_t(r) * c, 0) {}

    uint32_t& at(uint32_t i, uint32_t j) { return a[size_t(i) * cols + j]; }
    uint32_t at(uint32_t i, uint32_t j) const { return a[size_t(i) * cols + j]; }

    static Mat identity(uint32_t n) {
        Mat I(n, n);
        for (uint32_t i = 0; i < n; i++) I.at(i, i) = 1;
        return I;
    }

    bool operator==(const Mat& o) const {
        return rows == o.rows && cols == o.cols && a == o.a;
    }
};

inline uint32_t dot(const Field& F, const Vec& a, const Vec& b) {
    assert(a.size() == b.size());
    uint64_t acc = 0;
    for (size_t i = 0; i < a.size(); i++)
        acc += uint64_t(a[i]) * b[i] % F.q;
    return uint32_t(acc % F.q);
}

inline Vec mat_vec(const Field& F, const Mat& M, const Vec& x) {
    assert(M.cols == x.size());
    Vec y(M.rows, 0);
    for (uint32_t i = 0; i < M.rows; i++) {
        uint64_t acc = 0;
        for (uint32_t j = 0; j < M.cols; j++)
            acc += uint64_t(M.at(i, j)) * x[j] % F.q;
        y[i] = uint32_t(acc % F.q);
    }
    return y;
}

inline Mat mat_mul(const Field& F, const Mat& A, const Mat& B) {
    assert(A.cols == B.rows);
    Mat C(A.rows, B.cols);
    for (uint32_t i = 0; i < A.rows; i++)
        for (uint32_t k = 0; k < A.cols; k++) {
            uint32_t aik = A.at(i, k);
            if (!aik) continue;
            for (uint32_t j = 0; j < B.cols; j++)
                C.at(i, j) = F.add(C.at(i, j), F.mul(aik, B.at(k, j)));
        }
    return C;
}

// Gauss-Jordan inverse; nullopt when singular.
inline std::optional<Mat> mat_inverse(const Field& F, const Mat& M) {
    assert(M.rows == M.cols);
    uint32_t n = M.rows;
    Mat A = M, I = Mat::identity(n);
    for (uint32_t col = 0; col < n; col++) {
        uint32_t piv = col;
        while (piv < n && A.at(piv, col) == 0) piv++;
        if (piv == n) return std::nullopt;
        if (piv != col)
            for (uint32_t j = 0; j < n; j++) {
                std::swap(A.a[size_t(piv) * n + j], A.a[size_t(col) * n + j]);
                std::swap(I.a[size_t(piv) * n + j], I.a[size_t(col) * n + j]);
            }
        uint32_t inv_p = F.inv(A.at(col, col));
        for (uint32_t j = 0; j < n; j++) {
            A.at(col, j) = F.mul(A.at(col, j), inv_p);
            I.at(col, j) = F.mul(I.at(col, j), inv_p);
        }
        for (uint32_t r = 0; r < n; r++) {
            if (r == col) continue;
            uint32_t f = A.at(r, col);
            if (!f) continue;
            for (uint32_t j = 0; j < n; j++) {
                A.at(r, j) = F.sub(A.at(r, j), F.mul(f, A.at(col, j)));
                I.at(r, j) = F.sub(I.at(r, j), F.mul(f, I.at(col, j)));
            }
        }
    }
    return I;
}

// Sample invertible matrix by rejection; returns (matrix, retries used).
inline std::pair<Mat, uint32_t> sample_invertible(const Field& F, uint32_t n, Drbg& rng) {
    uint32_t retries = 0;
    for (;;) {
        Mat M(n, n);
        for (auto& e : M.a) e = rng.field_elem(F);
        if (mat_inverse(F, M)) return {M, retries};
        retries++;
    }
}

// Solve A x = b (A: m x n, m >= n allowed). Returns a solution if the system is
// consistent, nullopt otherwise. Used by the linear-forgery sanity check and the
// domain-sampler style solvers.
inline std::optional<Vec> solve_linear(const Field& F, Mat A, Vec b) {
    assert(A.rows == b.size());
    uint32_t m = A.rows, n = A.cols;
    uint32_t rank = 0;
    std::vector<uint32_t> pivot_col;
    for (uint32_t col = 0; col < n && rank < m; col++) {
        uint32_t piv = rank;
        while (piv < m && A.at(piv, col) == 0) piv++;
        if (piv == m) continue;
        if (piv != rank) {
            for (uint32_t j = 0; j < n; j++)
                std::swap(A.a[size_t(piv) * n + j], A.a[size_t(rank) * n + j]);
            std::swap(b[piv], b[rank]);
        }
        uint32_t inv_p = F.inv(A.at(rank, col));
        for (uint32_t j = 0; j < n; j++) A.at(rank, j) = F.mul(A.at(rank, j), inv_p);
        b[rank] = F.mul(b[rank], inv_p);
        for (uint32_t r = 0; r < m; r++) {
            if (r == rank) continue;
            uint32_t f = A.at(r, col);
            if (!f) continue;
            for (uint32_t j = 0; j < n; j++)
                A.at(r, j) = F.sub(A.at(r, j), F.mul(f, A.at(rank, j)));
            b[r] = F.sub(b[r], F.mul(f, b[rank]));
        }
        pivot_col.push_back(col);
        rank++;
    }
    // Consistency: rows below rank must have zero RHS.
    for (uint32_t r = rank; r < m; r++)
        if (b[r] != 0) return std::nullopt;
    Vec x(n, 0);
    for (uint32_t i = 0; i < rank; i++) x[pivot_col[i]] = b[i];
    return x;
}

inline bool is_zero_vec(const Vec& v) {
    for (auto e : v) if (e) return false;
    return true;
}

// Canonical projective representative: scale so the first nonzero coordinate is 1.
// Returns false when v == 0 (not a projective point).
inline bool projectivize(const Field& F, Vec& v) {
    size_t idx = 0;
    while (idx < v.size() && v[idx] == 0) idx++;
    if (idx == v.size()) return false;
    uint32_t s = F.inv(v[idx]);
    for (auto& e : v) e = F.mul(e, s);
    return true;
}

inline uint32_t hamming_weight(const Vec& v) {
    uint32_t w = 0;
    for (auto e : v) if (e) w++;
    return w;
}

} // namespace ccts
