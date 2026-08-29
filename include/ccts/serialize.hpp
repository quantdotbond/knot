#pragma once
// Deterministic little-endian binary serialization. Field elements are two
// bytes (prototype restricts q < 2^16).
#include "matrix.hpp"
#include "tensor.hpp"
#include <vector>
#include <cstdint>

namespace ccts {

struct ByteWriter {
    std::vector<uint8_t> buf;
    void u8(uint8_t x) { buf.push_back(x); }
    void u16(uint16_t x) { buf.push_back(uint8_t(x)); buf.push_back(uint8_t(x >> 8)); }
    void u32(uint32_t x) { u16(uint16_t(x)); u16(uint16_t(x >> 16)); }
    void elem(uint32_t x) { u16(uint16_t(x)); }
    void vec(const Vec& v) { u32(uint32_t(v.size())); for (auto e : v) elem(e); }
    void mat(const Mat& M) { u32(M.rows); u32(M.cols); for (auto e : M.a) elem(e); }
    void tensor(const Tensor3& T) {
        u32(T.n1); u32(T.n2); u32(T.n3);
        for (auto e : T.a) elem(e);
    }
    void bytes(const std::vector<uint8_t>& b) { u32(uint32_t(b.size())); buf.insert(buf.end(), b.begin(), b.end()); }
};

// ---------------------------------------------------------------------------
// Fixed-width bit packing (TRI design notes §7.5, Tier 1): field elements cost
// ceil(log2 q) bits on the wire instead of 16. LSB-first within the stream.
// ---------------------------------------------------------------------------
inline uint32_t elem_bits(uint32_t q) {
    uint32_t b = 0;
    for (uint32_t v = q - 1; v; v >>= 1) b++;
    return b ? b : 1;
}

struct BitWriter {
    std::vector<uint8_t> buf;
    uint64_t acc = 0;
    uint32_t nbits = 0;
    void bits(uint32_t v, uint32_t n) {
        acc |= uint64_t(v) << nbits;
        nbits += n;
        while (nbits >= 8) { buf.push_back(uint8_t(acc)); acc >>= 8; nbits -= 8; }
    }
    std::vector<uint8_t> finish() {
        if (nbits) { buf.push_back(uint8_t(acc)); acc = 0; nbits = 0; }
        return buf;
    }
};

struct BitReader {
    const std::vector<uint8_t>& buf;
    size_t pos = 0;
    uint64_t acc = 0;
    uint32_t nbits = 0;
    explicit BitReader(const std::vector<uint8_t>& b) : buf(b) {}
    uint32_t bits(uint32_t n) {
        while (nbits < n) { acc |= uint64_t(buf.at(pos++)) << nbits; nbits += 8; }
        uint32_t v = uint32_t(acc & ((uint64_t(1) << n) - 1));
        acc >>= n;
        nbits -= n;
        return v;
    }
};

// ---------------------------------------------------------------------------
// Radix (base-q) coding: n elements cost ceil(n*log2 q) bits *total*,
// recovering the ~1 bit/element that fixed-width packing wastes when q sits
// just above a power of two (TRI design notes §7.5: q = 2053 costs 11.004 bits
// per element radix-coded vs 12 fixed-width). The vector is encoded as the
// little-endian big integer sum v[i]*q^i, zero-padded to the exact length of
// the largest encodable value so the framing stays fixed-size and canonical.
// ---------------------------------------------------------------------------
inline std::vector<uint8_t> radix_pack_raw(const Vec& v, uint32_t q) {
    std::vector<uint8_t> out; // little-endian big integer
    for (size_t i = v.size(); i-- > 0;) {
        uint32_t carry = v[i]; // out = out * q + v[i]
        for (auto& b : out) {
            uint64_t t = uint64_t(b) * q + carry;
            b = uint8_t(t);
            carry = uint32_t(t >> 8);
        }
        while (carry) { out.push_back(uint8_t(carry)); carry >>= 8; }
    }
    return out;
}

// Exact payload length for n base-q elements: bytes of q^n - 1.
inline size_t radix_len(uint32_t q, size_t n) {
    return radix_pack_raw(Vec(n, q - 1), q).size();
}

inline std::vector<uint8_t> radix_pack(const Vec& v, uint32_t q) {
    auto out = radix_pack_raw(v, q);
    out.resize(radix_len(q, v.size()), 0);
    return out;
}

inline Vec radix_unpack(std::vector<uint8_t> bytes, uint32_t q, size_t n) {
    Vec v(n);
    for (size_t i = 0; i < n; i++) { // v[i] = bytes % q; bytes /= q
        uint32_t rem = 0;
        for (size_t j = bytes.size(); j-- > 0;) {
            uint64_t cur = (uint64_t(rem) << 8) | bytes[j];
            bytes[j] = uint8_t(cur / q);
            rem = uint32_t(cur % q);
        }
        v[i] = rem;
    }
    return v;
}

struct ByteReader {
    const std::vector<uint8_t>& buf;
    size_t pos = 0;
    explicit ByteReader(const std::vector<uint8_t>& b) : buf(b) {}
    uint8_t u8() { return buf.at(pos++); }
    uint16_t u16() { uint16_t x = u8(); x |= uint16_t(u8()) << 8; return x; }
    uint32_t u32() { uint32_t x = u16(); x |= uint32_t(u16()) << 16; return x; }
    uint32_t elem() { return u16(); }
    Vec vec() { uint32_t n = u32(); Vec v(n); for (auto& e : v) e = elem(); return v; }
    Mat mat() {
        Mat M; M.rows = u32(); M.cols = u32();
        M.a.resize(size_t(M.rows) * M.cols);
        for (auto& e : M.a) e = elem();
        return M;
    }
    Tensor3 tensor() {
        Tensor3 T;
        T.n1 = u32(); T.n2 = u32(); T.n3 = u32();
        T.a.resize(size_t(T.n1) * T.n2 * T.n3);
        for (auto& e : T.a) e = elem();
        return T;
    }
    std::vector<uint8_t> bytes() {
        uint32_t n = u32();
        std::vector<uint8_t> b(buf.begin() + pos, buf.begin() + pos + n);
        pos += n;
        return b;
    }
};

} // namespace ccts
