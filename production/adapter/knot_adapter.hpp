#pragma once
// =============================================================================
//  KNOT production/test adapter
// =============================================================================
//
// A thin, header-only layer between the immutable KNOT core (include/ccts/)
// and the verification infrastructure (tests, fuzzers, benchmarks, harnesses).
//
// It provides:
//   * a parameter-set registry with stable names ("<mode>/k=<k>");
//   * byte-level encode/decode helpers with *bounds-checked, canonical* parsing
//     for the wire formats the core defines (dense signature, packed signature,
//     dense public key, TRI packed public key);
//   * nothing else.
//
// The adapter never alters cryptographic semantics: every accepted encoding is
// handed to the core's own deserializer/verifier unchanged, and every value it
// produces is produced by the core. What the adapter adds is *rejection before
// the core sees an encoding that the core does not itself validate* (see the
// findings in metadata/findings/). The raw core boundary is fuzzed separately
// (production/fuzz/*_raw_*.cpp) precisely so those core defects stay visible.
// Project-owned code builds with strict warnings and -Werror. The immutable
// core does not compile cleanly under -Wpedantic (`unsigned __int128`, finding
// KNOT-CORE-001), -Wconversion / -Wsign-conversion (serialize.hpp,
// fastpoly.hpp) and -Wnull-dereference (vwz.hpp, scheme.hpp; GCC flow analysis
// on std::vector indexing) - finding KNOT-CORE-006. These four diagnostics -
// and only these - are suppressed for the core include so that -Werror stays
// meaningful for the assurance layer. The core is compiled separately with
// the same strict flags and its warning count is reported by scripts/ci.sh
// (check "core-diagnostics", non-blocking, see the production-readiness report).
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wnull-dereference"
#include "ccts/scheme.hpp"
#pragma GCC diagnostic pop
#include <optional>
#include <string>
#include <vector>
#include <cstdint>

namespace knot_adapter {

// ----------------------------------------------------------------------------
// Parameter sets
// ----------------------------------------------------------------------------
struct ParamSet {
    ccts::Mode mode;
    uint32_t k;
};

inline const char* mode_name(ccts::Mode m) {
    switch (m) {
        case ccts::Mode::tensor_reference: return "tensor_reference";
        case ccts::Mode::chord_tensor:     return "chord_tensor";
        case ccts::Mode::chord_structured: return "chord_structured";
        case ccts::Mode::chord_labeled:    return "chord_labeled";
        case ccts::Mode::tri_chord:        return "tri_chord";
    }
    return "unknown";
}

inline std::optional<ccts::Mode> mode_from_name(const std::string& s) {
    for (ccts::Mode m : {ccts::Mode::tensor_reference, ccts::Mode::chord_tensor,
                         ccts::Mode::chord_structured, ccts::Mode::chord_labeled,
                         ccts::Mode::tri_chord})
        if (s == mode_name(m)) return m;
    return std::nullopt;
}

inline std::string param_set_name(const ParamSet& p) {
    return std::string(mode_name(p.mode)) + "/k=" + std::to_string(p.k);
}

// Parameter derivation exactly as the core's own generators/tests do it.
inline ccts::Parameters make_params(ccts::Mode mode, uint32_t k) {
    switch (mode) {
        case ccts::Mode::chord_structured: return ccts::Parameters::for_k_structured(k);
        case ccts::Mode::chord_labeled:    return ccts::Parameters::for_k_labeled(k);
        case ccts::Mode::tri_chord:        return ccts::Parameters::for_k_tri(k);
        default:                           return ccts::Parameters::for_k(k);
    }
}
inline ccts::Parameters make_params(const ParamSet& p) { return make_params(p.mode, p.k); }

// tri_chord's wire format for signatures is the packed encoding; every other
// mode uses the dense 2-byte encoding (bench/bench_main.cpp, tests/gen_vectors.cpp).
inline bool uses_packed_signature(ccts::Mode m) { return m == ccts::Mode::tri_chord; }

// Parameter sets exercised on every PR (fast: all five modes, the k values the
// repository's own KAT corpus uses).
inline std::vector<ParamSet> ci_parameter_sets() {
    using M = ccts::Mode;
    return {{M::tensor_reference, 4}, {M::tensor_reference, 8},
            {M::chord_tensor, 4},     {M::chord_tensor, 8},
            {M::chord_structured, 4}, {M::chord_structured, 8},
            {M::chord_labeled, 4},    {M::chord_labeled, 8},
            {M::tri_chord, 8},        {M::tri_chord, 12}};
}
// Larger sets for nightly runs (still toy parameters; see manifest).
inline std::vector<ParamSet> extended_parameter_sets() {
    using M = ccts::Mode;
    auto v = ci_parameter_sets();
    for (M m : {M::tensor_reference, M::chord_tensor, M::chord_structured, M::chord_labeled, M::tri_chord})
        v.push_back({m, 16});
    v.push_back({M::tensor_reference, 32});
    v.push_back({M::tri_chord, 32});
    return v;
}

inline ccts::KeyPair keygen(const ParamSet& p, ccts::Drbg& rng) {
    return ccts::keygen(make_params(p), rng, p.mode);
}

// ----------------------------------------------------------------------------
// Bounds-checked little-endian reader (adapter-owned; the core's ByteReader is
// not fully bounds-checked, see finding KNOT-CORE-002).
// ----------------------------------------------------------------------------
struct SafeReader {
    const std::vector<uint8_t>& b;
    size_t pos = 0;
    explicit SafeReader(const std::vector<uint8_t>& bytes) : b(bytes) {}
    size_t remaining() const { return b.size() - pos; }
    bool u8(uint8_t& x) { if (remaining() < 1) return false; x = b[pos++]; return true; }
    bool u16(uint16_t& x) {
        if (remaining() < 2) return false;
        x = uint16_t(b[pos] | (uint16_t(b[pos + 1]) << 8)); pos += 2; return true;
    }
    bool u32(uint32_t& x) {
        if (remaining() < 4) return false;
        x = uint32_t(b[pos]) | (uint32_t(b[pos + 1]) << 8) | (uint32_t(b[pos + 2]) << 16) |
            (uint32_t(b[pos + 3]) << 24);
        pos += 4; return true;
    }
    bool bytes(std::vector<uint8_t>& out) {
        uint32_t n; if (!u32(n)) return false;
        if (remaining() < n) return false;
        out.assign(b.begin() + long(pos), b.begin() + long(pos + n)); pos += n; return true;
    }
    // n two-byte elements, each required to be a canonical field element (< q)
    bool elems(uint32_t n, uint32_t q, ccts::Vec& out) {
        if (remaining() < size_t(2) * n) return false;
        out.resize(n);
        for (uint32_t i = 0; i < n; i++) { uint16_t e = 0; u16(e); if (e >= q) return false; out[i] = e; }
        return true;
    }
    bool done() const { return pos == b.size(); }
};

// Adapter-side limits: the core's prototype range is q < 2^16 and (for chord
// modes) k <= 127. For dense tensors we additionally cap k so that a hostile
// header cannot request a multi-gigabyte allocation before validation.
inline constexpr uint32_t MAX_DENSE_K = 256; // dense pk <= 8 + 12 + 2*513*257*257 B ~ 68 MB
inline constexpr uint32_t MAX_TRI_K = 127;

inline bool valid_field_params(uint32_t k, uint32_t q) {
    return k >= 1 && q >= 3 && q < (1u << 16) && q > 4 * k && ccts::is_prime(q);
}

// ----------------------------------------------------------------------------
// Signatures
// ----------------------------------------------------------------------------
inline std::vector<uint8_t> signature_to_bytes(const ccts::Signature& s, const ccts::Parameters& p,
                                               ccts::Mode mode) {
    return uses_packed_signature(mode) ? ccts::serialize_signature_packed(s, p) : s.serialize();
}

// Dense format: bytes(salt) || vec(u) || vec(v). Exact length, salt of
// SALT_BYTES, k+1 canonical elements each. (The core has no dense signature
// parser at all: Signature::serialize() has no inverse. This is the adapter's.)
inline std::optional<ccts::Signature> signature_from_bytes_dense(const std::vector<uint8_t>& bytes,
                                                                 const ccts::Parameters& p) {
    SafeReader r(bytes);
    ccts::Signature s;
    uint32_t n;
    if (!r.bytes(s.salt) || s.salt.size() != ccts::SALT_BYTES) return std::nullopt;
    if (!r.u32(n) || n != p.k + 1 || !r.elems(n, p.q, s.u)) return std::nullopt;
    if (!r.u32(n) || n != p.k + 1 || !r.elems(n, p.q, s.v)) return std::nullopt;
    if (!r.done()) return std::nullopt;
    return s;
}

// Packed (tri_chord) format: bytes(salt) || bytes(radix_q(u||v)). Exact
// framing, exact payload length, and a canonicality check: the integer must
// re-encode to the same bytes (a payload above q^n-1 within the same byte
// length would otherwise decode to the same (u, v) - see finding KNOT-CORE-004).
inline std::optional<ccts::Signature> signature_from_bytes_packed(const std::vector<uint8_t>& bytes,
                                                                  const ccts::Parameters& p) {
    SafeReader r(bytes);
    std::vector<uint8_t> salt, payload;
    if (!r.bytes(salt) || salt.size() != ccts::SALT_BYTES) return std::nullopt;
    if (!r.bytes(payload) || !r.done()) return std::nullopt;
    const size_t n = size_t(2) * (p.k + 1);
    if (payload.size() != ccts::radix_len(p.q, n)) return std::nullopt;
    ccts::Signature s = ccts::deserialize_signature_packed(bytes, p); // framing validated above
    if (ccts::serialize_signature_packed(s, p) != bytes) return std::nullopt; // non-canonical
    return s;
}

inline std::optional<ccts::Signature> signature_from_bytes(const std::vector<uint8_t>& bytes,
                                                           const ccts::Parameters& p, ccts::Mode mode) {
    return uses_packed_signature(mode) ? signature_from_bytes_packed(bytes, p)
                                       : signature_from_bytes_dense(bytes, p);
}

// ----------------------------------------------------------------------------
// Public keys: validate the framing completely, then let the core build the
// object (PublicKey::deserialize) so the digest and the structure are the
// core's own.
// ----------------------------------------------------------------------------
inline bool validate_public_key_bytes(const std::vector<uint8_t>& bytes) {
    SafeReader r(bytes);
    uint32_t k, q;
    if (!r.u32(k) || !r.u32(q)) return false;
    if (!valid_field_params(k, q)) return false;
    const uint32_t n1 = 2 * k + 1, n23 = k + 1;
    uint8_t tag;
    if (!r.u8(tag)) return false;
    if (tag == 0x54) {
        // TRI packed framing
        if (k > MAX_TRI_K) return false;
        uint32_t t, w;
        std::vector<uint8_t> seed, payload;
        if (!r.u32(t) || !r.u32(w)) return false;
        if (t < k + 2 || t > n1) return false;
        if (w < 1 || w > n23 || (n23 - w) > (n1 - t)) return false;
        if ((q - 1) % (4 * k + 2) != 0) return false; // structured-field requirement of the mode
        if (!r.bytes(seed) || seed.size() != 32) return false;
        if (!r.bytes(payload) || !r.done()) return false;
        // Walk the bit stream exactly as the core does, bounds-checked.
        const uint32_t b = ccts::elem_bits(q), bnz = ccts::elem_bits(n23);
        size_t bitpos = 0;
        const size_t total_bits = payload.size() * 8;
        auto rd = [&](uint32_t nbits, uint32_t& out) -> bool {
            if (bitpos + nbits > total_bits) return false;
            uint64_t acc = 0;
            for (uint32_t i = 0; i < nbits; i++, bitpos++)
                acc |= uint64_t((payload[bitpos >> 3] >> (bitpos & 7)) & 1) << i;
            out = uint32_t(acc);
            return true;
        };
        for (uint32_t i = 0; i < t; i++) {
            uint32_t nz;
            if (!rd(bnz, nz) || nz >= n23) return false;
            for (uint32_t j = nz + 1; j < n23; j++) { uint32_t e; if (!rd(b, e) || e >= q) return false; }
            for (uint32_t j = 0; j < n23; j++)      { uint32_t e; if (!rd(b, e) || e >= q) return false; }
        }
        // Exact payload length and zero padding bits (canonical framing).
        if ((bitpos + 7) / 8 != payload.size()) return false;
        for (; bitpos < total_bits; bitpos++)
            if ((payload[bitpos >> 3] >> (bitpos & 7)) & 1) return false;
        return true;
    }
    // Dense framing: the byte we read as a tag is the first byte of n1.
    r.pos -= 1;
    if (k > MAX_DENSE_K) return false;
    uint32_t d1, d2, d3;
    if (!r.u32(d1) || !r.u32(d2) || !r.u32(d3)) return false;
    if (d1 != n1 || d2 != n23 || d3 != n23) return false;
    const size_t count = size_t(n1) * n23 * n23;
    if (r.remaining() != 2 * count) return false;
    for (size_t i = 0; i < count; i++) { uint16_t e = 0; r.u16(e); if (e >= q) return false; }
    return r.done();
}

inline std::optional<ccts::PublicKey> public_key_from_bytes(const std::vector<uint8_t>& bytes) {
    if (!validate_public_key_bytes(bytes)) return std::nullopt;
    return ccts::PublicKey::deserialize(bytes);
}

// Convenience: verify a message against serialized signature bytes.
inline bool verify_bytes(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig_bytes,
                         const ccts::PublicKey& pk, ccts::Mode mode) {
    auto s = signature_from_bytes(sig_bytes, pk.params, mode);
    if (!s) return false;
    return ccts::verify(msg.data(), msg.size(), *s, pk);
}

} // namespace knot_adapter
