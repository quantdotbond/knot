#pragma once
// Chord Tensor Trapdoor Signature (CCTS) -- experimental research prototype.
//
// Hash-and-Sign over the three-dimensional doubly boundary trapdoor one-way
// function of Narayanan, "Trapdoor one-way functions from tensors"
// (IACR ePrint 2025/624), scheme Sigma^3DB, with:
//   * X1 restricted to diagonal (weight-preserving) matrices,
//   * hash targets on the Hamming sphere S_{k+1}(P^{2k}), projectively canonical,
//   * SamplePre3DB dimension-swap coin (one bit of preimage entropy),
//   * public-key binding in the message hash (Remark 2 of the paper),
//   * an optional chord_tensor mode in which the VWZ defining matrix Lambda is
//     derived from a secret seed *and* the canonical encoding of a chord
//     diagram (structure, not entropy).
//
// NOT for deployment. No claim of post-quantum security is made.
#include "vwz.hpp"
#include <span>
#include <cstddef>
#include <cmath>
#include "chord.hpp"
#include "serialize.hpp"
#include <string>
#include <stdexcept>

namespace ccts {

enum class Mode : uint8_t {
    tensor_reference = 0, // Lambda uniform from the DRBG (paper's Sigma^3DB)
    chord_tensor     = 1, // Lambda hashed from seed + chord data (structure-as-domain-separation)
    chord_structured = 2, // Lambda = Lambda(D, g): the oriented diagram IS the pair
                          // structure of Lambda; rotation acts inside the monomial
                          // isomorphism class (see chord.hpp equivariance theorem)
    chord_labeled    = 3, // Lambda = Lambda(LD, g, h): oriented diagram + Z/N chord
                          // labels (cyclotomic layer); the product group
                          // Z/(4k+2) x Z/N acts by monomial twists, and labels add
                          // m*log2(N) bits of key entropy (see chord.hpp)
    tri_chord        = 4  // TRI (Tensor Restriction Isomorphism, TRI design notes):
                          // chord_structured trapdoor, but the public key is only
                          // the restriction psi|_I to a pseudorandom support I of
                          // t = k+1+m slices, serialized in rank-one factored form
                          // (Sec. 3.5). The closed chord diagram - and every
                          // rotation invariant of it - is never published.
};

// TRI support parameters (TRI design notes Sec. 3.3/3.4): |I| = t published
// slices and target weight w on the support. t and w are chosen before
// keygen (for_k_tri); I is derived pseudorandomly at keygen and is public.
struct SupportParams {
    uint32_t t = 0;          // support size; margin m = t - (k+1) >= 1
    uint32_t w = 0;          // projective weight of hash targets on the support
    std::vector<uint32_t> I; // sorted support indices in [0, 2k], size t
    bool active() const { return t != 0; }
};

struct Parameters {
    uint32_t k;    // format (2k+1) x (k+1) x (k+1)
    uint32_t q;    // prime, q > 4k (paper's conservative choice)
    static Parameters for_k(uint32_t k) {
        Parameters p;
        p.k = k;
        p.q = next_prime_above(4 * k);
        return p;
    }
    // chord_structured needs the circle Z/(4k+2) to embed multiplicatively:
    // smallest prime q with q = 1 (mod 4k+2), so F_q^* has an element of exact
    // order 4k+2. Still q > 4k, so all generic requirements hold.
    static Parameters for_k_structured(uint32_t k) {
        Parameters p;
        p.k = k;
        const uint32_t n = 4 * k + 2;
        uint32_t q = n + 1;
        while (!is_prime(q)) q += n;
        p.q = q;
        return p;
    }
    // chord_labeled additionally embeds the label group Z/N: N coprime to the
    // circle 4k+2 (trivial subgroup intersection => automatic column
    // distinctness) and (4k+2)*N | q-1. Default N: smallest odd prime coprime
    // to the circle. label_N is generation-time metadata; verification never
    // needs it, so it is not part of the public key serialization.
    // tri_chord support parameters (t, w); I is filled at keygen.
    SupportParams sup;
    // tri_chord: chord_structured field arithmetic plus the TRI margin rule of
    // TRI design notes Sec. 3.4: t = k+1+m with q^m >= 2^(lambda + slack),
    // lambda = k/2 (paper guidance k = 2*lambda) and a fixed slack for the
    // weight/Groebner gap - a placeholder until m is calibrated
    // experimentally. Default w = m+1 maximizes the off-support preimage
    // entropy (|J| = k+1-w equals the whole hidden complement, Sec. 4.2).
    static constexpr uint32_t TRI_MARGIN_SLACK_BITS = 16;
    static Parameters for_k_tri(uint32_t k, uint32_t m = 0, uint32_t w = 0) {
        Parameters p = for_k_structured(k);
        if (m == 0) {
            double bits = k / 2.0 + TRI_MARGIN_SLACK_BITS;
            m = uint32_t(std::ceil(bits / std::log2(double(p.q))));
        }
        if (m < 1) m = 1;
        if (k + 1 + m > 2 * k + 1)
            throw std::invalid_argument("k too small for the TRI margin: t = k+1+m "
                                        "would exceed the 2k+1 available slices");
        p.sup.t = k + 1 + m;
        p.sup.w = w ? w : m + 1;
        if (p.sup.w < 1 || p.sup.w > k + 1 ||
            (k + 1 - p.sup.w) > (2 * k + 1 - p.sup.t))
            throw std::invalid_argument("TRI weight must satisfy 1 <= w <= k+1 and "
                                        "k+1-w <= 2k+1-t");
        return p;
    }
    uint32_t label_N = 0;
    static Parameters for_k_labeled(uint32_t k, uint32_t N = 0) {
        Parameters p;
        p.k = k;
        const uint32_t circle = 4 * k + 2;
        if (N == 0) {
            N = 3;
            while (!is_prime(N) || std::gcd(N, circle) != 1) N += 2;
        }
        if (std::gcd(N, circle) != 1)
            throw std::invalid_argument("label modulus N must be coprime to 4k+2");
        p.label_N = N;
        const uint64_t modn = uint64_t(circle) * N;
        uint64_t q = modn + 1;
        while (q < (1u << 16) && !is_prime(uint32_t(q))) q += modn;
        if (q >= (1u << 16))
            throw std::invalid_argument("no prototype-range prime q = 1 (mod (4k+2)N)");
        p.q = uint32_t(q);
        return p;
    }
};

struct PublicKey {
    Parameters params;
    Tensor3 psi;                    // public twisted tensor (dense modes; empty in tri_chord)
    std::array<uint8_t, 32> digest; // SHAKE256 digest of the serialized published data

    // tri_chord only: public support and the factored slices psi_a = fx ox fy
    // for a in sup.I (TRI design notes Sec. 3.5), fx canonical projective (first
    // nonzero = 1), all scalars folded into fy. Hidden slices are never
    // computed densely, never stored, never serialized.
    SupportParams sup;
    std::vector<Vec> fx, fy;
    std::vector<uint8_t> support_seed; // tri_chord: I = derive_support(seed, ...)

    std::vector<uint8_t> serialize() const {
        ByteWriter w;
        w.u32(params.k); w.u32(params.q);
        if (sup.active()) {
            // TRI packed framing (Sec. 3.5 + Sec. 7.5 Tier 1): tag byte 0x54
            // ('T') separates the digest domain from the dense framing (whose
            // next byte is n1 = 2k+1, odd, hence never 0x54). The support is
            // serialized as its 32-byte derivation seed, not the index list;
            // field elements are bit-packed at ceil(log2 q) bits; and each
            // fx's canonical prefix (nz zeros then a 1) is stored as the
            // nz index alone. The digest binds (k, q, t, w, seed->I) and
            // every published factor pair - Remark 2 binding extended to I.
            w.u8(0x54);
            w.u32(sup.t); w.u32(sup.w);
            w.bytes(support_seed);
            const uint32_t b = elem_bits(params.q);
            const uint32_t bnz = elem_bits(params.k + 1);
            BitWriter bw;
            for (size_t i = 0; i < fx.size(); i++) {
                uint32_t nz = 0;
                while (fx[i][nz] == 0) nz++;
                bw.bits(nz, bnz); // fx[nz] = 1 and fx[<nz] = 0 are implicit
                for (size_t j = nz + 1; j < fx[i].size(); j++) bw.bits(fx[i][j], b);
                for (size_t j = 0; j < fy[i].size(); j++) bw.bits(fy[i][j], b);
            }
            w.bytes(bw.finish());
        } else {
            w.tensor(psi);
        }
        return w.buf;
    }
    void recompute_digest() { digest = Shake256::digest32(serialize()); }

    static PublicKey deserialize(const std::vector<uint8_t>& bytes);
};

struct SecretKey {
    Parameters params;
    Mode mode = Mode::tensor_reference;
    Vec c2, c3;      // columns of Lambda (each with distinct entries)
    Vec x1_diag;     // diagonal part of X1 (nonzero entries)
    Vec x1_perm;     // permutation part of X1: (X1 w)[i] = d_i * w[perm[i]];
                     // empty = identity (X1 diagonal, legacy modes). Monomial
                     // matrices are the full Hamming-weight-preserving group.
    Mat X2, X3;      // basis change in the two short dimensions
    Mat X2inv, X3inv;                    // precomputed inverses (paper Sec. 3.1)
    std::array<uint8_t, 32> pk_digest{}; // binds signatures to this public key
    std::vector<uint8_t> chord_canonical; // chord modes: canonical diagram bytes
    uint32_t chord_orbit = 0;
    uint32_t chord_loops = 0;
    uint32_t gen_g = 0;   // chord_structured/labeled: order-(4k+2) subgroup generator
    uint32_t rot = 0;     // chord_structured/labeled: secret rotation offset applied to D
    Vec chord_labels;     // chord_labeled: sampled per-chord labels (chord_list order)
    uint32_t label_N = 0;     // chord_labeled: label modulus
    uint32_t gen_h = 0;       // chord_labeled: order-N subgroup generator
    uint32_t label_shift = 0; // chord_labeled: secret global label shift
    std::vector<uint8_t> chord_census; // oriented modes: subdiagram-census digest
    SupportParams sup;                 // tri_chord: copy of the public support
    std::vector<uint8_t> support_seed; // tri_chord: seed the support was derived from
    // tri_chord / chord_structured: the effective oriented diagram defining
    // Lambda (i.e. the input diagram pre-rotated by `rot`). Kept in memory for
    // the TRI leakage experiments (tri_visible_subdiagram) only; deliberately
    // excluded from serialize() - the closed diagram never leaves the process.
    OrientedChordDiagram chord_diagram;

    std::vector<uint8_t> serialize() const {
        ByteWriter w;
        w.u32(params.k); w.u32(params.q);
        w.u8(uint8_t(mode));
        w.vec(c2); w.vec(c3); w.vec(x1_diag); w.vec(x1_perm);
        w.mat(X2); w.mat(X3);
        std::vector<uint8_t> d(pk_digest.begin(), pk_digest.end());
        w.bytes(d);
        w.bytes(chord_canonical);
        w.u32(chord_orbit);
        w.u32(chord_loops);
        w.u32(gen_g);
        w.u32(rot);
        w.vec(chord_labels);
        w.u32(label_N);
        w.u32(gen_h);
        w.u32(label_shift);
        w.bytes(chord_census);
        w.u32(sup.t);
        w.u32(sup.w);
        w.vec(sup.I);
        w.bytes(support_seed);
        return w.buf;
    }
};

struct Signature {
    std::vector<uint8_t> salt; // SALT_BYTES
    Vec u, v;                  // projective vectors in P^k x P^k (canonical reps)

    std::vector<uint8_t> serialize() const {
        ByteWriter w;
        w.bytes(salt);
        w.vec(u); w.vec(v);
        return w.buf;
    }
};

struct KeyPair {
    PublicKey pk;
    SecretKey sk;
    uint32_t keygen_retries = 0; // invertible-matrix rejection count
};

inline constexpr size_t SALT_BYTES = 16;

// ---------------------------------------------------------------------------
// Hash to the Hamming sphere S_{k+1}(P^{2k}), canonical projective form:
// support of size k+1 chosen uniformly; lowest support coordinate fixed to 1
// (canonical representative), remaining support values uniform nonzero.
// Domain-separated and bound to the public key digest.
// ---------------------------------------------------------------------------
inline Vec hash_to_sphere(const Parameters& p,
                          const std::array<uint8_t, 32>& pk_digest,
                          const uint8_t* msg, size_t msg_len,
                          const std::vector<uint8_t>& salt) {
    const Field F(p.q);
    const uint32_t n1 = 2 * p.k + 1;
    Shake256 x;
    x.absorb(std::string("CCTSv1|hash"));
    x.absorb(pk_digest.data(), pk_digest.size());
    x.absorb_u32(uint32_t(msg_len));
    x.absorb(msg, msg_len);
    x.absorb_u32(uint32_t(salt.size()));
    x.absorb(salt);
    x.finalize();

    auto draw_below = [&](uint32_t bound) -> uint32_t {
        // rejection sampling on bytes (bound <= 255 in prototype range)
        const uint32_t limit = (256 / bound) * bound;
        for (;;) {
            uint8_t b;
            x.squeeze(&b, 1);
            if (b < limit) return b % bound;
        }
    };
    auto draw_elem_below = [&](uint32_t bound) -> uint32_t {
        const uint32_t limit = (65536 / bound) * bound;
        for (;;) {
            uint8_t b[2];
            x.squeeze(b, 2);
            uint32_t v = uint32_t(b[0]) | (uint32_t(b[1]) << 8);
            if (v < limit) return v % bound;
        }
    };

    // Support: k+1 distinct indices in [0, 2k].
    std::vector<bool> in(n1, false);
    uint32_t chosen = 0;
    while (chosen < p.k + 1) {
        uint32_t idx = draw_below(n1);
        if (!in[idx]) { in[idx] = true; chosen++; }
    }
    Vec y(n1, 0);
    bool first = true;
    for (uint32_t i = 0; i < n1; i++) {
        if (!in[i]) continue;
        if (first) { y[i] = 1; first = false; }       // canonical: first nonzero = 1
        else y[i] = 1 + draw_elem_below(F.q - 1);     // uniform nonzero
    }
    return y;
}

// ---------------------------------------------------------------------------
// TRI support derivation (TRI design notes Sec. 4.1): I = SHAKE256(seed || domain),
// canonicalized (sorted). Pseudorandom per key - a *fixed* structured support
// (e.g. an arithmetic progression) would interact with the chord rotation
// action and is forbidden; a pseudorandom I is rotation-generic.
// ---------------------------------------------------------------------------
inline std::vector<uint32_t> derive_support(const std::vector<uint8_t>& seed,
                                            uint32_t k, uint32_t q, uint32_t t) {
    const uint32_t n1 = 2 * k + 1;
    assert(t <= n1 && n1 <= 255); // prototype range (k <= 127)
    Shake256 x;
    x.absorb(std::string("CCTSv1|TRI-support"));
    x.absorb_u32(k);
    x.absorb_u32(q);
    x.absorb_u32(t);
    x.absorb(seed);
    x.finalize();
    const uint32_t limit = (256 / n1) * n1;
    std::vector<bool> in(n1, false);
    uint32_t chosen = 0;
    while (chosen < t) {
        uint8_t b;
        x.squeeze(&b, 1);
        if (b >= limit) continue;
        uint32_t idx = b % n1;
        if (!in[idx]) { in[idx] = true; chosen++; }
    }
    std::vector<uint32_t> I;
    I.reserve(t);
    for (uint32_t i = 0; i < n1; i++)
        if (in[i]) I.push_back(i);
    return I;
}

// Both framings: dense (tensor) and TRI packed (tag 0x54). The TRI support is
// re-derived from the serialized seed; fx's canonical prefix is reconstructed
// from the stored nz index. recompute_digest() on the result reproduces the
// original digest bit-for-bit (the framing is canonical).
inline PublicKey PublicKey::deserialize(const std::vector<uint8_t>& bytes) {
    ByteReader r(bytes);
    PublicKey pk;
    pk.params.k = r.u32();
    pk.params.q = r.u32();
    if (bytes.at(r.pos) == 0x54) {
        r.u8();
        pk.sup.t = r.u32();
        pk.sup.w = r.u32();
        pk.support_seed = r.bytes();
        pk.sup.I = derive_support(pk.support_seed, pk.params.k, pk.params.q, pk.sup.t);
        pk.params.sup.t = pk.sup.t;
        pk.params.sup.w = pk.sup.w;
        const std::vector<uint8_t> payload = r.bytes();
        BitReader br(payload);
        const uint32_t n23 = pk.params.k + 1;
        const uint32_t b = elem_bits(pk.params.q);
        const uint32_t bnz = elem_bits(pk.params.k + 1);
        for (uint32_t i = 0; i < pk.sup.t; i++) {
            Vec x(n23, 0), y(n23, 0);
            uint32_t nz = br.bits(bnz);
            x[nz] = 1;
            for (uint32_t j = nz + 1; j < n23; j++) x[j] = br.bits(b);
            for (uint32_t j = 0; j < n23; j++) y[j] = br.bits(b);
            pk.fx.push_back(std::move(x));
            pk.fy.push_back(std::move(y));
        }
    } else {
        pk.psi = r.tensor();
    }
    pk.recompute_digest();
    return pk;
}

// ---------------------------------------------------------------------------
// Packed signature encoding (TRI design notes Sec. 7.5 Tier 1): salt plus u || v
// radix-coded as a single base-q integer - ceil(2(k+1) log2 q) bits total,
// the tri_chord wire format. At k = 256 (q = 2053) this is 731 B versus 795 B
// fixed-width and 1,052 B at two bytes per element. The legacy two-byte
// Signature::serialize() remains the dense modes' format.
// ---------------------------------------------------------------------------
inline std::vector<uint8_t> serialize_signature_packed(const Signature& sig,
                                                       const Parameters& p) {
    ByteWriter w;
    w.bytes(sig.salt);
    Vec uv = sig.u;
    uv.insert(uv.end(), sig.v.begin(), sig.v.end());
    w.bytes(radix_pack(uv, p.q));
    return w.buf;
}

inline Signature deserialize_signature_packed(const std::vector<uint8_t>& bytes,
                                              const Parameters& p) {
    ByteReader r(bytes);
    Signature sig;
    sig.salt = r.bytes();
    const uint32_t n23 = p.k + 1;
    Vec uv = radix_unpack(r.bytes(), p.q, size_t(2) * n23);
    sig.u.assign(uv.begin(), uv.begin() + n23);
    sig.v.assign(uv.begin() + n23, uv.end());
    return sig;
}

// ---------------------------------------------------------------------------
// Hash to the restricted sphere (TRI design notes Sec. 4.2): a weight-w canonical
// projective vector *indexed by the support* (position idx refers to the
// idx-th smallest element of I). Domain-separated from the full-sphere hash;
// the pk digest absorbed here binds (I, t, w) and all published factor pairs.
// ---------------------------------------------------------------------------
inline Vec hash_to_support_sphere(const Parameters& p, const SupportParams& sup,
                                  const std::array<uint8_t, 32>& pk_digest,
                                  const uint8_t* msg, size_t msg_len,
                                  const std::vector<uint8_t>& salt) {
    const Field F(p.q);
    const uint32_t t = sup.t;
    assert(t >= 1 && t <= 255);
    Shake256 x;
    x.absorb(std::string("CCTSv1|hash-tri"));
    x.absorb(pk_digest.data(), pk_digest.size());
    x.absorb_u32(uint32_t(msg_len));
    x.absorb(msg, msg_len);
    x.absorb_u32(uint32_t(salt.size()));
    x.absorb(salt);
    x.finalize();

    auto draw_below = [&](uint32_t bound) -> uint32_t {
        const uint32_t limit = (256 / bound) * bound;
        for (;;) {
            uint8_t b;
            x.squeeze(&b, 1);
            if (b < limit) return b % bound;
        }
    };
    auto draw_elem_below = [&](uint32_t bound) -> uint32_t {
        const uint32_t limit = (65536 / bound) * bound;
        for (;;) {
            uint8_t b[2];
            x.squeeze(b, 2);
            uint32_t v = uint32_t(b[0]) | (uint32_t(b[1]) << 8);
            if (v < limit) return v % bound;
        }
    };

    // Weight-w support-of-the-target within the t published positions.
    std::vector<bool> in(t, false);
    uint32_t chosen = 0;
    while (chosen < sup.w) {
        uint32_t idx = draw_below(t);
        if (!in[idx]) { in[idx] = true; chosen++; }
    }
    Vec y(t, 0);
    bool first = true;
    for (uint32_t i = 0; i < t; i++) {
        if (!in[i]) continue;
        if (first) { y[i] = 1; first = false; }       // canonical: first nonzero = 1
        else y[i] = 1 + draw_elem_below(F.q - 1);     // uniform nonzero
    }
    return y;
}

// ---------------------------------------------------------------------------
// Lambda derivation. tensor_reference: from the DRBG directly.
// chord_tensor: SHAKE256(seed || canonical chord encoding || orbit || loops),
// i.e. the diagram contributes reproducible cyclic structure; the seed
// contributes all the entropy. Rejection keeps each column's entries distinct.
// ---------------------------------------------------------------------------
inline Vec distinct_column(const Field& F, uint32_t n, Drbg& rng) {
    std::vector<bool> used(F.q, false);
    Vec col;
    col.reserve(n);
    while (col.size() < n) {
        uint32_t e = rng.field_elem(F);
        if (!used[e]) { used[e] = true; col.push_back(e); }
    }
    return col;
}

struct ChordContext {
    ChordDiagram diagram;
    std::vector<uint8_t> canonical;
    uint32_t orbit = 0;
    uint32_t loops = 0;
};

// Monomial matrix M with (M w)[i] = d[i] * w[perm[i]] under the convention
// (X w)[i] = sum_a X[i][a] w[a], i.e. M[i][perm[i]] = d[i]. Empty perm = identity.
inline Mat monomial_matrix(uint32_t n, const Vec& perm, const Vec& diag) {
    Mat M(n, n);
    for (uint32_t i = 0; i < n; i++)
        M.at(i, perm.empty() ? i : perm[i]) = diag[i];
    return M;
}

inline Vec random_permutation(uint32_t n, Drbg& rng) {
    Vec p(n);
    for (uint32_t i = 0; i < n; i++) p[i] = i;
    for (uint32_t i = n; i-- > 1;) std::swap(p[i], p[rng.uniform(i + 1)]);
    return p;
}

inline KeyPair keygen(const Parameters& params, Drbg& rng,
                      Mode mode = Mode::tensor_reference,
                      const ChordDiagram* diagram_in = nullptr,
                      const OrientedChordDiagram* oriented_in = nullptr,
                      const LabeledChordDiagram* labeled_in = nullptr) {
    if (params.q <= 4 * params.k || !is_prime(params.q))
        throw std::invalid_argument("parameters require prime q > 4k");
    const Field F(params.q);
    const uint32_t n1 = 2 * params.k + 1, n23 = params.k + 1;

    KeyPair kp;
    kp.sk.params = kp.pk.params = params;
    kp.sk.mode = mode;

    if (mode == Mode::chord_structured || mode == Mode::tri_chord) {
        // The oriented diagram IS the discrete structure of Lambda. Require the
        // circle Z/(4k+2) to embed as a multiplicative subgroup. tri_chord is
        // chord_structured with a restricted public key (TRI design notes Sec. 4).
        const uint32_t circle = 2 * n1; // 4k+2 endpoints, n1 = 2k+1 chords
        if ((params.q - 1) % circle != 0)
            throw std::invalid_argument("chord_structured requires (4k+2) | (q-1); "
                                        "use Parameters::for_k_structured");
        if (2 * n1 - 1 > 255)
            throw std::invalid_argument("prototype limit: k <= 127 in chord_structured");
        OrientedChordDiagram D = oriented_in ? *oriented_in
                                             : OrientedChordDiagram::random(n1, rng);
        assert(D.valid() && D.chords() == n1);
        kp.sk.rot = rng.uniform(circle);                     // secret rotation offset
        kp.sk.gen_g = element_of_order(F, circle, &rng);     // secret subgroup generator
        OrientedChordDiagram Drot = D.rotated(kp.sk.rot);
        lambda_from_diagram(F, Drot, kp.sk.gen_g, kp.sk.c2, kp.sk.c3);
        kp.sk.chord_diagram = Drot; // in-memory only; never serialized

        uint32_t stab = 1;
        (void)D.canonical_sequence(&stab);
        kp.sk.chord_canonical = D.canonical_bytes();
        kp.sk.chord_orbit = D.endpoints() / stab;
        kp.sk.chord_loops = D.closure_loops();
        kp.sk.chord_census = census_digest(D, 2);

        // X1 monomial: the full weight-preserving restricted isomorphism group
        // (permutation x nonzero diagonal). This is what makes diagram rotation
        // an *internal* symmetry of the key's isomorphism class.
        kp.sk.x1_perm = random_permutation(n1, rng);
    } else if (mode == Mode::chord_labeled) {
        // Cyclotomic layer: oriented diagram + Z/N chord labels; the product
        // group Z/(4k+2) x Z/N acts by monomial twists (chord.hpp theorem).
        const uint32_t circle = 2 * n1;
        const uint32_t N = params.label_N;
        if (N < 2 || std::gcd(N, circle) != 1)
            throw std::invalid_argument("chord_labeled requires label_N >= 2 coprime to 4k+2; "
                                        "use Parameters::for_k_labeled");
        if ((params.q - 1) % (uint64_t(circle) * N) != 0)
            throw std::invalid_argument("chord_labeled requires (4k+2)*N | (q-1); "
                                        "use Parameters::for_k_labeled");
        if (2 * n1 - 1 > 255)
            throw std::invalid_argument("prototype limit: k <= 127 in chord_labeled");
        LabeledChordDiagram LD = labeled_in ? *labeled_in
                                            : LabeledChordDiagram::random(n1, N, rng);
        assert(LD.valid() && LD.chords() == n1 && LD.N == N);
        kp.sk.rot = rng.uniform(circle);          // secret rotation offset
        kp.sk.label_shift = rng.uniform(N);       // secret label shift
        kp.sk.gen_g = element_of_order(F, circle, &rng);
        kp.sk.gen_h = element_of_order(F, N, &rng);
        LabeledChordDiagram LDs = LD.rotated(kp.sk.rot).shifted(kp.sk.label_shift);
        lambda_from_labeled_diagram(F, LDs, kp.sk.gen_g, kp.sk.gen_h,
                                    kp.sk.c2, kp.sk.c3);

        uint32_t stab = 1;
        (void)LD.canonical_sequence(&stab);
        kp.sk.chord_canonical = LD.canonical_bytes();
        kp.sk.chord_orbit = LD.endpoints() * N / stab; // product-group orbit
        kp.sk.chord_loops = LD.closure_loops();
        kp.sk.chord_census = census_digest(LD.D, 2);
        kp.sk.chord_labels = LD.labels;
        kp.sk.label_N = N;

        kp.sk.x1_perm = random_permutation(n1, rng);
    } else if (mode == Mode::chord_tensor) {
        // Diagram: supplied, or drawn from the DRBG (k chords).
        ChordDiagram d = diagram_in ? *diagram_in : ChordDiagram::random(params.k, rng);
        assert(d.valid());
        uint32_t stab = 1;
        auto canon = d.canonical_sequence(&stab);
        (void)canon;
        kp.sk.chord_canonical = d.canonical_bytes();
        kp.sk.chord_orbit = d.endpoints() / stab;
        kp.sk.chord_loops = d.closure_loops();

        // Secret seed provides entropy; chord canonical encoding provides
        // reproducible cyclic structure.
        std::vector<uint8_t> seed = rng.bytes(32);
        Shake256 x;
        x.absorb(std::string("CCTSv1|chord-lambda"));
        x.absorb(seed);
        x.absorb(kp.sk.chord_canonical);
        x.absorb_u32(kp.sk.chord_orbit);
        x.absorb_u32(kp.sk.chord_loops);
        x.absorb_u32(d.closure_value(F, 2)); // contraction value of the closed network
        x.finalize();
        // Wrap the XOF stream as a DRBG-compatible sampler.
        std::vector<uint8_t> stream_seed = x.squeeze(32);
        Drbg lam_rng(stream_seed, "CCTSv1|chord-lambda-expand");
        kp.sk.c2 = distinct_column(F, n1, lam_rng);
        kp.sk.c3 = distinct_column(F, n1, lam_rng);
    } else {
        kp.sk.c2 = distinct_column(F, n1, rng);
        kp.sk.c3 = distinct_column(F, n1, rng);
    }

    // X1 monomial (permutation x nonzero diagonal): the weight-preserving
    // restricted isomorphisms. Legacy modes keep the identity permutation, so
    // their DRBG consumption and keys are unchanged.
    kp.sk.x1_diag.resize(n1);
    for (auto& e : kp.sk.x1_diag) e = rng.nonzero_field_elem(F);

    auto [X2, r2] = sample_invertible(F, n23, rng);
    auto [X3, r3] = sample_invertible(F, n23, rng);
    kp.keygen_retries = r2 + r3;
    kp.sk.X2 = X2; kp.sk.X3 = X3;
    kp.sk.X2inv = *mat_inverse(F, X2);
    kp.sk.X3inv = *mat_inverse(F, X3);

    if (mode == Mode::tri_chord) {
        // TRI public key (TRI design notes Sec. 4.1): derive the pseudorandom
        // support I and publish only the factored slices for a in I. The dense
        // psi - and in particular every hidden slice - is never materialized.
        const SupportParams& sp = params.sup;
        if (sp.t < params.k + 2 || sp.t > n1)
            throw std::invalid_argument("TRI support must satisfy k+2 <= t <= 2k+1: "
                                        "t <= k+1 is a total break (Sec. 3.4); "
                                        "use Parameters::for_k_tri");
        if (sp.w < 1 || sp.w > params.k + 1 ||
            (params.k + 1 - sp.w) > (n1 - sp.t))
            throw std::invalid_argument("TRI weight must satisfy 1 <= w <= k+1 and "
                                        "k+1-w <= 2k+1-t");
        kp.sk.support_seed = rng.bytes(32);
        SupportParams sup = sp;
        sup.I = derive_support(kp.sk.support_seed, params.k, params.q, sp.t);

        // Factored slices (Sec. 3.1/3.5). X1 monomial with X1[i][perm[i]] = d_i
        // means slice a of psi comes from secret row i = perm^{-1}(a):
        //   psi_a = d_i * (X2^T v(c2[i])) ox (X3^T v(c3[i])).
        // Publish fx = X2^T v(c2[i]) scaled canonical (first nonzero = 1) and
        // fy = X3^T v(c3[i]) with d_i and the canonicalization scalar folded in.
        std::vector<uint32_t> ip(n1);
        for (uint32_t i = 0; i < n1; i++)
            ip[kp.sk.x1_perm.empty() ? i : kp.sk.x1_perm[i]] = i;
        for (uint32_t a : sup.I) {
            const uint32_t i = ip[a];
            Vec v2(n23), v3(n23);
            v2[0] = v3[0] = 1;
            for (uint32_t d = 1; d < n23; d++) {
                v2[d] = F.mul(v2[d - 1], kp.sk.c2[i]);
                v3[d] = F.mul(v3[d - 1], kp.sk.c3[i]);
            }
            Vec x(n23, 0), y(n23, 0);
            for (uint32_t b = 0; b < n23; b++) {
                uint64_t ax = 0, ay = 0;
                for (uint32_t j = 0; j < n23; j++) {
                    ax += uint64_t(X2.at(j, b)) * v2[j] % F.q;
                    ay += uint64_t(X3.at(j, b)) * v3[j] % F.q;
                }
                x[b] = uint32_t(ax % F.q);
                y[b] = uint32_t(ay % F.q);
            }
            // x != 0 (X2 invertible, v2 != 0); canonicalize and fold scalars.
            size_t nz = 0;
            while (x[nz] == 0) nz++;
            const uint32_t s = x[nz], sinv = F.inv(s);
            for (auto& e : x) e = F.mul(e, sinv);
            const uint32_t fold = F.mul(s, kp.sk.x1_diag[i]);
            for (auto& e : y) e = F.mul(e, fold);
            kp.pk.fx.push_back(std::move(x));
            kp.pk.fy.push_back(std::move(y));
        }
        kp.pk.sup = sup;
        kp.sk.sup = sup;
        kp.pk.support_seed = kp.sk.support_seed;
    } else {
        // Public tensor psi = phi<Lambda>^{(X1,X2,X3)}.
        Tensor3 phi = build_vwz(F, params.k, kp.sk.c2, kp.sk.c3);
        Mat X1 = monomial_matrix(n1, kp.sk.x1_perm, kp.sk.x1_diag);
        kp.pk.psi = twist(F, phi, X1, X2, X3);
    }
    kp.pk.recompute_digest();
    kp.sk.pk_digest = kp.pk.digest;
    return kp;
}

// ---------------------------------------------------------------------------
// TRI leakage-experiment helper (TRI design notes): the
// sub-diagram of the secret chord diagram visible through the public support -
// the chords whose slices land in I under the monomial permutation of X1.
// Research/analysis use only; the closed diagram and this restriction are
// never serialized with either key half.
// ---------------------------------------------------------------------------
inline OrientedChordDiagram tri_visible_subdiagram(const SecretKey& sk) {
    if (!sk.sup.active() || sk.chord_diagram.chords() == 0)
        throw std::invalid_argument("tri_visible_subdiagram needs a tri_chord secret key");
    const uint32_t n1 = 2 * sk.params.k + 1;
    std::vector<uint32_t> ip(n1);
    for (uint32_t i = 0; i < n1; i++)
        ip[sk.x1_perm.empty() ? i : sk.x1_perm[i]] = i;
    std::vector<uint32_t> rows;
    rows.reserve(sk.sup.I.size());
    for (uint32_t a : sk.sup.I) rows.push_back(ip[a]);
    std::sort(rows.begin(), rows.end());
    return sk.chord_diagram.restricted(rows);
}

// ---------------------------------------------------------------------------
// Sign: salt <- rng; y = H(pk, m, salt) on the sphere; y0 = X1^{-1} y
// (diagonal, weight-preserving); SamplePre3DB coin picks the vanishing
// dimension; preimage (w2, w3) against phi; publish (X2^{-1} w2, X3^{-1} w3)
// projectivized. Never fails; `retries_out` reports 0 by construction.
// ---------------------------------------------------------------------------
inline Signature sign(const uint8_t* msg, size_t msg_len, const SecretKey& sk,
                      Drbg& rng, uint32_t* retries_out = nullptr,
                      PolyBackend backend = PolyBackend::autoselect) {
    const Field F(sk.params.q);
    const uint32_t n1 = 2 * sk.params.k + 1;

    Signature sig;
    sig.salt = rng.bytes(SALT_BYTES);
    Vec y;
    if (sk.sup.active()) {
        // TRI (TRI design notes Sec. 4.2): hash to a weight-w target on the
        // support, then extend it off-support with fresh coins - a uniform
        // (k+1-w)-subset J of the hidden coordinates with uniform nonzero
        // values. This replaces and strictly generalizes the single Z/2
        // SamplePre3DB coin (which remains, below); the hidden coordinates are
        // signer freedom. J and its values come from the seeded RNG only (no
        // data-dependent branching, Sec. 5.3).
        Vec ys = hash_to_support_sphere(sk.params, sk.sup, sk.pk_digest,
                                        msg, msg_len, sig.salt);
        y.assign(n1, 0);
        std::vector<bool> in_I(n1, false);
        for (size_t idx = 0; idx < sk.sup.I.size(); idx++) {
            y[sk.sup.I[idx]] = ys[idx];
            in_I[sk.sup.I[idx]] = true;
        }
        std::vector<uint32_t> C; // hidden complement
        C.reserve(n1 - sk.sup.t);
        for (uint32_t i = 0; i < n1; i++)
            if (!in_I[i]) C.push_back(i);
        const uint32_t jn = (sk.params.k + 1) - sk.sup.w; // |J| <= |C| by keygen
        for (uint32_t s = 0; s < jn; s++) { // partial Fisher-Yates: uniform subset
            std::swap(C[s], C[s + rng.uniform(uint32_t(C.size()) - s)]);
            y[C[s]] = rng.nonzero_field_elem(F);
        }
        // y is now on the full sphere S_{k+1}(P^{2k}) with y|_I = ys.
    } else {
        y = hash_to_sphere(sk.params, sk.pk_digest, msg, msg_len, sig.salt);
    }

    // Solve X1^T y0 = y for the monomial X1 with X1[i][perm[i]] = d_i:
    // y0[i] = y[perm[i]] / d_i. Monomial maps preserve Hamming weight, so y0
    // stays on the sphere. Identity permutation reduces to the diagonal case.
    Vec y0(n1);
    for (uint32_t i = 0; i < n1; i++) {
        uint32_t a = sk.x1_perm.empty() ? i : sk.x1_perm[i];
        y0[i] = F.mul(y[a], F.inv(sk.x1_diag[i]));
    }

    bool coin = rng.bit(); // SamplePre3DB dimension-swap coin
    Vec w2, w3;
    bool ok = vwz_preimage(F, sk.params.k, sk.c2, sk.c3, y0, coin, w2, w3, backend);
    if (!ok) throw std::runtime_error("preimage sampling failed (should not happen)");

    sig.u = mat_vec(F, sk.X2inv, w2);
    sig.v = mat_vec(F, sk.X3inv, w3);
    projectivize(F, sig.u);
    projectivize(F, sig.v);
    if (retries_out) *retries_out = 0;
    return sig;
}

inline bool verify(const uint8_t* msg, size_t msg_len, const Signature& sig,
                   const PublicKey& pk) {
    const Field F(pk.params.q);
    const uint32_t n23 = pk.params.k + 1;
    if (sig.salt.size() != SALT_BYTES) return false;
    if (sig.u.size() != n23 || sig.v.size() != n23) return false;
    if (is_zero_vec(sig.u) || is_zero_vec(sig.v)) return false;
    for (auto e : sig.u) if (e >= pk.params.q) return false;
    for (auto e : sig.v) if (e >= pk.params.q) return false;

    if (pk.sup.active()) {
        // TRI (TRI design notes Sec. 4.3): evaluate the published slices only -
        // two inner products per coordinate, O(t*k) total - and check
        // entirely inside the support.
        const uint32_t t = pk.sup.t;
        if (pk.sup.I.size() != t || pk.fx.size() != t || pk.fy.size() != t)
            return false;
        Vec y = hash_to_support_sphere(pk.params, pk.sup, pk.digest,
                                       msg, msg_len, sig.salt);
        Vec z(t);
        for (uint32_t idx = 0; idx < t; idx++) {
            if (pk.fx[idx].size() != n23 || pk.fy[idx].size() != n23) return false;
            z[idx] = F.mul(dot(F, pk.fx[idx], sig.u), dot(F, pk.fy[idx], sig.v));
        }
        if (hamming_weight(z) != pk.sup.w) return false;
        if (!projectivize(F, z)) return false;
        return z == y; // y is already canonical
    }

    Vec y = hash_to_sphere(pk.params, pk.digest, msg, msg_len, sig.salt);
    Vec w = tensor_eval(F, pk.psi, sig.u, sig.v);
    if (!projectivize(F, w)) return false; // evaluated to zero: reject
    return w == y;                          // y is already canonical
}

// Convenience wrappers.
inline Signature sign(const std::vector<uint8_t>& msg, const SecretKey& sk, Drbg& rng) {
    return sign(msg.data(), msg.size(), sk, rng);
}
inline bool verify(const std::vector<uint8_t>& msg, const Signature& sig, const PublicKey& pk) {
    return verify(msg.data(), msg.size(), sig, pk);
}

// Exact API from the project specification (system-entropy salt/coin).
inline KeyPair keygen(const Parameters& parameters) {
    Drbg rng = Drbg::from_system_entropy();
    return keygen(parameters, rng);
}
inline Signature sign(std::span<const std::byte> message, const SecretKey& secret_key) {
    Drbg rng = Drbg::from_system_entropy();
    return sign(reinterpret_cast<const uint8_t*>(message.data()), message.size(),
                secret_key, rng);
}
inline bool verify(std::span<const std::byte> message, const Signature& signature,
                   const PublicKey& public_key) {
    return verify(reinterpret_cast<const uint8_t*>(message.data()), message.size(),
                  signature, public_key);
}

} // namespace ccts
