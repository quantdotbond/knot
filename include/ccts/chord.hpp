#pragma once
// Minimal chord-diagram layer (after Singh, "Cyclic Symmetries of Chord
// Diagrams"): cyclically ordered endpoints, perfect matchings, rotation action,
// canonical encoding modulo rotation, and evaluation of the induced small
// tensor-contraction (closure/trace) network.
//
// Only the finite combinatorial layer is implemented; no associators or
// Grothendieck-Teichmueller structure.
#include "field.hpp"
#include "rng.hpp"
#include "shake.hpp"
#include <vector>
#include <string>
#include <algorithm>
#include <cassert>
#include <numeric>
#include <map>

namespace ccts {

struct ChordDiagram {
    // match[i] = partner endpoint of i, over endpoints 0..2n-1 in cyclic order.
    std::vector<uint32_t> match;

    uint32_t endpoints() const { return uint32_t(match.size()); }
    uint32_t chords() const { return endpoints() / 2; }

    bool valid() const {
        uint32_t m = endpoints();
        if (m == 0 || m % 2) return false;
        for (uint32_t i = 0; i < m; i++) {
            if (match[i] >= m || match[i] == i) return false;
            if (match[match[i]] != i) return false;
        }
        return true;
    }

    // Cyclic rotation by r: endpoint i of the rotated diagram corresponds to
    // endpoint (i + r) mod 2n of the original.
    ChordDiagram rotated(uint32_t r) const {
        uint32_t m = endpoints();
        ChordDiagram d;
        d.match.resize(m);
        for (uint32_t i = 0; i < m; i++)
            d.match[i] = (match[(i + r) % m] + m - r % m) % m;
        return d;
    }

    // First-occurrence chord labelling: walk endpoints in cyclic order, assign
    // each chord a label in order of first appearance. E.g. the crossing
    // diagram on 4 endpoints encodes as [0,1,0,1].
    std::vector<uint32_t> label_sequence() const {
        uint32_t m = endpoints();
        std::vector<int32_t> lab(m, -1);
        std::vector<uint32_t> seq(m);
        uint32_t next = 0;
        for (uint32_t i = 0; i < m; i++) {
            if (lab[i] < 0) {
                lab[i] = lab[match[i]] = int32_t(next++);
            }
            seq[i] = uint32_t(lab[i]);
        }
        return seq;
    }

    // Canonical encoding modulo rotation: lexicographically minimal label
    // sequence over all 2n rotations. Also reports the rotation stabiliser
    // order (number of rotations fixing the canonical sequence), from which
    // the cyclic orbit size is 2n / stabiliser.
    std::vector<uint32_t> canonical_sequence(uint32_t* stabiliser_out = nullptr) const {
        uint32_t m = endpoints();
        std::vector<uint32_t> best;
        uint32_t hits = 0;
        for (uint32_t r = 0; r < m; r++) {
            auto seq = rotated(r).label_sequence();
            if (best.empty() || seq < best) { best = seq; hits = 1; }
            else if (seq == best) hits++;
        }
        if (stabiliser_out) *stabiliser_out = hits;
        return best;
    }

    uint32_t orbit_size() const {
        uint32_t stab = 1;
        canonical_sequence(&stab);
        return endpoints() / stab;
    }

    // Stable serialization of the canonical form (one byte per label; prototype
    // restricts to <= 255 chords).
    std::vector<uint8_t> canonical_bytes() const {
        auto seq = canonical_sequence();
        std::vector<uint8_t> out;
        out.reserve(seq.size() + 4);
        uint32_t n = chords();
        out.push_back(uint8_t(n)); out.push_back(uint8_t(n >> 8));
        out.push_back(uint8_t(n >> 16)); out.push_back(uint8_t(n >> 24));
        for (auto s : seq) out.push_back(uint8_t(s));
        return out;
    }

    // --- Tensor-contraction (closure) network -------------------------------
    // Realize each chord as a metric pairing (identity contraction) on a
    // d-dimensional space and close the diagram along the circle: endpoint i is
    // wired to endpoint i+1 (mod 2n) by the cyclic structure and to match[i] by
    // its chord. The contraction value of the closed network is d^{#loops}.
    // The loop count is the number of cycles of the permutation
    //     sigma(i) = match(i) + 1 (mod 2n),
    // and is a rotation invariant of the diagram.
    uint32_t closure_loops() const {
        uint32_t m = endpoints();
        std::vector<bool> seen(m, false);
        uint32_t loops = 0;
        for (uint32_t s = 0; s < m; s++) {
            if (seen[s]) continue;
            loops++;
            uint32_t i = s;
            while (!seen[i]) {
                seen[i] = true;
                i = (match[i] + 1) % m;
            }
        }
        return loops;
    }

    // Contraction value of the closed network over F_q with fibre dimension d.
    uint32_t closure_value(const Field& F, uint32_t d) const {
        return F.pow(d % F.q, closure_loops());
    }

    static ChordDiagram random(uint32_t n_chords, Drbg& rng) {
        uint32_t m = 2 * n_chords;
        std::vector<uint32_t> free_pts(m);
        for (uint32_t i = 0; i < m; i++) free_pts[i] = i;
        ChordDiagram d;
        d.match.assign(m, 0);
        // Repeatedly pair the smallest free endpoint with a uniform other one.
        while (!free_pts.empty()) {
            uint32_t a = free_pts.front();
            uint32_t idx = 1 + rng.uniform(uint32_t(free_pts.size() - 1));
            uint32_t b = free_pts[idx];
            d.match[a] = b;
            d.match[b] = a;
            free_pts.erase(free_pts.begin() + idx);
            free_pts.erase(free_pts.begin());
        }
        return d;
    }
};

// ===========================================================================
// Structured Lambda layer: oriented chord diagrams as the discrete part of a
// VWZ trapdoor, with the rotation action embedded in the (monomial-restricted)
// tensor isomorphism group.
//
// Setup. Fix q with (2m) | (q - 1), where m is the number of chords, and let
// g in F_q^* have exact multiplicative order 2m, so positions on the circle
// Z/2m embed as the subgroup <g>. An *oriented* diagram D assigns each chord a
// tail t_i and head h_i. Sorting chords by tail position, define
//
//     Lambda(D, g):   c2[i] = g^{t_i},  c3[i] = g^{h_i}.
//
// Within-column distinctness (Weyman-Zelevinsky non-degeneracy) holds by
// construction: tails are distinct positions, heads are distinct positions,
// and a -> g^a is injective on Z/2m.
//
// EQUIVARIANCE THEOREM (tested exactly in the suite). For every rotation r,
//
//   phi<Lambda(rho_r D, g)> = phi<Lambda(D, g)>^{(P, diag(s^j), diag(s^l))},
//
// where s = g^{-r}, P is the permutation matrix matching rows by chord, and
// the diagonal twists act on the two short dimensions. Since permutation x
// diagonal (monomial) maps preserve Hamming weight, rotation acts *within*
// the weight-preserving restricted isomorphism class of the key. Hence the
// diagram's rotation class - and every rotation invariant (canonical form,
// cyclic orbit size, closure loop count) - is a well-defined invariant of the
// structured tensor's restricted orbit. The orbit-membership problem for the
// structured family therefore *contains* recovery of these chord invariants
// from the public twisted tensor.
// ===========================================================================

struct OrientedChordDiagram {
    ChordDiagram base;
    std::vector<uint8_t> is_tail; // per endpoint: 1 = tail, 0 = head

    uint32_t endpoints() const { return base.endpoints(); }
    uint32_t chords() const { return base.chords(); }

    bool valid() const {
        if (!base.valid()) return false;
        if (is_tail.size() != base.match.size()) return false;
        for (uint32_t i = 0; i < endpoints(); i++)
            if ((is_tail[i] ^ is_tail[base.match[i]]) != 1) return false;
        return true;
    }

    OrientedChordDiagram rotated(uint32_t r) const {
        uint32_t m = endpoints();
        OrientedChordDiagram d;
        d.base = base.rotated(r);
        d.is_tail.resize(m);
        for (uint32_t i = 0; i < m; i++) d.is_tail[i] = is_tail[(i + r) % m];
        return d;
    }

    // Chords as (tail, head) position pairs, sorted by tail position; this is
    // the canonical row order of Lambda(D, g).
    std::vector<std::pair<uint32_t, uint32_t>> chord_list() const {
        std::vector<std::pair<uint32_t, uint32_t>> out;
        out.reserve(chords());
        for (uint32_t i = 0; i < endpoints(); i++)
            if (is_tail[i]) out.push_back({i, base.match[i]});
        std::sort(out.begin(), out.end());
        return out;
    }

    // Orientation-aware label sequence: 2 * first-occurrence chord label + tail
    // bit at each endpoint. Rotation acts by cyclic shift + relabelling.
    std::vector<uint32_t> label_sequence() const {
        auto lab = base.label_sequence();
        std::vector<uint32_t> seq(lab.size());
        for (size_t i = 0; i < lab.size(); i++)
            seq[i] = 2 * lab[i] + (is_tail[i] ? 1 : 0);
        return seq;
    }

    // Canonical encoding modulo rotation (lexicographically minimal oriented
    // label sequence) and rotation stabiliser order.
    std::vector<uint32_t> canonical_sequence(uint32_t* stabiliser_out = nullptr) const {
        uint32_t m = endpoints();
        std::vector<uint32_t> best;
        uint32_t hits = 0;
        for (uint32_t r = 0; r < m; r++) {
            auto seq = rotated(r).label_sequence();
            if (best.empty() || seq < best) { best = seq; hits = 1; }
            else if (seq == best) hits++;
        }
        if (stabiliser_out) *stabiliser_out = hits;
        return best;
    }

    uint32_t orbit_size() const {
        uint32_t stab = 1;
        canonical_sequence(&stab);
        return endpoints() / stab;
    }

    std::vector<uint8_t> canonical_bytes() const {
        auto seq = canonical_sequence();
        std::vector<uint8_t> out;
        out.reserve(seq.size() + 5);
        uint32_t n = chords();
        out.push_back(0x4f); // 'O' domain tag: oriented encoding
        out.push_back(uint8_t(n)); out.push_back(uint8_t(n >> 8));
        out.push_back(uint8_t(n >> 16)); out.push_back(uint8_t(n >> 24));
        for (auto s : seq) out.push_back(uint8_t(s)); // fits: 2*chords-1 <= 255 checked by caller
        return out;
    }

    // Closure loop count is orientation-independent, hence inherited.
    uint32_t closure_loops() const { return base.closure_loops(); }
    uint32_t closure_value(const Field& F, uint32_t d) const {
        return base.closure_value(F, d);
    }

    static OrientedChordDiagram random(uint32_t n_chords, Drbg& rng) {
        OrientedChordDiagram d;
        d.base = ChordDiagram::random(n_chords, rng);
        d.is_tail.assign(2 * n_chords, 0);
        std::vector<bool> done(2 * n_chords, false);
        for (uint32_t i = 0; i < 2 * n_chords; i++) {
            if (done[i]) continue;
            uint32_t j = d.base.match[i];
            bool i_is_tail = rng.bit();
            d.is_tail[i] = i_is_tail ? 1 : 0;
            d.is_tail[j] = i_is_tail ? 0 : 1;
            done[i] = done[j] = true;
        }
        return d;
    }

    // Restriction to a subset of chords (indices into chord_list()): keep the
    // chosen chords' endpoints in their circular order and renumber 0..2j-1.
    // Restriction commutes with rotation up to a rotation of the small diagram,
    // which is what makes the subdiagram census below rotation-invariant.
    OrientedChordDiagram restricted(const std::vector<uint32_t>& chord_rows) const {
        auto list = chord_list();
        std::vector<uint32_t> pts;
        pts.reserve(2 * chord_rows.size());
        for (uint32_t r : chord_rows) {
            pts.push_back(list[r].first);
            pts.push_back(list[r].second);
        }
        std::sort(pts.begin(), pts.end());
        std::vector<int32_t> idx(endpoints(), -1);
        for (uint32_t i = 0; i < pts.size(); i++) idx[pts[i]] = int32_t(i);
        OrientedChordDiagram s;
        s.base.match.assign(pts.size(), 0);
        s.is_tail.assign(pts.size(), 0);
        for (uint32_t r : chord_rows) {
            uint32_t t = uint32_t(idx[list[r].first]), h = uint32_t(idx[list[r].second]);
            s.base.match[t] = h;
            s.base.match[h] = t;
            s.is_tail[t] = 1;
            s.is_tail[h] = 0;
        }
        return s;
    }
};

// ---------------------------------------------------------------------------
// Subdiagram census (Goussarov-Polyak-Viro style, cf. Sconza-Wildi App. A).
// For each rotation-canonical type of degree-j oriented subdiagram, count the
// j-subsets of chords of D whose restriction has that type. Rotating D
// permutes the j-subsets and rotates each restriction, so the census -- the
// multiset of (canonical type, count) pairs -- is a rotation invariant of D.
// Counts are Z-valued (reducible mod p at will); cost is C(m, j) restrictions.
// Together with the equivariance theorem, every census entry of a structured
// key's diagram is an invariant of the tensor's restricted orbit.
// ---------------------------------------------------------------------------
inline std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
subdiagram_census(const OrientedChordDiagram& D, uint32_t degree) {
    const uint32_t m = D.chords();
    assert(degree >= 1 && degree <= m);
    std::map<std::vector<uint8_t>, uint64_t> acc;
    std::vector<uint32_t> idx(degree);
    for (uint32_t i = 0; i < degree; i++) idx[i] = i;
    for (;;) {
        acc[D.restricted(idx).canonical_bytes()]++;
        // next combination in lexicographic order
        uint32_t i = degree;
        while (i-- > 0) {
            if (idx[i] + (degree - i) < m) {
                idx[i]++;
                for (uint32_t j = i + 1; j < degree; j++) idx[j] = idx[j - 1] + 1;
                break;
            }
            if (i == 0) return {acc.begin(), acc.end()};
        }
    }
}

// 32-byte SHAKE256 digest of the census up to max_degree, suitable for storing
// with a key as a compact rotation-invariant summary.
inline std::vector<uint8_t> census_digest(const OrientedChordDiagram& D,
                                          uint32_t max_degree) {
    Shake256 x;
    x.absorb(std::string("CCTSv1|census"));
    x.absorb_u32(D.chords());
    x.absorb_u32(max_degree);
    for (uint32_t d = 1; d <= max_degree; d++) {
        auto cen = subdiagram_census(D, d);
        x.absorb_u32(d);
        x.absorb_u32(uint32_t(cen.size()));
        for (auto& [type, cnt] : cen) {
            x.absorb(type);
            x.absorb_u32(uint32_t(cnt));
            x.absorb_u32(uint32_t(cnt >> 32));
        }
    }
    x.finalize();
    return x.squeeze(32);
}

// Factor n by trial division (n < 2^32 in prototype range).
inline std::vector<uint32_t> prime_factors(uint32_t n) {
    std::vector<uint32_t> ps;
    for (uint32_t d = 2; uint64_t(d) * d <= n; d++)
        if (n % d == 0) {
            ps.push_back(d);
            while (n % d == 0) n /= d;
        }
    if (n > 1) ps.push_back(n);
    return ps;
}

// Smallest primitive root of F_q (q prime).
inline uint32_t primitive_root(const Field& F) {
    auto ps = prime_factors(F.q - 1);
    for (uint32_t h = 2; h < F.q; h++) {
        bool ok = true;
        for (uint32_t p : ps)
            if (F.pow(h, (F.q - 1) / p) == 1) { ok = false; break; }
        if (ok) return h;
    }
    assert(false && "no primitive root found");
    return 0;
}

// An element of exact multiplicative order n (requires n | q-1). If rng is
// given, a uniformly random such element: g0^u with u uniform coprime to n.
inline uint32_t element_of_order(const Field& F, uint32_t n, Drbg* rng = nullptr) {
    assert((F.q - 1) % n == 0);
    uint32_t g0 = F.pow(primitive_root(F), (F.q - 1) / n);
    if (!rng) return g0;
    uint32_t u;
    do { u = 1 + rng->uniform(n - 1); } while (std::gcd(u, n) != 1);
    return F.pow(g0, u);
}

// Lambda(D, g): rows sorted by tail position; c2[i] = g^{tail_i}, c3[i] = g^{head_i}.
// Requires ord(g) = 2 * chords so that position arithmetic mod 2m matches
// exponent arithmetic (this is what makes rotation act by column scaling).
inline void lambda_from_diagram(const Field& F, const OrientedChordDiagram& D,
                                uint32_t g, Vec& c2, Vec& c3) {
    auto list = D.chord_list();
    c2.clear(); c3.clear();
    c2.reserve(list.size());
    c3.reserve(list.size());
    // Precompute powers g^0 .. g^{2m-1}.
    Vec pw(D.endpoints());
    uint32_t acc = 1;
    for (uint32_t a = 0; a < D.endpoints(); a++) { pw[a] = acc; acc = F.mul(acc, g); }
    for (auto& [t, h] : list) { c2.push_back(pw[t]); c3.push_back(pw[h]); }
}

// ===========================================================================
// Cyclotomic (Z/N-labeled) chord diagrams, after the cyclotomic Drinfeld-Kohno
// formalism (Calaque-Roca i Lucio, Sec. 3.4): each chord carries a label in
// Z/N, and the label group acts by a global shift. Over F_q, fix
//
//   g of exact order 2m  (circle positions),   h of exact order N  (labels),
//
// with gcd(2m, N) = 1 so <g> and <h> intersect trivially, and define
//
//   Lambda(LD, g, h):  c2[i] = g^{tail_i} * h^{lab_i},
//                      c3[i] = g^{head_i} * h^{lab_i}.
//
// DISTINCTNESS LEMMA. Columns are automatically distinct: g^a h^x = g^b h^y
// forces g^{a-b} = h^{y-x} in <g> intersect <h> = {1} (coprime orders), so
// a = b -- and tails (resp. heads) are distinct positions.
//
// EXTENDED EQUIVARIANCE THEOREM (tested exactly in the suite). The product
// group Z/2m x Z/N acts: rotation rho_r shifts positions, sigma_delta shifts
// all labels. For every (r, delta),
//
//   phi<Lambda(rho_r sigma_delta LD, g, h)>
//       = phi<Lambda(LD, g, h)>^{(P, diag(v^j), diag(v^l))},  v = g^{-r} h^{delta},
//
// again a monomial twist inside the weight-preserving restricted isomorphism
// class. Hence every (rotation, label-shift)-invariant of LD -- canonical
// form, product-group orbit size, closure loops, subdiagram census -- is an
// invariant of the tensor's restricted orbit. Labels add m*log2(N) bits of
// key entropy on top of the (2m)!/m! oriented matchings, addressing the
// structured mode's entropy deficit.
// ===========================================================================

struct LabeledChordDiagram {
    OrientedChordDiagram D;
    Vec labels;     // per chord, indexed in chord_list() order (sorted by tail)
    uint32_t N = 0; // label modulus

    uint32_t endpoints() const { return D.endpoints(); }
    uint32_t chords() const { return D.chords(); }

    bool valid() const {
        if (!D.valid() || N < 2) return false;
        if (labels.size() != D.chords()) return false;
        for (auto l : labels) if (l >= N) return false;
        return true;
    }

    // Rotation: positions shift; labels follow their chords through the
    // re-sorting by tail position.
    LabeledChordDiagram rotated(uint32_t r) const {
        LabeledChordDiagram out;
        out.D = D.rotated(r);
        out.N = N;
        const uint32_t m2 = endpoints();
        auto list = D.chord_list();
        std::vector<std::pair<uint32_t, uint32_t>> tl; // (new tail, label)
        tl.reserve(list.size());
        for (uint32_t i = 0; i < list.size(); i++)
            tl.push_back({(list[i].first + m2 - r % m2) % m2, labels[i]});
        std::sort(tl.begin(), tl.end());
        out.labels.reserve(tl.size());
        for (auto& [t, l] : tl) { (void)t; out.labels.push_back(l); }
        return out;
    }

    // Global label shift by delta (the Z/N part of the product action).
    LabeledChordDiagram shifted(uint32_t delta) const {
        LabeledChordDiagram out = *this;
        for (auto& l : out.labels) l = (l + delta) % N;
        return out;
    }

    // Per-endpoint sequence: oriented label-sequence value refined by the
    // chord label. Product-group action = cyclic shift + label translation.
    std::vector<uint32_t> label_sequence() const {
        auto seq = D.label_sequence();
        auto list = D.chord_list();
        std::vector<uint32_t> lab_at(endpoints(), 0);
        for (uint32_t i = 0; i < list.size(); i++)
            lab_at[list[i].first] = lab_at[list[i].second] = labels[i];
        std::vector<uint32_t> out(seq.size());
        for (size_t e = 0; e < seq.size(); e++) out[e] = seq[e] * N + lab_at[e];
        return out;
    }

    // Canonical encoding modulo the product group Z/2m x Z/N, and the
    // stabiliser order within it.
    std::vector<uint32_t> canonical_sequence(uint32_t* stabiliser_out = nullptr) const {
        std::vector<uint32_t> best;
        uint32_t hits = 0;
        for (uint32_t r = 0; r < endpoints(); r++) {
            LabeledChordDiagram Dr = rotated(r);
            for (uint32_t d = 0; d < N; d++) {
                auto seq = Dr.shifted(d).label_sequence();
                if (best.empty() || seq < best) { best = seq; hits = 1; }
                else if (seq == best) hits++;
            }
        }
        if (stabiliser_out) *stabiliser_out = hits;
        return best;
    }

    uint32_t orbit_size() const {
        uint32_t stab = 1;
        canonical_sequence(&stab);
        return endpoints() * N / stab;
    }

    std::vector<uint8_t> canonical_bytes() const {
        auto seq = canonical_sequence();
        std::vector<uint8_t> out;
        out.reserve(2 * seq.size() + 9);
        uint32_t n = chords();
        out.push_back(0x4c); // 'L' domain tag: labeled encoding
        out.push_back(uint8_t(n)); out.push_back(uint8_t(n >> 8));
        out.push_back(uint8_t(n >> 16)); out.push_back(uint8_t(n >> 24));
        out.push_back(uint8_t(N)); out.push_back(uint8_t(N >> 8));
        out.push_back(uint8_t(N >> 16)); out.push_back(uint8_t(N >> 24));
        for (auto s : seq) { out.push_back(uint8_t(s)); out.push_back(uint8_t(s >> 8)); }
        return out;
    }

    uint32_t closure_loops() const { return D.closure_loops(); }

    static LabeledChordDiagram random(uint32_t n_chords, uint32_t N, Drbg& rng) {
        LabeledChordDiagram out;
        out.D = OrientedChordDiagram::random(n_chords, rng);
        out.N = N;
        out.labels.resize(n_chords);
        for (auto& l : out.labels) l = rng.uniform(N);
        return out;
    }
};

// Lambda(LD, g, h): rows sorted by tail; c2[i] = g^{tail_i} h^{lab_i},
// c3[i] = g^{head_i} h^{lab_i}. Requires ord(g) = 2m, ord(h) = N.
inline void lambda_from_labeled_diagram(const Field& F, const LabeledChordDiagram& LD,
                                        uint32_t g, uint32_t h, Vec& c2, Vec& c3) {
    auto list = LD.D.chord_list();
    c2.clear(); c3.clear();
    c2.reserve(list.size());
    c3.reserve(list.size());
    Vec pwg(LD.endpoints()), pwh(LD.N);
    uint32_t acc = 1;
    for (uint32_t a = 0; a < LD.endpoints(); a++) { pwg[a] = acc; acc = F.mul(acc, g); }
    acc = 1;
    for (uint32_t a = 0; a < LD.N; a++) { pwh[a] = acc; acc = F.mul(acc, h); }
    for (uint32_t i = 0; i < list.size(); i++) {
        c2.push_back(F.mul(pwg[list[i].first], pwh[LD.labels[i]]));
        c3.push_back(F.mul(pwg[list[i].second], pwh[LD.labels[i]]));
    }
}

} // namespace ccts
