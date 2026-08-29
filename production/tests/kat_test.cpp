// KNOT known-answer tests.
//
// Two corpora are checked byte-for-byte:
//   vectors/kat.txt          the repository's original corpus (tests/gen_vectors.cpp)
//   vectors/knot-kat-v1.txt  the versioned production corpus (production/tools/gen_kat.cpp)
// Both are reproduced through the deterministic test RNG adapter with the
// exact DRBG usage the generators used. Any byte difference fails.
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <fstream>
#include <map>
#include <sstream>

using namespace ccts;
using namespace knot_test;
using namespace knot_adapter;

using Record = std::map<std::string, std::string>;

static std::vector<Record> parse(const std::string& path, bool& ok) {
    std::ifstream in(path);
    ok = bool(in);
    std::vector<Record> recs;
    Record cur;
    std::string line;
    auto flush = [&] { if (cur.count("mode")) recs.push_back(cur); cur.clear(); };
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') { if (line.empty()) flush(); continue; }
        if (line == "[vector]") { flush(); continue; }
        auto eq = line.find(" = ");
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 3);
        if (v.size() >= 2 && v.front() == '"' && v.back() == '"') v = v.substr(1, v.size() - 2);
        cur[k] = v;
    }
    flush();
    return recs;
}

static Vec parse_vec(const std::string& s) {
    Vec v; std::istringstream ss(s); uint32_t x;
    while (ss >> x) v.push_back(x);
    return v;
}

// vectors/kat.txt: Drbg(seed) -> keygen -> sign(message)
static void check_original_corpus() {
    bool ok;
    auto recs = parse("vectors/kat.txt", ok);
    KCHECK(ok, "vectors/kat.txt readable");
    KCHECK(recs.size() == 10, "vectors/kat.txt has 10 vectors");
    for (auto& r : recs) {
        std::string name = r["mode"] + "/k=" + r["k"];
        auto mode = mode_from_name(r["mode"]);
        KCHECK(mode.has_value(), (name + ": known mode").c_str());
        if (!mode) continue;
        ParamSet ps{*mode, uint32_t(std::stoul(r["k"]))};
        Parameters p = make_params(ps);
        KCHECK(p.q == std::stoul(r["q"]), (name + ": q matches").c_str());
        Drbg rng = TestOnlyDeterministicRng::from_label(r["seed"]);
        KeyPair kp = keygen(ps, rng);
        KCHECK(hex(kp.pk.digest) == r["pk_digest"], (name + ": pk_digest").c_str());
        KCHECK(kp.pk.serialize().size() == std::stoul(r["pk_bytes"]), (name + ": pk_bytes").c_str());
        KCHECK(kp.sk.serialize().size() == std::stoul(r["sk_bytes"]), (name + ": sk_bytes").c_str());
        auto msg = bytes_of(r["message"]);
        Signature s = sign(msg, kp.sk, rng);
        KCHECK(hex(s.salt) == r["salt"], (name + ": salt").c_str());
        KCHECK(s.u == parse_vec(r["u"]), (name + ": u").c_str());
        KCHECK(s.v == parse_vec(r["v"]), (name + ": v").c_str());
        KCHECK(hex(s.serialize()) == r["signature_hex"], (name + ": signature_hex").c_str());
        KCHECK(verify(msg, s, kp.pk) == (r["verifies"] == "true"), (name + ": verifies").c_str());
        if (r.count("signature_packed_hex"))
            KCHECK(hex(serialize_signature_packed(s, p)) == r["signature_packed_hex"],
                   (name + ": signature_packed_hex").c_str());
    }
}

// vectors/knot-kat-v1.txt: Drbg(seed) -> keygen -> sign(msg1) -> sign(msg2)
static void check_versioned_corpus() {
    bool ok;
    auto recs = parse("vectors/knot-kat-v1.txt", ok);
    KCHECK(ok, "vectors/knot-kat-v1.txt readable");
    KCHECK(recs.size() == ci_parameter_sets().size(), "knot-kat-v1 covers every CI parameter set");
    for (auto& r : recs) {
        std::string name = r["name"];
        auto mode = mode_from_name(r["mode"]);
        KCHECK(mode.has_value(), (name + ": known mode").c_str());
        if (!mode) continue;
        ParamSet ps{*mode, uint32_t(std::stoul(r["k"]))};
        Parameters p = make_params(ps);
        KCHECK(p.q == std::stoul(r["q"]), (name + ": q").c_str());
        if (r.count("tri_t")) KCHECK(p.sup.t == std::stoul(r["tri_t"]) && p.sup.w == std::stoul(r["tri_w"]),
                                     (name + ": tri (t, w)").c_str());
        if (r.count("label_N")) KCHECK(p.label_N == std::stoul(r["label_N"]), (name + ": label_N").c_str());
        Drbg rng = TestOnlyDeterministicRng::from_label(r["seed"]);
        KeyPair kp = keygen(ps, rng);
        KCHECK(hex(kp.pk.digest) == r["pk_digest"], (name + ": pk_digest").c_str());
        KCHECK(hex(kp.pk.serialize()) == r["pk_hex"], (name + ": pk bytes").c_str());
        KCHECK(hex(kp.sk.serialize()) == r["sk_hex"], (name + ": sk bytes").c_str());
        std::vector<uint8_t> m1, m2;
        KCHECK(unhex(r["message_hex"], m1) && unhex(r["message2_hex"], m2), (name + ": messages").c_str());
        Signature s1 = sign(m1, kp.sk, rng);
        Signature s2 = sign(m2, kp.sk, rng);
        KCHECK(hex(signature_to_bytes(s1, p, ps.mode)) == r["sig_hex"], (name + ": sig bytes").c_str());
        KCHECK(hex(signature_to_bytes(s2, p, ps.mode)) == r["sig2_hex"], (name + ": sig2 bytes").c_str());
        KCHECK(verify(m1, s1, kp.pk) && verify(m2, s2, kp.pk), (name + ": verifies").c_str());
        // The recorded encodings must also verify when parsed back from bytes
        // by the adapter against the recorded public key bytes.
        std::vector<uint8_t> pkb, sb;
        unhex(r["pk_hex"], pkb); unhex(r["sig_hex"], sb);
        auto pk = public_key_from_bytes(pkb);
        KCHECK(pk && verify_bytes(m1, sb, *pk, ps.mode), (name + ": recorded bytes verify").c_str());
    }
}

int main() {
    check_original_corpus();
    check_versioned_corpus();
    return finish("kat");
}
