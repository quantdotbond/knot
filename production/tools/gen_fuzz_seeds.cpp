// Writes seed corpora for the fuzz targets: valid encodings at several
// parameter sets, minimal valid and minimal invalid encodings, boundary
// lengths. Output directory: production/fuzz/corpus/<target>/seeds/.
#include "knot_adapter.hpp"
#include "deterministic_test_rng.hpp"
#include "test_util.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>

using namespace ccts;
using namespace knot_test;
using namespace knot_adapter;
namespace fs = std::filesystem;

static void put(const fs::path& dir, const std::string& name, const std::vector<uint8_t>& b) {
    fs::create_directories(dir);
    std::ofstream(dir / name, std::ios::binary).write(reinterpret_cast<const char*>(b.data()), long(b.size()));
}

int main(int argc, char** argv) {
    fs::path root = argc > 1 ? argv[1] : "production/fuzz/corpus";
    int n = 0;
    for (const ParamSet& ps : ci_parameter_sets()) {
        if (ps.k > 8) continue; // keep seeds small
        std::string tag = std::string(mode_name(ps.mode)) + "_k" + std::to_string(ps.k);
        Parameters p = make_params(ps);
        Drbg rng = TestOnlyDeterministicRng::from_label("fuzz-seed|" + tag);
        KeyPair kp = keygen(ps, rng);
        auto msg = bytes_of("fuzz seed message");
        Signature s = sign(msg, kp.sk, rng);
        auto pkb = kp.pk.serialize();
        put(root / "fuzz_pk_adapter" / "seeds", tag + ".pk", pkb); n++;
        put(root / "fuzz_pk_raw" / "seeds", tag + ".pk", pkb); n++;
        // truncated pk (minimal invalid)
        put(root / "fuzz_pk_adapter" / "seeds", tag + ".pk.trunc", std::vector<uint8_t>(pkb.begin(), pkb.begin() + 20));
        put(root / "fuzz_pk_raw" / "seeds", tag + ".pk.trunc", std::vector<uint8_t>(pkb.begin(), pkb.begin() + 20));
        auto dense = s.serialize();
        put(root / "fuzz_sig_dense_adapter" / "seeds", tag + ".sig", dense); n++;
        // (message || signature) for the verify fuzzer: 2-byte length prefix for the message
        std::vector<uint8_t> mv = {uint8_t(msg.size()), uint8_t(msg.size() >> 8)};
        mv.insert(mv.end(), msg.begin(), msg.end());
        auto wire = signature_to_bytes(s, p, ps.mode);
        mv.insert(mv.end(), wire.begin(), wire.end());
        put(root / "fuzz_verify" / "seeds", tag + ".msgsig", mv); n++;
        if (ps.mode == Mode::tri_chord) {
            auto packed = serialize_signature_packed(s, p);
            put(root / "fuzz_sig_packed_adapter" / "seeds", tag + ".psig", packed); n++;
            put(root / "fuzz_sig_packed_raw" / "seeds", tag + ".psig", packed); n++;
        }
        put(root / "fuzz_sign_verify" / "seeds", tag + ".msg", msg); n++;
    }
    // Serialization primitive seeds: (q lo, q hi, n, values...)
    put(root / "fuzz_radix" / "seeds", "q103_n4", {103, 0, 4, 1, 2, 3, 4});
    put(root / "fuzz_radix" / "seeds", "q65521_n9", {0xf1, 0xff, 9, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7});
    put(root / "fuzz_radix" / "seeds", "empty", {});
    // Chord diagram seeds: match arrays of small valid diagrams
    put(root / "fuzz_chord" / "seeds", "cross4", {2, 3, 0, 1, 1, 1, 0, 0});
    put(root / "fuzz_chord" / "seeds", "nested4", {1, 0, 3, 2, 1, 0, 1, 0});
    put(root / "fuzz_chord" / "seeds", "invalid", {0, 0, 0, 0});
    // Backend parity seeds: (k, coin, bytes...)
    put(root / "fuzz_backend_parity" / "seeds", "k4", {4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
    put(root / "fuzz_backend_parity" / "seeds", "k9", {9, 1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 22, 33, 44, 55});
    std::printf("wrote %d primary seeds under %s\n", n, root.c_str());
    return 0;
}
