// Exports algebraic-attack instances for the cryptanalysis experiments:
// the public tensor psi and a hash target y, i.e. exactly what a forger sees.
// The forgery system is: find (u, v, mu != 0) with f_psi(u, v) = mu * y.
//
// usage: export_instance <mode 0|2|3> <k> <seed-string> <outfile>
#include "ccts/scheme.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace ccts;

int main(int argc, char** argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <mode 0|2|3> <k> <seed> <outfile>\n", argv[0]);
        return 2;
    }
    Mode mode = Mode(atoi(argv[1]));
    uint32_t k = uint32_t(atoi(argv[2]));
    std::string seed_s = argv[3];
    Parameters p = mode == Mode::chord_structured ? Parameters::for_k_structured(k)
                 : mode == Mode::chord_labeled    ? Parameters::for_k_labeled(k)
                                                  : Parameters::for_k(k);
    Drbg rng(std::vector<uint8_t>(seed_s.begin(), seed_s.end()));
    KeyPair kp = keygen(p, rng, mode);

    // Forgery target: hash of a fixed message and salt under this public key.
    std::string msg_s = "groebner-experiment-target";
    std::vector<uint8_t> msg(msg_s.begin(), msg_s.end()), salt(SALT_BYTES, 0x42);
    Vec y = hash_to_sphere(p, kp.pk.digest, msg.data(), msg.size(), salt);

    FILE* f = fopen(argv[4], "w");
    if (!f) { perror(argv[4]); return 1; }
    const uint32_t n1 = 2 * k + 1, n23 = k + 1;
    fprintf(f, "%u %u %u\n", p.q, k, uint32_t(mode));
    for (uint32_t i = 0; i < n1; i++)
        for (uint32_t j = 0; j < n23; j++)
            for (uint32_t l = 0; l < n23; l++)
                fprintf(f, "%u ", kp.pk.psi.at(i, j, l));
    fprintf(f, "\n");
    for (uint32_t i = 0; i < n1; i++) fprintf(f, "%u ", y[i]);
    fprintf(f, "\n");
    fclose(f);
    printf("wrote %s (mode=%u k=%u q=%u)\n", argv[4], uint32_t(mode), k, p.q);
    return 0;
}
