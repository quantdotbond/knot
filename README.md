# KNOT

A hash-and-sign signature whose trapdoor is a **non-degenerate tensor**, not a
lattice. It has a chord-diagram-structured trapdoor and a restricted public key.

> Alpha version (0.1v). Test parameters. Not constant-time.

## Structure

* **Sign:** hash $(pk, m, \mathrm{salt})$ to a weight-$(k+1)$ projective target, undo $X_1$, interpolate a preimage, then undo $X_2, X_3$.
* **Verify:** $\mathrm{projectivize}(f_{\psi}(u,v)) = \text{hash target}$.
* **TRI mode:** publish only $t = k+1+m$ tensor slices, each as a rank-one factor pair. $\Theta(k^2)$ key bytes instead of the expected $\Theta(k^3)$.

## Numbers (measured, k = 32; alpha parameters)

| | pk | sk | sig | keygen | sign | verify |
|---|---|---|---|---|---|---|
| dense (`tensor_reference`) | 141 590 B | 4 879 B | 160 B | 32 ms | 85 µs | 487 µs |
| `tri_chord` | 2 556 B | 5 284 B | 83 B | 5 ms | 82 µs | 25 µs |

Projection at k = 256: TRI pk around 271 kB, signature 731 B.

## Use

```cpp
#include "ccts/scheme.hpp"
using namespace ccts;
Parameters p = Parameters::for_k_tri(8);
Drbg rng(std::vector<uint8_t>{'s','e','e','d'});   // test only; production overloads use std::random_device
KeyPair kp = keygen(p, rng, Mode::tri_chord);
Signature s = sign(msg, kp.sk, rng);
bool ok = verify(msg, s, kp.pk);
```

```
make test     # 3480 checks
make ci       # full assurance gate: KATs, sanitizers, Valgrind, fuzzing, static analysis,
              # side-channel harnesses, cross-arch, SBOM, evidence chain
```

## Milestones

- [x] 0–2 Baseline CI, immutable core identity, KATs, round-trip/negative tests, backend and encoding parity
- [x] 3–4 Side-channel harnesses (Valgrind secret tracking, dudect), fuzzing with regression corpora
- [x] 5–7 Benchmarks with environment metadata, regression policy, supported build matrix
- [x] 8–10 Release/provenance workflow, hash-chained evidence records, production-readiness report

To do:

- [ ] Close core input-validation findings: bounds-checked `ByteReader`, validated `PublicKey::deserialize` (KNOT-CORE-002, -005, -009)
- [ ] Endian-independent SHAKE256 lane access (KNOT-CORE-008)
- [ ] Portable 64×64→128 multiplication in the NTT for 32-bit and MSVC (KNOT-CORE-001)
- [ ] Canonical-encoding enforcement in the core verifier and packed parser (KNOT-CORE-003, -004)
- [ ] Constant-time sampler, field arithmetic and permutation application; re-run ctgrind/dudect until clean (KNOT-CORE-007)
- [ ] Strict-diagnostic-clean core (KNOT-CORE-006)
- [ ] MemorySanitizer with an instrumented libc++
- [ ] Native ARM64 / macOS / Windows results from hosted CI (currently unvalidated)
- [ ] Dedicated benchmark runner and nightly 20 000-sample timing evaluation
- [ ] OSS-Fuzz integration
- [ ] Versioned specification document and named parameter sets with a security-level argument
- [ ] LICENSE file; first tagged, signed, attested release
- [ ] External review / audit
- [ ] milagro-pqc / post-quantum TLS integration
- [ ] Deployed-protocol benchmarking
- [ ] EVA/Nova-style IVC provenance over the evidence chain
