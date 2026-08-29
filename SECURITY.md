# Security policy

KNOT (code name CCTS) is a **research prototype** of a post-quantum signature
scheme. It is not standardized, not externally audited, not side-channel
hardened, and uses toy parameters. It must not be used to protect anything.
The machine-readable registry of known implementation findings is
`metadata/findings/findings.json`.

## Reporting a vulnerability

Please report security-relevant defects **privately** rather than in a public

Include: affected core identity (`scripts/core_digest.sh --tree`), platform,
compiler and version, a reproduction (input bytes or seed label and command),
expected and observed behaviour. Deterministic test seeds
(`TestOnlyDeterministicRng` labels) are welcome; never send private key material.

You should receive an acknowledgement within 7 days. Because this is a
research project there is no formal SLA for fixes; findings against the
cryptographic core are recorded in `metadata/findings/findings.json` with
reproduction inputs persisted in `production/fuzz/corpus/*/regressions/`.

## Scope

In scope: memory-safety defects, malformed-input handling, deviations from the
documented scheme behaviour, side-channel observations, build/supply-chain
issues in this repository.

Out of scope: cryptanalysis of the underlying tensor-isomorphism assumptions
(welcome as research discussion, but not a "vulnerability" of this
implementation), and any use of this code in production.

## Supported versions

There are no supported release versions. Only the current `master`/`main`
revision is evaluated by CI.

## Secrets

No production key material, entropy, signing keys or credentials are or may
be committed. Deterministic seeds under `vectors/` and `production/` are
explicitly non-secret test material.
