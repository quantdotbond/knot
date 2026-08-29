#!/usr/bin/env bash
# Assemble release artifacts: reproducible source archive,
# manifest, core digests, KAT corpora, SBOM, build metadata, evidence chain,
# production-readiness report; then SHA-256 and SHA-512 sums over all of them.
# Signing and provenance attestation happen in CI (release workflow, sigstore
# keyless + GitHub artifact attestations); nothing here publishes anything.
#   scripts/release_hashes.sh <version-tag> [ci-artifacts-dir]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
VER="${1:?version tag required, e.g. v0.1.0-rc1}"
ART="${2:-ci-artifacts}"
OUT="$ART/release"
rm -rf "$OUT"; mkdir -p "$OUT"
# Reproducible source archive: git archive is deterministic for a given tree
# (mtime = commit time, sorted entries, fixed owner). Uncommitted changes are
# deliberately excluded - releases come from committed, reviewed revisions.
git archive --format=tar --prefix="knot-$VER/" HEAD | gzip -n -9 > "$OUT/knot-$VER-src.tar.gz"
cp metadata/knot-implementation.yaml "$OUT/knot-$VER-implementation-manifest.yaml"
cp metadata/core-digests.sha256 "$OUT/knot-$VER-core-digests.sha256"
cp vectors/knot-kat-v1.txt "$OUT/knot-$VER-kat-v1.txt"
[ -f "$ART/sbom.cdx.json" ] && cp "$ART/sbom.cdx.json" "$OUT/knot-$VER-sbom.cdx.json"
[ -f "$ART/build-metadata.json" ] && cp "$ART/build-metadata.json" "$OUT/knot-$VER-build-metadata.json"
[ -f "$ART/ci-summary.json" ] && cp "$ART/ci-summary.json" "$OUT/knot-$VER-ci-summary.json"
[ -f "$ART/bench-summary.json" ] && cp "$ART/bench-summary.json" "$OUT/knot-$VER-bench-summary.json"
if [ -d "$ART/evidence" ]; then (cd "$ART/evidence" && tar --sort=name --mtime='1970-01-01' --owner=0 --group=0 --numeric-owner -cf - . ) | gzip -n > "$OUT/knot-$VER-evidence.tar.gz"; fi
(cd "$OUT" && LC_ALL=C sha256sum -- * | LC_ALL=C sort -k2 > SHA256SUMS && LC_ALL=C sha512sum -- $(ls | grep -v SHA256SUMS) | LC_ALL=C sort -k2 > SHA512SUMS)
echo "release artifacts in $OUT:"; ls -1 "$OUT"
