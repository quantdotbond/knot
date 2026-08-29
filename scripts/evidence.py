#!/usr/bin/env python3
"""Normalized, machine-readable verification evidence.

Collects the artifacts of a CI run (ci-artifacts/) into canonical JSON state
records forming a hash chain:

  state_0  source identity        (core tree digest, manifest digest, git commit, spec identity)
  state_1  correctness evidence   (KAT corpus digests, test result digests, parity)
  state_2  security engineering   (sanitizer/fuzz/side-channel/static-analysis result digests)
  state_3  build evidence         (toolchain digest, SBOM digest, benchmark digest)
  state_4  release artifacts      (artifact digests, if present)

Each record carries `prev` = SHA-256 of the canonical encoding of the previous
record, so an external verifier can consume the chain without redesigning CI. Records describe WHAT WAS TESTED AND BUILT; they carry no
security claim. Canonical encoding: JSON, sorted keys, no whitespace, UTF-8.

Usage: scripts/evidence.py [--artifacts ci-artifacts] [--out ci-artifacts/evidence]
"""
import argparse, glob, hashlib, json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def digest_bytes(b):
    return hashlib.sha256(b).hexdigest()

def digest_file(path):
    if not os.path.exists(path):
        return None
    return digest_bytes(open(path, "rb").read())

def digest_tree(paths):
    """Digest of sorted (relpath, sha256) pairs."""
    items = []
    for p in sorted(paths):
        if os.path.isfile(p):
            items.append([os.path.relpath(p, ROOT), digest_file(p)])
    return digest_bytes(canon(items)), len(items)

def load_json(path):
    try:
        return json.load(open(path))
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", default="ci-artifacts")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    os.chdir(ROOT)
    art = a.artifacts
    out = a.out or os.path.join(art, "evidence")
    os.makedirs(out, exist_ok=True)
    meta = load_json(os.path.join(art, "build-metadata.json")) or {}
    summary = load_json(os.path.join(art, "ci-summary.json")) or {}
    core_tree = subprocess.run(["scripts/core_digest.sh", "--tree"], capture_output=True, text=True).stdout.strip()

    def results_by_prefix(prefix):
        d = {}
        for p in sorted(glob.glob(os.path.join(art, "results", prefix + "*.json"))):
            d[os.path.basename(p)] = digest_file(p)
        return d

    chain = []
    def emit(name, body):
        rec = {"record": name, "record_version": 1, "prev": chain[-1]["digest"] if chain else None, **body}
        enc = canon(rec)
        dg = digest_bytes(enc)
        with open(os.path.join(out, name + ".json"), "wb") as f:
            f.write(enc + b"\n")
        chain.append({"record": name, "digest": dg})
        return dg

    emit("state_0_source", {
        "core_tree_digest_sha256": core_tree,
        "core_digest_record_sha256": digest_file("metadata/core-digests.sha256"),
        "manifest_sha256": digest_file("metadata/knot-implementation.yaml"),
        "git_commit": meta.get("source", {}).get("git_commit", "unknown"),
        "git_tree_dirty": meta.get("source", {}).get("git_tree_dirty"),
        "specification": "repository documents; unversioned",
        "assurance_layer_sha256": digest_tree(glob.glob("production/**/*", recursive=True) + glob.glob("scripts/*"))[0],
    })
    kat_v1 = digest_file("vectors/knot-kat-v1.txt")
    emit("state_1_correctness", {
        "kat_corpus": {"vectors/kat.txt": digest_file("vectors/kat.txt"), "vectors/knot-kat-v1.txt": kat_v1,
                       "corpus_version": 1},
        "test_results": results_by_prefix("test-"),
        "parity_results": results_by_prefix("parity-"),
        "check_status": {k: v.get("status") for k, v in summary.get("checks", {}).items()
                         if k.startswith(("test-", "parity-", "kat", "build-"))},
    })
    fuzz_corpus_digest, fuzz_files = digest_tree(glob.glob("production/fuzz/corpus/**/*", recursive=True))
    emit("state_2_security_engineering", {
        "sanitizer_results": results_by_prefix("sanitizer-"),
        "memcheck_results": results_by_prefix("valgrind-"),
        "fuzz_results": results_by_prefix("fuzz-"),
        "fuzz_corpus": {"digest_sha256": fuzz_corpus_digest, "files": fuzz_files},
        "side_channel_results": results_by_prefix("sidechannel-"),
        "static_analysis_results": results_by_prefix("static-"),
        "portability_results": results_by_prefix("cross-"),
        "findings_registry_sha256": digest_file("metadata/findings/findings.json"),
        "check_status": {k: v.get("status") for k, v in summary.get("checks", {}).items()
                         if k.startswith(("sanitizer-", "valgrind-", "fuzz-", "sidechannel-", "static-", "cross-"))},
    })
    emit("state_3_build", {
        "build_metadata_sha256": digest_file(os.path.join(art, "build-metadata.json")),
        "toolchain": meta.get("toolchain", {}),
        "sbom_sha256": digest_file(os.path.join(art, "sbom.cdx.json")),
        "benchmark_sha256": {os.path.basename(p): digest_file(p) for p in sorted(glob.glob(os.path.join(art, "bench*.json")))},
        "reproducibility_sha256": digest_file(os.path.join(art, "results", "build-reproducibility.json")),
    })
    artifacts = {os.path.basename(p): digest_file(p) for p in sorted(glob.glob(os.path.join(art, "release", "*"))) if os.path.isfile(p)}
    emit("state_4_release", {"artifacts": artifacts, "count": len(artifacts)})
    with open(os.path.join(out, "chain.json"), "wb") as f:
        f.write(canon({"record": "evidence-chain", "states": chain, "claim": "describes what was tested and built; no security claim"}) + b"\n")
    for c in chain:
        print(f"{c['digest']}  {c['record']}")

if __name__ == "__main__":
    main()
