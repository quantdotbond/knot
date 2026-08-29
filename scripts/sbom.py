#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM for the KNOT repository.

The KNOT core is a header-only C++20 library with no third-party C/C++
dependencies; the SBOM therefore records (a) the project component with its
core tree digest, (b) the build toolchain actually used, and (c) the optional
Python analysis dependencies with the versions installed. It is generated, not
maintained by hand. If `syft` is available it is run as well and its output is
kept alongside as an independent inventory (ci-artifacts/sbom-syft.json).

Usage: scripts/sbom.py [--out ci-artifacts/sbom.cdx.json] [--build-meta ci-artifacts/build-metadata.json]
"""
import argparse, datetime, hashlib, json, os, subprocess, sys, uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()
    except OSError:
        return ""

def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

def python_component(name):
    try:
        mod = __import__(name)
        ver = getattr(mod, "__version__", "unknown")
    except Exception:
        return None
    return {"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{name}@{ver}",
            "scope": "optional", "description": "analysis/plotting only (analysis/analyze.py); not part of the library"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="ci-artifacts/sbom.cdx.json")
    ap.add_argument("--build-meta", default="ci-artifacts/build-metadata.json")
    a = ap.parse_args()
    os.chdir(ROOT)
    meta = {}
    if os.path.exists(a.build_meta):
        meta = json.load(open(a.build_meta))
    core_tree = sh(["scripts/core_digest.sh", "--tree"])
    commit = meta.get("source", {}).get("git_commit") or sh(["git", "rev-parse", "HEAD"]) or "unknown"
    core_files = sorted(os.path.join("include/ccts", f) for f in os.listdir("include/ccts") if f.endswith(".hpp"))
    components = []
    for f in core_files:
        components.append({"type": "file", "name": f, "hashes": [{"alg": "SHA-256", "content": file_hash(f)}],
                           "group": "knot-core"})
    tc = meta.get("toolchain", {})
    if tc.get("cxx_version"):
        components.append({"type": "application", "name": tc.get("cxx", "c++"), "version": tc["cxx_version"],
                           "description": "C++ compiler used for the evaluated build", "scope": "required",
                           "properties": [{"name": "knot:cxx_target", "value": tc.get("cxx_target", "unknown")},
                                          {"name": "knot:cxxflags", "value": tc.get("cxxflags", "unknown")}]})
    if tc.get("make_version"):
        components.append({"type": "application", "name": "make", "version": tc["make_version"], "scope": "required"})
    if tc.get("python_version"):
        components.append({"type": "application", "name": "python3", "version": tc["python_version"], "scope": "optional",
                           "description": "scripts/ and analysis/ only"})
    for name in ("numpy", "pandas", "matplotlib", "yaml"):
        c = python_component(name)
        if c: components.append(c)
    if os.environ.get("KNOT_TOOLCHAIN_PINNED"):
        components.append({"type": "platform", "name": "auxiliary-toolchain", "version": os.environ["KNOT_TOOLCHAIN_PINNED"],
                           "description": "pinned nixpkgs revision providing clang/valgrind/clang-tidy/cppcheck/qemu/cross-gcc (scripts/toolchain-env.sh)"})
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"name": "scripts/sbom.py", "version": "1"}],
            "component": {"type": "library", "name": "knot", "version": commit,
                          "description": "KNOT (CCTS) post-quantum signature research implementation; header-only C++20",
                          "hashes": [{"alg": "SHA-256", "content": core_tree}],
                          "properties": [{"name": "knot:core_tree_digest_sha256", "value": core_tree},
                                         {"name": "knot:manifest", "value": "metadata/knot-implementation.yaml"},
                                         {"name": "knot:third_party_cxx_dependencies", "value": "none"},
                                         {"name": "knot:license", "value": "unknown (no LICENSE file)"}]},
        },
        "components": components,
        "dependencies": [{"ref": "knot", "dependsOn": []}],
    }
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(bom, f, indent=2, sort_keys=True)
    print(a.out)
    syft = sh(["sh", "-c", "command -v syft"])
    if syft:
        out2 = os.path.join(os.path.dirname(a.out) or ".", "sbom-syft.cdx.json")
        r = subprocess.run([syft, "scan", "dir:.", "-o", f"cyclonedx-json={out2}", "-q"], capture_output=True, text=True)
        print(out2 if r.returncode == 0 else f"syft failed: {r.stderr.strip()[:200]}")

if __name__ == "__main__":
    main()
