#!/usr/bin/env bash
# Emit deterministic build/toolchain metadata as JSON (ci-artifacts/build-metadata.json).
# Every benchmark or test record must be joinable to one of these documents.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-ci-artifacts/build-metadata.json}"
mkdir -p "$(dirname "$OUT")"
CXX="${CXX:-g++}"
CXXFLAGS="${CXXFLAGS:-unset}"
j() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }
cxx_version="$($CXX --version 2>/dev/null | head -1 || echo unknown)"
cxx_path="$(command -v "$CXX" 2>/dev/null || echo unknown)"
cxx_target="$($CXX -dumpmachine 2>/dev/null || echo unknown)"
git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
git_dirty="false"; [ -z "$(git status --porcelain --untracked-files=no 2>/dev/null)" ] || git_dirty="true"
core_dirty="false"; [ -z "$(git status --porcelain --untracked-files=no -- include/ccts 2>/dev/null)" ] || core_dirty="true"
core_tree="$(scripts/core_digest.sh --tree)"
cpu="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
os="$(uname -s 2>/dev/null || echo unknown)"; kernel="$(uname -r 2>/dev/null || echo unknown)"; arch="$(uname -m 2>/dev/null || echo unknown)"
distro="$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || echo unknown)"
cat > "$OUT" <<JSON
{
  "record": "build-metadata",
  "record_version": 1,
  "generated_utc": $(j "$(date -u +%Y-%m-%dT%H:%M:%SZ)"),
  "source": {
    "git_commit": $(j "$git_commit"),
    "git_tree_dirty": $git_dirty,
    "core_tree_dirty_vs_head": $core_dirty,
    "core_tree_digest_sha256": $(j "$core_tree"),
    "manifest": "metadata/knot-implementation.yaml"
  },
  "toolchain": {
    "cxx": $(j "$CXX"),
    "cxx_path": $(j "$cxx_path"),
    "cxx_version": $(j "$cxx_version"),
    "cxx_target": $(j "$cxx_target"),
    "cxxflags": $(j "$CXXFLAGS"),
    "make_version": $(j "$(make --version 2>/dev/null | head -1 || echo unknown)"),
    "python_version": $(j "$(python3 --version 2>/dev/null || echo unknown)")
  },
  "host": {
    "os": $(j "$os"),
    "distro": $(j "$distro"),
    "kernel": $(j "$kernel"),
    "arch": $(j "$arch"),
    "cpu": $(j "$cpu"),
    "cpu_count": $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 0),
    "ci": $(j "${GITHUB_ACTIONS:-false}"),
    "ci_run_id": $(j "${GITHUB_RUN_ID:-}"),
    "ci_runner": $(j "${RUNNER_NAME:-}")
  }
}
JSON
echo "$OUT"
