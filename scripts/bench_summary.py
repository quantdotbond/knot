#!/usr/bin/env python3
"""Merge the micro-benchmark record with the build/host metadata and emit the
canonical benchmark artifact (ci-artifacts/bench-summary.json) plus a Markdown
table. A benchmark record without environment metadata is refused.

Usage: scripts/bench_summary.py --bench ci-artifacts/bench-raw.json --meta ci-artifacts/build-metadata.json
                               [--out ci-artifacts/bench-summary.json] [--table ci-artifacts/bench-summary.txt]
"""
import argparse, json, os, sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--out", default="ci-artifacts/bench-summary.json")
    ap.add_argument("--table", default="ci-artifacts/bench-summary.txt")
    ap.add_argument("--flags", default=os.environ.get("KNOT_BENCH_FLAGS", "unknown"))
    a = ap.parse_args()
    bench = json.load(open(a.bench))
    meta = json.load(open(a.meta))
    for key in ("toolchain", "host", "source"):
        if key not in meta:
            sys.exit(f"bench_summary: build metadata lacks '{key}'; refusing to emit a benchmark record")
    rec = {
        "record": "benchmark-summary", "record_version": 1,
        "kind": "microbenchmark",  # protocol/application benchmarks are out of scope here
        "environment": {
            "cpu": meta["host"].get("cpu"), "arch": meta["host"].get("arch"), "os": meta["host"].get("os"),
            "distro": meta["host"].get("distro"), "kernel": meta["host"].get("kernel"),
            "compiler": meta["toolchain"].get("cxx_version"), "optimization_flags": a.flags,
            "commit": meta["source"].get("git_commit"), "core_tree_digest_sha256": meta["source"].get("core_tree_digest_sha256"),
            "ci": meta["host"].get("ci"), "ci_run_id": meta["host"].get("ci_run_id"),
        },
        "samples": bench.get("samples"), "cycle_source": bench.get("cycle_source"),
        "results": bench.get("results", []),
    }
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rec, open(a.out, "w"), indent=1, sort_keys=True)
    with open(a.table, "w") as f:
        e = rec["environment"]
        f.write(f"# KNOT micro-benchmark\n\nCPU: {e['cpu']} | {e['arch']} | {e['os']} {e['kernel']} | {e['compiler']} | flags `{e['optimization_flags']}` | commit `{e['commit']}`\n\n")
        f.write("Toy parameters; no security level. Latencies in microseconds (median / p95 / p99), cycles = median.\n\n")
        f.write("| parameter set | q | pk B | sk B | sig B | keygen us (p95/p99) | sign us (p95/p99) | verify us (p95/p99) | sign cycles | stack sign B | heap sign B |\n|---|---|---|---|---|---|---|---|---|---|---|\n")
        for r in rec["results"]:
            o = r["ops"]; s = r["sizes"]
            fmt = lambda x: f"{x['median_ns']/1e3:.1f} ({x['p95_ns']/1e3:.1f}/{x['p99_ns']/1e3:.1f})"
            f.write(f"| {r['parameter_set']} | {r['q']} | {s['public_key']} | {s['secret_key']} | {s['signature']} | {fmt(o['keygen'])} | {fmt(o['sign'])} | {fmt(o['verify'])} | {o['sign']['median_cycles']} | {r['stack_bytes']['sign']} | {r['heap']['sign']['peak_live']} |\n")
    print(a.out)

if __name__ == "__main__":
    main()
