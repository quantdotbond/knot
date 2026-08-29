#!/usr/bin/env python3
"""Benchmark regression detection.

Compares a benchmark summary against a stored baseline for the same host class
and reports per-(parameter set, op) ratios of medians. Policy:
  * sizes (pk/sk/sig bytes) must be IDENTICAL - any change is a hard failure
    (a size change means the serialization or parameters changed);
  * latency: ratio > --warn (default 1.15) -> warning; ratio > --fail
    (default 1.35) -> failure, but ONLY in --mode dedicated (nightly / pinned
    runner). In --mode informational (PRs on shared runners) nothing fails;
    the report is attached as an artifact;
  * stack/heap: > --warn ratio -> warning; heap peak > --fail -> failure in dedicated mode.
Baselines live under bench/baselines/<host-class>.json and are updated
deliberately (scripts/bench_compare.py --update-baseline).

Usage: scripts/bench_compare.py --current ci-artifacts/bench-summary.json --baseline bench/baselines/<class>.json
       [--mode informational|dedicated] [--warn 1.15] [--fail 1.35] [--out ci-artifacts/results/bench-regression.json]
"""
import argparse, json, os, sys

def index(rec):
    return {r["parameter_set"]: r for r in rec.get("results", [])}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--current", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--mode", choices=["informational", "dedicated"], default="informational")
    ap.add_argument("--warn", type=float, default=1.15)
    ap.add_argument("--fail", type=float, default=1.35)
    ap.add_argument("--out", default="ci-artifacts/results/bench-regression.json")
    ap.add_argument("--update-baseline", action="store_true")
    a = ap.parse_args()
    cur = json.load(open(a.current))
    if a.update_baseline or not os.path.exists(a.baseline):
        os.makedirs(os.path.dirname(a.baseline) or ".", exist_ok=True)
        json.dump(cur, open(a.baseline, "w"), indent=1, sort_keys=True)
        print(f"baseline written: {a.baseline}")
        return 0
    base = json.load(open(a.baseline))
    ci, bi = index(cur), index(base)
    rows, warnings, failures = [], [], []
    for name, c in ci.items():
        b = bi.get(name)
        if not b:
            rows.append({"parameter_set": name, "status": "no-baseline"}); continue
        for field in ("public_key", "secret_key", "signature"):
            if c["sizes"][field] != b["sizes"][field]:
                failures.append(f"{name}: {field} size changed {b['sizes'][field]} -> {c['sizes'][field]}")
        for op in ("keygen", "sign", "verify"):
            r = c["ops"][op]["median_ns"] / max(1.0, b["ops"][op]["median_ns"])
            row = {"parameter_set": name, "op": op, "baseline_median_ns": b["ops"][op]["median_ns"],
                   "current_median_ns": c["ops"][op]["median_ns"], "ratio": round(r, 3)}
            if r > a.fail: row["status"] = "regression"; failures.append(f"{name}/{op}: {r:.2f}x slower")
            elif r > a.warn: row["status"] = "warning"; warnings.append(f"{name}/{op}: {r:.2f}x slower")
            elif r < 1 / a.warn: row["status"] = "improvement"
            else: row["status"] = "ok"
            rows.append(row)
            hs = c["heap"][op]["peak_live"] / max(1.0, b["heap"][op]["peak_live"])
            ss = c["stack_bytes"][op] / max(1.0, b["stack_bytes"][op])
            if hs > a.fail: failures.append(f"{name}/{op}: heap peak {hs:.2f}x")
            elif hs > a.warn or ss > a.warn: warnings.append(f"{name}/{op}: heap {hs:.2f}x stack {ss:.2f}x")
    same_host = cur.get("environment", {}).get("cpu") == base.get("environment", {}).get("cpu")
    status = "pass"
    if failures and a.mode == "dedicated": status = "fail"
    elif failures or warnings: status = "warning"
    rep = {"record": "bench-regression", "mode": a.mode, "status": status, "same_cpu_as_baseline": same_host,
           "baseline_commit": base.get("environment", {}).get("commit"), "current_commit": cur.get("environment", {}).get("commit"),
           "thresholds": {"warn": a.warn, "fail": a.fail}, "warnings": warnings, "failures": failures, "rows": rows,
           "note": "informational mode never fails; dedicated mode fails on size changes and > fail-ratio regressions"}
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    for w in warnings: print("WARN", w)
    for f in failures: print("FAIL" if a.mode == "dedicated" else "INFO", f)
    print(f"bench_compare: {status} ({len(rows)} rows, same CPU as baseline: {same_host})")
    return 1 if status == "fail" else 0

if __name__ == "__main__":
    sys.exit(main())
