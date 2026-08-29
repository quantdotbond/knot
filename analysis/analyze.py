#!/usr/bin/env python3
"""CCTS benchmark analysis.

Reads results/timings.csv and results/sizes.csv, produces:
  results/stats.csv          per-config summary statistics
  results/stats.txt          the same as a markdown table
  results/mode_comparison.csv  Mann-Whitney + Cliff's delta, tensor_reference vs
                               chord_tensor and vs chord_structured
  results/mldsa_comparison.csv size ratios against published FIPS 204 ML-DSA sizes
  results/interp_summary.csv   naive vs fast preimage-sampler medians + crossover
  results/plot_*.png         latency, size, and interpolation-crossover plots

ML-DSA sizes are the published FIPS 204 parameter-set sizes; no ML-DSA build
or timing is performed (per project decision).
"""
import math
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RNG = np.random.default_rng(20260720)

# Published sizes (bytes), NIST FIPS 204 (final, Aug 2024).
MLDSA = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420},
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309},
    "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4627},
}

def bootstrap_median_ci(x, n_boot=2000, alpha=0.05):
    x = np.asarray(x)
    meds = np.median(RNG.choice(x, size=(n_boot, len(x)), replace=True), axis=1)
    return np.quantile(meds, alpha / 2), np.quantile(meds, 1 - alpha / 2)

def mann_whitney_u(x, y):
    """Two-sided Mann-Whitney U with normal approximation and tie correction."""
    x, y = np.asarray(x, float), np.asarray(y, float)
    n1, n2 = len(x), len(y)
    combined = np.concatenate([x, y])
    ranks = pd.Series(combined).rank().to_numpy()
    r1 = ranks[:n1].sum()
    u1 = r1 - n1 * (n1 + 1) / 2
    u = min(u1, n1 * n2 - u1)
    mu = n1 * n2 / 2
    _, counts = np.unique(combined, return_counts=True)
    tie_term = (counts ** 3 - counts).sum()
    n = n1 + n2
    sigma2 = n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1)))
    if sigma2 <= 0:
        return u, 1.0
    z = (u - mu + 0.5) / math.sqrt(sigma2)  # continuity correction
    p = 2 * 0.5 * math.erfc(abs(z) / math.sqrt(2))
    return u, min(p, 1.0)

def cliffs_delta(x, y):
    x, y = np.asarray(x, float), np.asarray(y, float)
    gt = sum((xi > y).sum() for xi in x)
    lt = sum((xi < y).sum() for xi in x)
    return (gt - lt) / (len(x) * len(y))

def main():
    t = pd.read_csv("results/timings.csv")
    sizes = pd.read_csv("results/sizes.csv")
    t["us"] = t["nanoseconds"] / 1000.0

    rows = []
    for (mode, k, q, op), g in t.groupby(["mode", "k", "q", "op"]):
        x = g["us"].to_numpy()
        lo, hi = bootstrap_median_ci(x)
        q1, q3 = np.quantile(x, [0.25, 0.75])
        rows.append({
            "mode": mode, "k": k, "q": q, "op": op, "n": len(x),
            "mean_us": x.mean(), "median_us": np.median(x), "sd_us": x.std(ddof=1),
            "iqr_us": q3 - q1, "p95_us": np.quantile(x, 0.95),
            "median_ci95_lo_us": lo, "median_ci95_hi_us": hi,
        })
    stats = pd.DataFrame(rows).sort_values(["op", "k", "mode"])
    stats.to_csv("results/stats.csv", index=False, float_format="%.2f")
    def to_markdown_table(df, floatfmt=".1f"):
        # Minimal markdown writer (avoids the optional `tabulate` dependency).
        cells = [[f"{v:{floatfmt}}" if isinstance(v, float) else str(v) for v in row]
                 for row in df.itertuples(index=False)]
        widths = [max(len(h), *(len(r[i]) for r in cells)) for i, h in enumerate(df.columns)]
        line = lambda row: "| " + " | ".join(c.rjust(w) for c, w in zip(row, widths)) + " |"
        out = [line(list(df.columns)), "|" + "|".join("-" * (w + 2) for w in widths) + "|"]
        out += [line(r) for r in cells]
        return "\n".join(out)

    with open("results/stats.txt", "w") as f:
        f.write("# CCTS latency statistics (microseconds; toy parameters)\n\n")
        f.write(to_markdown_table(stats))
        f.write("\n")

    # Mode comparison: does the chord layer change performance? (sign & verify)
    # Note: chord_structured uses a different prime q (for_k_structured), so its
    # comparison against tensor_reference is mode+parameter, not mode alone.
    comp_rows = []
    for other in ["chord_tensor", "chord_structured", "chord_labeled"]:
        if other not in t["mode"].unique():
            continue
        for op in ["sign", "verify", "keygen"]:
            for k in sorted(t["k"].unique()):
                a = t[(t["mode"] == "tensor_reference") & (t["k"] == k) & (t["op"] == op)]["us"].to_numpy()
                b = t[(t["mode"] == other) & (t["k"] == k) & (t["op"] == op)]["us"].to_numpy()
                if len(a) == 0 or len(b) == 0:
                    continue
                u, p = mann_whitney_u(a, b)
                comp_rows.append({
                    "mode": other, "op": op, "k": k,
                    "median_ref_us": np.median(a), "median_mode_us": np.median(b),
                    "median_ratio_mode_over_ref": np.median(b) / np.median(a),
                    "mann_whitney_p": p, "cliffs_delta": cliffs_delta(a, b),
                })
    pd.DataFrame(comp_rows).to_csv("results/mode_comparison.csv", index=False, float_format="%.4f")

    # ML-DSA size comparison (published sizes only).
    ml_rows = []
    ref_sizes = sizes[sizes["mode"] == "tensor_reference"]
    for _, r in ref_sizes.iterrows():
        for name, m in MLDSA.items():
            ml_rows.append({
                "ccts_k": r["k"], "mldsa": name,
                "ccts_pk_bytes": r["pk_bytes"], "mldsa_pk_bytes": m["pk"],
                "pk_ratio_ccts_over_mldsa": r["pk_bytes"] / m["pk"],
                "ccts_sig_bytes": r["sig_bytes"], "mldsa_sig_bytes": m["sig"],
                "sig_ratio_ccts_over_mldsa": r["sig_bytes"] / m["sig"],
                "ccts_sk_bytes": r["sk_bytes"], "mldsa_sk_bytes": m["sk"],
                "sk_ratio_ccts_over_mldsa": r["sk_bytes"] / m["sk"],
            })
    pd.DataFrame(ml_rows).to_csv("results/mldsa_comparison.csv", index=False, float_format="%.4f")

    # ---- plots -------------------------------------------------------------
    ks = sorted(t["k"].unique())
    mode_specs = [("tensor_reference", "ref", "#7fb3d5"),
                  ("chord_tensor", "chord", "#f5b041"),
                  ("chord_structured", "struct", "#58d68d"),
                  ("chord_labeled", "label", "#c39bd3")]
    mode_specs = [(m, tag, c) for m, tag, c in mode_specs if m in t["mode"].unique()]
    for op in ["sign", "verify", "keygen"]:
        fig, ax = plt.subplots(figsize=(9, 4.2))
        data, labels, colors = [], [], []
        for k in ks:
            for mode, tag, color in mode_specs:
                data.append(t[(t["mode"] == mode) & (t["k"] == k) & (t["op"] == op)]["us"].to_numpy())
                labels.append(f"k={k}\n{tag}")
                colors.append(color)
        bp = ax.boxplot(data, tick_labels=labels, showfliers=False, patch_artist=True)
        for box, color in zip(bp["boxes"], colors):
            box.set_facecolor(color)
        ax.set_yscale("log")
        ax.set_ylabel("latency (µs, log scale)")
        ax.set_title(f"CCTS {op} latency — toy parameters (not security-matched)")
        fig.tight_layout()
        fig.savefig(f"results/plot_{op}_latency.png", dpi=140)
        plt.close(fig)

    # Size plots vs published ML-DSA sizes.
    for field, fname, title in [
        ("pk_bytes", "plot_public_key_size.png", "Public-key size"),
        ("sig_bytes", "plot_signature_size.png", "Signature size"),
    ]:
        fig, ax = plt.subplots(figsize=(7, 4.2))
        xs = [f"CCTS k={int(r.k)}" for _, r in ref_sizes.iterrows()]
        ys = [r[field] for _, r in ref_sizes.iterrows()]
        xs += list(MLDSA.keys())
        ys += [m["pk" if field == "pk_bytes" else "sig"] for m in MLDSA.values()]
        colors = ["#7fb3d5"] * len(ref_sizes) + ["#58d68d"] * len(MLDSA)
        ax.bar(xs, ys, color=colors)
        ax.set_yscale("log")
        ax.set_ylabel("bytes (log scale)")
        ax.set_title(f"{title}: CCTS (toy params) vs ML-DSA (published FIPS 204 sizes)")
        for x, y in zip(xs, ys):
            ax.text(x, y * 1.08, f"{int(y):,}", ha="center", fontsize=7)
        plt.xticks(rotation=30, ha="right", fontsize=8)
        fig.tight_layout()
        fig.savefig(f"results/{fname}", dpi=140)
        plt.close(fig)

    # ---- interpolation backend crossover (results/interp.csv) --------------
    try:
        it = pd.read_csv("results/interp.csv")
    except FileNotFoundError:
        it = None
        print("results/interp.csv not found; skipping crossover analysis")
    if it is not None:
        it["us"] = it["nanoseconds"] / 1000.0
        med = (it.groupby(["backend", "k"])["us"].median()
                 .unstack(level=0).sort_index())
        med["speedup_naive_over_fast"] = med["naive"] / med["fast"]
        med.to_csv("results/interp_summary.csv", float_format="%.2f")

        # Crossover: smallest benchmarked k from which the fast backend's median
        # wins at every larger size too (a sustained win, not a noise tie).
        crossover = None
        for k in sorted(med.index, reverse=True):
            if med.loc[k, "fast"] < med.loc[k, "naive"]:
                crossover = int(k)
            else:
                break

        fig, ax = plt.subplots(figsize=(7, 4.2))
        ax.plot(med.index, med["naive"], "o-", color="#7fb3d5", label="naive O(k²)")
        ax.plot(med.index, med["fast"], "s-", color="#f5b041",
                label="fast (subproduct trees + NTT)")
        if crossover is not None:
            ax.axvline(crossover, color="grey", linestyle="--", linewidth=1,
                       label=f"fast wins from k={crossover}")
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("k (interpolation size k+1)")
        ax.set_ylabel("vwz_preimage median latency (µs, log)")
        ax.set_title("Preimage sampler: naive vs fast polynomial backend")
        ax.legend()
        fig.tight_layout()
        fig.savefig("results/plot_interp_crossover.png", dpi=140)
        plt.close(fig)

        print("\ninterpolation backend medians (µs):")
        print(med.to_string(float_format=lambda v: f"{v:.1f}"))
        if crossover is not None:
            print(f"fast backend first wins at k={crossover} "
                  f"(set FAST_BACKEND_MIN_K accordingly)")

    print("analysis complete")
    print(stats.to_string(index=False, float_format=lambda v: f"{v:.1f}"))

if __name__ == "__main__":
    main()
