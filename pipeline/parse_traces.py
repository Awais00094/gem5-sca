#!/usr/bin/env python3
"""
Stage 3: turn each run's gem5 stats.txt (one block per interval) + its
SECRET/IDX ground-truth line into ONE feature row.

For every run we build:
  * aggregate features  -> sum/mean/std/max/last of each selected counter
                           over the interval series (the PROOFS-style view)
  * temporal features   -> for key counter series: slope, spectral-flatness
                           entropy, lag-1 autocorrelation, burstiness, and
                           the per-interval miss-rate dynamics (the NEW view)
  * ground truth        -> secret, idx (for Stage-4 leakage), and label

Output: data/features.parquet  (one row per run)
Also writes results/stat_names.txt (union of stat names in the first run),
so the exact counter picks can be tuned to your gem5 build.

Usage:
    python pipeline/parse_traces.py --config configs/config.yaml
    python pipeline/parse_traces.py --config configs/config.yaml --raw-dir data/raw
"""
import argparse
import glob
import os
import re
import sys
import numpy as np
import pandas as pd
import yaml

# Semantic counters -> ordered list of candidate gem5 stat names.
# The first name present in a run is used; names vary across gem5 versions,
# so several spellings are tried. Unmatched counters become NaN.
SEMANTIC = {
    "cycles":        ["system.cpu.numCycles", "system.switch_cpus.numCycles"],
    "insts":         ["system.cpu.commitStats0.numInsts",
                      "system.cpu.committedInsts", "simInsts"],
    "ops":           ["system.cpu.commitStats0.numOps", "simOps"],
    "branches":      ["system.cpu.commitStats0.numBranches",
                      "system.cpu.branchPred.lookups",
                      "system.cpu.branchPred.condPredicted"],
    "branch_misp":   ["system.cpu.branchPred.condIncorrect",
                      "system.cpu.branchPred.mispredicted",
                      "system.cpu.commit.branchMispredicts"],
    "l1d_hits":      ["system.cpu.dcache.overallHits::total",
                      "system.cpu.dcache.demandHits::total"],
    "l1d_misses":    ["system.cpu.dcache.overallMisses::total",
                      "system.cpu.dcache.demandMisses::total"],
    "l1i_misses":    ["system.cpu.icache.overallMisses::total",
                      "system.cpu.icache.demandMisses::total"],
    "l2_hits":       ["system.l2cache.overallHits::total",
                      "system.l2cache.demandHits::total"],
    "l2_misses":     ["system.l2cache.overallMisses::total",
                      "system.l2cache.demandMisses::total"],
    "l2_accesses":   ["system.l2cache.overallAccesses::total",
                      "system.l2cache.demandAccesses::total"],
    "mem_reads":     ["system.mem_ctrl.dram.numReads::total",
                      "system.mem_ctrl.readReqs"],
    "mem_writes":    ["system.mem_ctrl.dram.numWrites::total",
                      "system.mem_ctrl.writeReqs"],
    "rob_stalls":    ["system.cpu.rename.ROBFullEvents",
                      "system.cpu.commit.commitSquashedInsts"],
}

# Which series get full temporal features (the expensive, informative ones).
TEMPORAL_KEYS = ["l1d_misses", "l2_misses", "branch_misp", "mem_reads", "insts"]

BLOCK_SEP = "Begin Simulation Statistics"
LINE_RE = re.compile(r"^(\S+)\s+([-\d.einfa]+)")


def parse_stats_blocks(path):
    """Return list of dicts, one per interval block: {stat_name: float}."""
    blocks, cur = [], None
    with open(path, errors="ignore") as f:
        for line in f:
            if BLOCK_SEP in line:
                if cur is not None:
                    blocks.append(cur)
                cur = {}
                continue
            if cur is None:
                continue
            m = LINE_RE.match(line)
            if not m:
                continue
            name, val = m.group(1), m.group(2)
            try:
                cur[name] = float(val)
            except ValueError:
                pass
    if cur:
        blocks.append(cur)
    return blocks


def pick(series_df, candidates):
    for c in candidates:
        if c in series_df.columns:
            return series_df[c].to_numpy(dtype=float)
    return None


def temporal_features(x):
    """Temporal descriptors of one counter's per-interval series."""
    x = np.asarray(x, dtype=float)
    n = len(x)
    if n == 0 or np.all(np.isnan(x)):
        return {k: np.nan for k in
                ["slope", "ac1", "burst", "spec_flat", "ent", "cv"]}
    x = np.nan_to_num(x)
    # de-trended diffs give per-interval deltas (counters may be cumulative
    # within an interval but reset across intervals, so use the raw series)
    t = np.arange(n)
    slope = np.polyfit(t, x, 1)[0] if n > 1 and np.ptp(x) > 0 else 0.0
    # lag-1 autocorrelation
    if n > 1 and np.std(x) > 0:
        ac1 = np.corrcoef(x[:-1], x[1:])[0, 1]
    else:
        ac1 = 0.0
    mu = np.mean(x)
    sd = np.std(x)
    cv = sd / mu if mu != 0 else 0.0
    burst = np.max(x) / mu if mu != 0 else 0.0          # peak-to-mean
    # spectral flatness of the series (tonal vs noisy periodicity)
    sp = np.abs(np.fft.rfft(x - mu)) ** 2
    sp = sp[1:]
    if sp.size and np.all(sp >= 0) and np.sum(sp) > 0:
        gm = np.exp(np.mean(np.log(sp + 1e-12)))
        spec_flat = gm / (np.mean(sp) + 1e-12)
    else:
        spec_flat = np.nan
    # Shannon entropy of the normalised series (distribution over intervals)
    p = x - np.min(x)
    s = np.sum(p)
    if s > 0:
        p = p / s
        ent = -np.sum(p[p > 0] * np.log2(p[p > 0]))
    else:
        ent = 0.0
    return {"slope": slope, "ac1": ac1, "burst": burst,
            "spec_flat": spec_flat, "ent": ent, "cv": cv}


def read_ground_truth(run_dir):
    """Find SECRET=.. IDX=.. in gem5 stdout/log files."""
    for fn in ("simout", "gem5.log", "simout.txt"):
        p = os.path.join(run_dir, fn)
        if os.path.exists(p):
            txt = open(p, errors="ignore").read()
            m = re.search(r"SECRET=(\d+)\s+IDX=(\d+)", txt)
            if m:
                return int(m.group(1)), int(m.group(2))
    return np.nan, np.nan


def label_map(cfg):
    m = {}
    for wl in cfg["workloads"]:
        m[wl["name"]] = wl["label"]
    return m


def process_run(run_dir, labels, dump_names=False):
    stats_path = os.path.join(run_dir, "stats.txt")
    if not os.path.exists(stats_path):
        return None
    blocks = parse_stats_blocks(stats_path)
    if not blocks:
        return None
    sdf = pd.DataFrame(blocks)
    if dump_names:
        os.makedirs("results", exist_ok=True)
        with open("results/stat_names.txt", "w") as f:
            f.write("\n".join(sorted(sdf.columns)))

    # resolve semantic series
    series = {k: pick(sdf, cands) for k, cands in SEMANTIC.items()}

    # gem5 L2 emits no overallHits -> derive hits = accesses - misses
    if series.get("l2_hits") is None and series.get("l2_accesses") is not None \
            and series.get("l2_misses") is not None:
        import numpy as _np
        series["l2_hits"] = _np.maximum(
            _np.nan_to_num(series["l2_accesses"]) -
            _np.nan_to_num(series["l2_misses"]), 0.0)

    row = {}
    # aggregate features
    for k, x in series.items():
        if x is None:
            for agg in ("sum", "mean", "std", "max", "last"):
                row[f"{k}_{agg}"] = np.nan
            continue
        x = np.nan_to_num(np.asarray(x, dtype=float))
        row[f"{k}_sum"] = np.sum(x)
        row[f"{k}_mean"] = np.mean(x)
        row[f"{k}_std"] = np.std(x)
        row[f"{k}_max"] = np.max(x)
        row[f"{k}_last"] = x[-1]
    # derived ratios
    with np.errstate(divide="ignore", invalid="ignore"):
        row["l1d_miss_rate"] = np.nan_to_num(
            row.get("l1d_misses_sum", np.nan) /
            (row.get("l1d_hits_sum", 0) + row.get("l1d_misses_sum", 0) + 1e-9))
        row["l2_miss_rate"] = np.nan_to_num(
            row.get("l2_misses_sum", np.nan) /
            (row.get("l2_accesses_sum", 0) + 1e-9))
        row["mpki"] = np.nan_to_num(
            1000.0 * row.get("l2_misses_sum", 0) /
            (row.get("insts_sum", 0) + 1e-9))
    # temporal features
    for k in TEMPORAL_KEYS:
        tf = temporal_features(series[k]) if series[k] is not None else \
             {kk: np.nan for kk in ["slope","ac1","burst","spec_flat","ent","cv"]}
        for name, v in tf.items():
            row[f"{k}_{name}"] = v

    # meta + ground truth
    base = os.path.basename(run_dir)
    m = re.match(r"(.+)_(small|large)_s(\d+)$", base)
    wl_name = m.group(1) if m else base
    row["workload"] = wl_name
    row["memcfg"] = m.group(2) if m else "na"
    row["seed"] = int(m.group(3)) if m else -1
    row["label"] = labels.get(wl_name, "unknown")
    row["n_intervals"] = len(blocks)
    secret, idx = read_ground_truth(run_dir)
    row["secret"] = secret
    row["idx"] = idx
    row["run"] = base
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/config.yaml")
    ap.add_argument("--raw-dir", default="data/raw")
    ap.add_argument("--out", default="data/features.csv")
    args = ap.parse_args()

    cfg = yaml.safe_load(open(args.config))
    labels = label_map(cfg)

    run_dirs = sorted(d for d in glob.glob(os.path.join(args.raw_dir, "*"))
                      if os.path.isdir(d))
    if not run_dirs:
        print(f"[parse] no run dirs under {args.raw_dir}", file=sys.stderr)
        sys.exit(1)

    rows = []
    for i, rd in enumerate(run_dirs):
        row = process_run(rd, labels, dump_names=(i == 0))
        if row:
            rows.append(row)
        if (i + 1) % 50 == 0:
            print(f"[parse] {i+1}/{len(run_dirs)}", file=sys.stderr)

    df = pd.DataFrame(rows)
    if df.empty:
        print("[parse] no runs parsed -- check that gem5 produced stats.txt "
              "in the run dirs (did run_gem5.py succeed?).", file=sys.stderr)
        sys.exit(1)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if args.out.endswith(".parquet"):
        try:
            df.to_parquet(args.out, index=False)
        except Exception as e:
            args.out = args.out[:-8] + ".csv"
            print(f"[parse] parquet unavailable ({e}); writing CSV", file=sys.stderr)
            df.to_csv(args.out, index=False)
    else:
        df.to_csv(args.out, index=False)
    print(f"[parse] {len(df)} runs -> {args.out}")
    print(f"[parse] {df.shape[1]} columns; labels: "
          f"{df['label'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()
