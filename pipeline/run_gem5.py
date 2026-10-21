#!/usr/bin/env python3
"""
Stage 1 orchestrator: run every (workload x memory-config x sample) point
through gem5 SE mode and collect the raw stats.txt files.

Usage:
    python pipeline/run_gem5.py --config configs/config.yaml
    python pipeline/run_gem5.py --config configs/config.yaml --dry-run

--dry-run prints the gem5 command lines without launching gem5, so you can
sanity-check the sweep (and run it on the cluster) before committing compute.

Output layout:
    data/raw/<workload>_<memcfg>_s<seed>/stats.txt
"""
import argparse
import os
import subprocess
import sys
import yaml


def build_cmd(cfg, wl, mem, seed, outdir):
    g = cfg["gem5"]
    binary = os.path.join("workloads", "bin", wl["name"])
    cmd = [
        g["binary"],
        f"--outdir={outdir}",
        g["se_script"],
        "--binary", binary,
        "--cpu", "o3" if cfg["cpu"]["type"].startswith("Deriv") else "simple",
        "--clock", cfg["cpu"]["clock"],
        "--l1i", mem["l1i"], "--l1d", mem["l1d"],
        "--l1-assoc", str(mem["l1_assoc"]),
        "--l2", mem["l2"], "--l2-assoc", str(mem["l2_assoc"]),
        "--line-size", str(mem["line_size"]),
        "--interval", str(cfg["sampling"]["interval_ticks"]),
        "--max-intervals", str(cfg["sampling"]["max_intervals"]),
        # pass the per-run seed to the workload (keys/inputs vary by seed)
        "--args", str(seed),
    ]
    return cmd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/config.yaml")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0,
                    help="only emit the first N commands (smoke test)")
    ap.add_argument("--per-class", type=int, default=0,
                    help="max seeds per workload class (covers all classes)")
    ap.add_argument("--mem", default="",
                    help="restrict to one memory config by name (e.g. small)")
    args = ap.parse_args()

    cfg = yaml.safe_load(open(args.config))
    base_seed = cfg.get("seed", 0)
    n = cfg["samples_per_class"]

    per_class = args.per_class if args.per_class else n
    mems = [m for m in cfg["memory_sweep"]
            if not args.mem or m["name"] == args.mem]
    jobs = []
    for wl in cfg["workloads"]:
        for mem in mems:
            for i in range(per_class):
                seed = base_seed + i
                outdir = os.path.join("data", "raw",
                                      f"{wl['name']}_{mem['name']}_s{seed}")
                jobs.append((wl, mem, seed, outdir))

    if args.limit:
        jobs = jobs[: args.limit]

    print(f"[run_gem5] {len(jobs)} simulation jobs", file=sys.stderr)
    for wl, mem, seed, outdir in jobs:
        os.makedirs(outdir, exist_ok=True)
        cmd = build_cmd(cfg, wl, mem, seed, outdir)
        if args.dry_run:
            print(" ".join(cmd))
            continue
        log = open(os.path.join(outdir, "gem5.log"), "w")
        rc = subprocess.call(cmd, stdout=log, stderr=subprocess.STDOUT)
        status = "ok" if rc == 0 else f"FAIL({rc})"
        print(f"{status}  {outdir}", file=sys.stderr)


if __name__ == "__main__":
    main()
