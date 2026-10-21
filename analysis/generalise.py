#!/usr/bin/env python3
"""
Stage 6: generalisation and stealthiness.
  (A) zero-day: anomaly model trained on benign only, detection per family
  (B) leave-one-attack-family-out: supervised binary detector trained on
      benign + all-but-one attack family, must still flag the held-out one
  (C) stealthiness proxy: detectability vs attack intensity (mpki quartiles)
Outputs results/generalisation.json and results/stealthiness.pdf
"""
import argparse, json, os, warnings
import numpy as np, pandas as pd
warnings.filterwarnings("ignore")
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.pipeline import make_pipeline

META = {"workload", "memcfg", "seed", "label", "run", "secret", "idx", "n_intervals"}
FAMS = ["flush_reload", "prime_probe", "spectre"]

def feats_of(df):
    return [c for c in df.select_dtypes(include=[np.number]).columns
            if c not in META and not c.endswith("_sum")]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="sweep.csv")
    ap.add_argument("--outdir", default="results")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    df = pd.read_csv(args.features)
    feats = feats_of(df)
    out = {}

    # (A) zero-day
    benign = df[df.label == "benign"]
    sc = StandardScaler().fit(benign[feats])
    iforest = IsolationForest(n_estimators=300, random_state=0).fit(sc.transform(benign[feats]))
    thr = np.quantile(-iforest.score_samples(sc.transform(benign[feats])), 0.95)
    out["zero_day_detection@5%FPR"] = {
        fam: round(float(((-iforest.score_samples(sc.transform(df[df.label == fam][feats]))) > thr).mean()), 4)
        for fam in FAMS}

    # (B) leave-one-family-out (supervised binary)
    loo = {}
    for held in FAMS:
        train = df[(df.label == "benign") | (df.label.isin([f for f in FAMS if f != held]))]
        test = df[df.label == held]
        yb = np.where(train.label == "benign", "benign", "attack")
        clf = make_pipeline(StandardScaler(), RandomForestClassifier(n_estimators=300, random_state=0))
        clf.fit(train[feats], yb)
        loo[held] = round(float((clf.predict(test[feats]) == "attack").mean()), 4)
    out["leave_one_family_out_recall"] = loo

    # (C) stealthiness proxy: detection vs intensity quartile
    att = df[df.label != "benign"].copy()
    att["score"] = -iforest.score_samples(sc.transform(att[feats]))
    att["q"] = pd.qcut(att["mpki"], 4, labels=["Q1(stealthiest)", "Q2", "Q3", "Q4(loudest)"])
    byq = att.groupby("q", observed=True).apply(lambda g: (g.score > thr).mean())
    out["stealthiness_detection_by_mpki_quartile"] = {k: round(float(v), 4) for k, v in byq.items()}

    with open(os.path.join(args.outdir, "generalisation.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))

    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(4.6, 2.7))
    ks = list(out["stealthiness_detection_by_mpki_quartile"].keys())
    vs = list(out["stealthiness_detection_by_mpki_quartile"].values())
    ax.bar(ks, vs, color="#4C6B8A", edgecolor="#333", lw=0.6)
    ax.set_ylabel("detection rate @ 5% FPR", fontsize=9); ax.set_ylim(0, 1.05)
    ax.set_xlabel("attack intensity quartile (MPKI)", fontsize=9)
    ax.tick_params(axis="x", labelsize=7.5)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    plt.tight_layout(); plt.savefig(os.path.join(args.outdir, "stealthiness.pdf"), bbox_inches="tight")
    plt.savefig(os.path.join(args.outdir, "stealthiness.png"), dpi=130, bbox_inches="tight")

if __name__ == "__main__":
    main()
