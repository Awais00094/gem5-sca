#!/usr/bin/env python3
"""
Stage 5: detection with stratified cross-validation.

Three tasks:
  (A) multi-class attack-family classification (benign / flush_reload /
      prime_probe / spectre), supervised, 5-fold stratified CV
  (B) binary attack-vs-benign, supervised
  (C) unsupervised anomaly detection: models trained on BENIGN ONLY,
      evaluated by how well they flag the attack classes (the realistic
      zero-day setting)

Feature policy: we drop length-proxy features (every *_sum counter and
n_intervals) and all ground-truth/meta columns, so a model cannot cheat on
how long a synthetic run happens to last. Rates, per-interval means, and
temporal-shape features remain.

Outputs: results/detection.json and results/confusion_matrix.pdf
"""
import argparse, json, os, warnings
import numpy as np, pandas as pd
warnings.filterwarnings("ignore")

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPRegressor
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support,
                             confusion_matrix, roc_auc_score)
from xgboost import XGBClassifier
import hdbscan

META = {"workload", "memcfg", "seed", "label", "run", "secret", "idx", "n_intervals"}

def feature_columns(df):
    cols = []
    for c in df.select_dtypes(include=[np.number]).columns:
        if c in META:            continue
        if c.endswith("_sum"):   continue   # length proxy
        cols.append(c)
    return cols

def summarise(y, yhat, labels):
    p, r, f, _ = precision_recall_fscore_support(y, yhat, labels=labels,
                                                 average="macro", zero_division=0)
    return {"accuracy": round(accuracy_score(y, yhat), 4),
            "precision_macro": round(p, 4), "recall_macro": round(r, 4),
            "f1_macro": round(f, 4)}

def supervised(df, feats, target, tag, out):
    X = df[feats].values
    y = df[target].values
    labels = sorted(pd.unique(y))
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    models = {
        "RandomForest": RandomForestClassifier(n_estimators=300, random_state=0),
        "XGBoost": XGBClassifier(n_estimators=300, max_depth=5, learning_rate=0.1,
                                 subsample=0.9, eval_metric="mlogloss",
                                 random_state=0, verbosity=0),
        "SVM-RBF": SVC(C=10, gamma="scale", random_state=0),
        "LogReg": LogisticRegression(max_iter=2000, random_state=0),
    }
    res = {}
    best_pred = None
    for name, clf in models.items():
        from sklearn.pipeline import make_pipeline
        pipe = make_pipeline(StandardScaler(), clf)
        # encode labels for xgboost
        if name == "XGBoost":
            yc = pd.Categorical(y, categories=labels).codes
            yhat_codes = cross_val_predict(pipe, X, yc, cv=skf)
            yhat = np.array(labels)[yhat_codes]
        else:
            yhat = cross_val_predict(pipe, X, y, cv=skf)
        res[name] = summarise(y, yhat, labels)
        if name == "RandomForest":
            best_pred = yhat
    out[tag] = {"labels": labels, "models": res}
    return labels, y, best_pred

def unsupervised(df, feats, out):
    """Train anomaly models on benign only; score all runs."""
    Xall = df[feats].values
    is_benign = (df["label"] == "benign").values
    sc = StandardScaler().fit(Xall[is_benign])
    Xs = sc.transform(Xall)
    Xb = Xs[is_benign]
    y_attack = (~is_benign).astype(int)   # 1 = attack

    scores = {}
    # Isolation Forest (higher = more anomalous)
    iforest = IsolationForest(n_estimators=300, contamination="auto",
                              random_state=0).fit(Xb)
    scores["IsolationForest"] = -iforest.score_samples(Xs)
    # Autoencoder via MLPRegressor reconstruction error (stand-in for VAE)
    ae = MLPRegressor(hidden_layer_sizes=(32, 8, 32), max_iter=1500,
                      random_state=0).fit(Xb, Xb)
    rec = ae.predict(Xs)
    scores["Autoencoder"] = ((Xs - rec) ** 2).mean(axis=1)
    # HDBSCAN outlier scores (fit on benign, approximate_predict strength)
    clus = hdbscan.HDBSCAN(min_cluster_size=10, prediction_data=True).fit(Xb)
    strengths, _ = hdbscan.approximate_predict(clus, Xs)
    # membership strength: low strength / label -1 => anomalous
    soft = hdbscan.membership_vector(clus, Xs) if clus.labels_.max() >= 0 else None
    hdb_score = 1.0 - (soft.max(axis=1) if soft is not None else np.zeros(len(Xs)))
    scores["HDBSCAN"] = hdb_score

    res = {}
    ens = np.zeros(len(Xs))
    for name, s in scores.items():
        auc = roc_auc_score(y_attack, s)
        res[name] = {"roc_auc": round(auc, 4)}
        # normalise to [0,1] for ensemble averaging
        ens += (s - s.min()) / (np.ptp(s) + 1e-12)
    ens /= len(scores)
    res["Ensemble(mean)"] = {"roc_auc": round(roc_auc_score(y_attack, ens), 4)}
    # ensemble detection rate at a benign-FPR=5% threshold
    thr = np.quantile(ens[is_benign], 0.95)
    det_rate = (ens[~is_benign] > thr).mean()
    res["Ensemble(mean)"]["detection_rate@5%FPR"] = round(float(det_rate), 4)
    out["unsupervised_benign_trained"] = res

def plot_confusion(y, yhat, labels, path):
    import matplotlib
    matplotlib.use("Agg"); import matplotlib.pyplot as plt
    cm = confusion_matrix(y, yhat, labels=labels)
    cmn = cm / cm.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(4.2, 3.6))
    im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels))); ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("predicted"); ax.set_ylabel("true")
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{cmn[i,j]:.2f}", ha="center", va="center",
                    fontsize=7, color="white" if cmn[i,j] > 0.5 else "#333")
    fig.colorbar(im, fraction=0.046, pad=0.04)
    plt.tight_layout(); plt.savefig(path, bbox_inches="tight")
    plt.savefig(path.replace(".pdf", ".png"), dpi=130, bbox_inches="tight")
    plt.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="sweep.csv")
    ap.add_argument("--outdir", default="results")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    df = pd.read_csv(args.features)
    feats = feature_columns(df)
    out = {"n_runs": len(df), "n_features_used": len(feats),
           "feature_policy": "dropped *_sum and n_intervals (length proxies)"}

    # (A) multi-class family
    labels, y, rf_pred = supervised(df, feats, "label", "multiclass_family", out)
    plot_confusion(y, rf_pred, labels,
                   os.path.join(args.outdir, "confusion_matrix.pdf"))
    # (B) binary attack vs benign
    df = df.assign(binlabel=np.where(df["label"] == "benign", "benign", "attack"))
    supervised(df, feats, "binlabel", "binary_attack_vs_benign", out)
    # (C) unsupervised anomaly
    unsupervised(df, feats, out)

    with open(os.path.join(args.outdir, "detection.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()
