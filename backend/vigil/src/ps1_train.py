"""
Train a LightGBM classifier on the synthetic PS1 corpus.

Reads data/ps1_corpus/{clean,malicious}/*.ps1, vectorizes each file via
ps1_extractor.extract_path(), splits 80/20 stratified, trains LightGBM,
reports metrics, saves the model to models/ps1_model.lgbm.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time

import numpy as np
import lightgbm as lgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score,
)
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps1_extractor import extract_path, FEATURE_NAMES


def load_corpus(corpus_dir: str):
    clean_files = sorted(glob.glob(os.path.join(corpus_dir, "clean", "*.ps1")))
    mal_files = sorted(glob.glob(os.path.join(corpus_dir, "malicious", "*.ps1")))
    if not clean_files or not mal_files:
        raise SystemExit(f"empty corpus under {corpus_dir}. run src/ps1_corpus.py first.")
    print(f"[*] {len(clean_files)} clean + {len(mal_files)} malicious .ps1 files")

    X, y = [], []
    for p in clean_files:
        X.append(extract_path(p).vector())
        y.append(0)
    for p in mal_files:
        X.append(extract_path(p).vector())
        y.append(1)
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int32)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default="data/ps1_corpus")
    ap.add_argument("--model-out", default="models/ps1_model.lgbm")
    ap.add_argument("--num-iterations", type=int, default=200)
    ap.add_argument("--learning-rate", type=float, default=0.05)
    ap.add_argument("--num-leaves", type=int, default=31)
    args = ap.parse_args()

    X, y = load_corpus(args.corpus_dir)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"    train: {X_tr.shape}, test: {X_te.shape}")

    params = {
        "boosting_type": "gbdt",
        "objective": "binary",
        "num_iterations": args.num_iterations,
        "learning_rate": args.learning_rate,
        "num_leaves": args.num_leaves,
        "feature_fraction": 0.8,
        "min_data_in_leaf": 5,
        "verbose": -1,
    }
    print(f"[*] training with {params}")
    t0 = time.time()
    train_ds = lgb.Dataset(X_tr, label=y_tr, feature_name=FEATURE_NAMES)
    val_ds = lgb.Dataset(X_te, label=y_te, reference=train_ds)
    model = lgb.train(
        params, train_ds,
        valid_sets=[val_ds], valid_names=["test"],
        callbacks=[lgb.log_evaluation(period=50)],
    )
    print(f"[*] trained in {time.time() - t0:.1f}s")

    probs = model.predict(X_te)
    preds = (probs >= 0.5).astype(np.int32)
    acc = accuracy_score(y_te, preds)
    prec = precision_score(y_te, preds)
    rec = recall_score(y_te, preds)
    f1 = f1_score(y_te, preds)
    auc = roc_auc_score(y_te, probs)
    tn, fp, fn, tp = confusion_matrix(y_te, preds).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print()
    print("=" * 56)
    print(f"  accuracy        : {acc:.4f}")
    print(f"  precision       : {prec:.4f}")
    print(f"  recall          : {rec:.4f}")
    print(f"  F1              : {f1:.4f}")
    print(f"  ROC AUC         : {auc:.4f}")
    print(f"  false positive  : {fpr:.4f}  ({fp}/{fp+tn})")
    print(f"  confusion       : TN={tn} FP={fp} FN={fn} TP={tp}")
    print("=" * 56)

    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    model.save_model(args.model_out)
    print(f"[*] saved model -> {args.model_out}")

    metrics_path = os.path.splitext(args.model_out)[0] + "_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump({
            "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
            "roc_auc": auc, "fpr": fpr,
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
            "n_train": int(X_tr.shape[0]), "n_test": int(X_te.shape[0]),
        }, f, indent=2)
    print(f"[*] saved metrics -> {metrics_path}")


if __name__ == "__main__":
    main()
