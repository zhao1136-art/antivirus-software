"""
Train a LightGBM classifier on EMBER 2018 v2.

Loads the memory-mapped vectorized features (X_train.dat / y_train.dat,
X_test.dat / y_test.dat), drops unlabeled rows (y == -1), trains, evaluates
and saves the model to models/model.lgbm.
"""
from __future__ import annotations

import argparse
import os
import time

import numpy as np
import lightgbm as lgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score,
)


N_FEATURES = 2381  # EMBER v2


def _mmap(path: str, dtype, n_features: int | None = None) -> np.ndarray:
    """Memory-map a .dat file. For features, reshape to (-1, n_features)."""
    a = np.memmap(path, dtype=dtype, mode="r")
    if n_features:
        a = a.reshape(-1, n_features)
    return a


def load_ember(data_dir: str):
    """Load EMBER 2018 vectorized features as memmaps."""
    X_train = _mmap(os.path.join(data_dir, "X_train.dat"), np.float32, N_FEATURES)
    y_train = _mmap(os.path.join(data_dir, "y_train.dat"), np.float32)
    X_test = _mmap(os.path.join(data_dir, "X_test.dat"), np.float32, N_FEATURES)
    y_test = _mmap(os.path.join(data_dir, "y_test.dat"), np.float32)
    return X_train, y_train, X_test, y_test


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/ember2018")
    ap.add_argument("--model-out", default="models/model.lgbm")
    ap.add_argument("--num-iterations", type=int, default=500)
    ap.add_argument("--learning-rate", type=float, default=0.05)
    ap.add_argument("--num-leaves", type=int, default=1024)
    ap.add_argument("--max-train", type=int, default=0,
                    help="cap training set size for quick runs (0 = no cap)")
    args = ap.parse_args()

    print(f"[*] loading EMBER from {args.data_dir}")
    X_train, y_train, X_test, y_test = load_ember(args.data_dir)
    print(f"    X_train: {X_train.shape}, y_train: {y_train.shape}")
    print(f"    X_test:  {X_test.shape}, y_test:  {y_test.shape}")

    # Drop unlabeled training rows (EMBER marks them as -1).
    train_mask = y_train != -1
    n_total = len(y_train)
    n_labeled = int(train_mask.sum())
    print(f"    labeled train rows: {n_labeled} / {n_total}")

    # Materialize labeled subset (LightGBM needs np arrays).
    idx = np.where(train_mask)[0]
    if args.max_train and args.max_train < len(idx):
        rng = np.random.default_rng(42)
        idx = rng.choice(idx, size=args.max_train, replace=False)
        idx.sort()
        print(f"    capping training set at {args.max_train} rows")
    X_tr = np.asarray(X_train[idx], dtype=np.float32)
    y_tr = np.asarray(y_train[idx], dtype=np.int32)

    # Test set: in EMBER all 200k test rows are labeled but be defensive.
    test_mask = y_test != -1
    X_te = np.asarray(X_test[test_mask], dtype=np.float32)
    y_te = np.asarray(y_test[test_mask], dtype=np.int32)

    print(f"    final train: {X_tr.shape}  (pos rate {y_tr.mean():.3f})")
    print(f"    final test:  {X_te.shape}  (pos rate {y_te.mean():.3f})")

    params = {
        "boosting_type": "gbdt",
        "objective": "binary",
        "num_iterations": args.num_iterations,
        "learning_rate": args.learning_rate,
        "num_leaves": args.num_leaves,
        "feature_fraction": 0.5,
        "bagging_fraction": 0.5,
        "bagging_freq": 5,
        "verbose": -1,
    }
    print(f"[*] training LightGBM with {params}")
    t0 = time.time()
    train_ds = lgb.Dataset(X_tr, label=y_tr)
    val_ds = lgb.Dataset(X_te, label=y_te, reference=train_ds)
    model = lgb.train(
        params,
        train_ds,
        valid_sets=[val_ds],
        valid_names=["test"],
        callbacks=[lgb.log_evaluation(period=50)],
    )
    print(f"[*] trained in {time.time() - t0:.1f}s")

    print("[*] evaluating on EMBER test set")
    probs = model.predict(X_te)
    preds = (probs >= 0.5).astype(np.int32)

    acc = accuracy_score(y_te, preds)
    prec = precision_score(y_te, preds)
    rec = recall_score(y_te, preds)
    f1 = f1_score(y_te, preds)
    auc = roc_auc_score(y_te, probs)
    tn, fp, fn, tp = confusion_matrix(y_te, preds).ravel()
    fpr = fp / (fp + tn)

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

    # Also dump metrics next to the model.
    metrics_path = os.path.splitext(args.model_out)[0] + "_metrics.txt"
    with open(metrics_path, "w") as f:
        f.write(f"accuracy   {acc:.6f}\n")
        f.write(f"precision  {prec:.6f}\n")
        f.write(f"recall     {rec:.6f}\n")
        f.write(f"f1         {f1:.6f}\n")
        f.write(f"roc_auc    {auc:.6f}\n")
        f.write(f"fpr        {fpr:.6f}\n")
        f.write(f"tn {tn}\nfp {fp}\nfn {fn}\ntp {tp}\n")
    print(f"[*] saved metrics -> {metrics_path}")


if __name__ == "__main__":
    main()
