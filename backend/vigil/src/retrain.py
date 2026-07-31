"""
Retrain a classifier on the original corpus + accumulated user feedback,
versioning the old model and keeping a changelog.

    python -m src.retrain --type ps1

Old and new boosters are scored on the same deterministic test split
(stratified, random_state=42) so the F1 comparison is apples-to-apples.
The on-disk model is replaced only if the new F1 strictly improves;
rejected attempts still get a row in retrain_log.jsonl.

PE retrain is not wired -- the corpus loader is the only missing piece,
but reloading EMBER takes ~10 min so it's gated behind --type ps1.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import numpy as np
import lightgbm as lgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps1_extractor import extract_path as ps1_extract, FEATURE_NAMES as PS1_FEATURE_NAMES


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(HERE, "models")
ARCHIVE_DIR = os.path.join(MODELS_DIR, "archive")
CHANGELOG_PATH = os.path.join(MODELS_DIR, "changelog.json")
RETRAIN_LOG_PATH = os.path.join(MODELS_DIR, "retrain_log.jsonl")
FEEDBACK_PATH = os.path.join(HERE, "data", "feedback", "feedback.jsonl")

KEEP_VERSIONS = 5


# ---------- changelog ------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_changelog() -> dict:
    if not os.path.isfile(CHANGELOG_PATH):
        return {}
    try:
        with open(CHANGELOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_changelog(cl: dict) -> None:
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(CHANGELOG_PATH, "w", encoding="utf-8") as f:
        json.dump(cl, f, indent=2)


def _ensure_initial_version(cl: dict, model_key: str, model_path: str,
                            f1_initial: float | None = None,
                            change: str = "initial baseline") -> dict:
    """If the changelog has no v1 entry for this model, record one now."""
    versions = cl.setdefault(model_key, [])
    if versions:
        return cl
    versions.append({
        "version": 1,
        "timestamp": _now_iso(),
        "model_path": os.path.basename(model_path),
        "f1_before": None,
        "f1_after": f1_initial,
        "feedback_samples_added": 0,
        "change": change,
    })
    return cl


def append_changelog(cl: dict, model_key: str, *,
                     prev_version: int, new_version: int,
                     f1_before: float, f1_after: float,
                     feedback_added: int, change: str,
                     accepted: bool) -> dict:
    cl.setdefault(model_key, []).append({
        "version": new_version,
        "previous_version": prev_version,
        "timestamp": _now_iso(),
        "f1_before": f1_before,
        "f1_after": f1_after,
        "delta_f1": f1_after - f1_before,
        "feedback_samples_added": feedback_added,
        "accepted": accepted,
        "change": change,
    })
    return cl


# ---------- retrain log ----------------------------------------------------

def append_retrain_log(entry: dict) -> None:
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(RETRAIN_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ---------- corpus loaders -------------------------------------------------

def load_ps1_corpus(corpus_dir: str) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Read every .ps1 under {clean,malicious}/ and vectorize."""
    clean = sorted(glob.glob(os.path.join(corpus_dir, "clean", "*.ps1")))
    mal = sorted(glob.glob(os.path.join(corpus_dir, "malicious", "*.ps1")))
    paths = clean + mal
    X = np.asarray([ps1_extract(p).vector() for p in paths], dtype=np.float32)
    y = np.asarray([0] * len(clean) + [1] * len(mal), dtype=np.int32)
    return X, y, paths


def load_feedback_for(file_type: str) -> tuple[np.ndarray, np.ndarray, list[dict]]:
    """Load feedback rows for `file_type` that carry a feature_vector."""
    if not os.path.isfile(FEEDBACK_PATH):
        return np.zeros((0, 0), dtype=np.float32), np.zeros((0,), dtype=np.int32), []
    feats: list[list[float]] = []
    labels: list[int] = []
    rows: list[dict] = []
    with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("file_type") != file_type:
                continue
            vec = e.get("feature_vector")
            if not vec:
                continue
            feats.append([float(v) for v in vec])
            labels.append(int(e.get("label_int", 1 if e.get("correct_label") == "malicious" else 0)))
            rows.append(e)
    if not feats:
        return np.zeros((0, 0), dtype=np.float32), np.zeros((0,), dtype=np.int32), []
    return np.asarray(feats, dtype=np.float32), np.asarray(labels, dtype=np.int32), rows


# ---------- evaluation ------------------------------------------------------

def _evaluate(booster: lgb.Booster, X: np.ndarray, y: np.ndarray) -> dict:
    probs = booster.predict(X)
    preds = (probs >= 0.5).astype(np.int32)
    tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
    out = {
        "accuracy": float(accuracy_score(y, preds)),
        "precision": float(precision_score(y, preds, zero_division=0)),
        "recall": float(recall_score(y, preds, zero_division=0)),
        "f1": float(f1_score(y, preds, zero_division=0)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }
    if len(np.unique(y)) == 2:
        out["roc_auc"] = float(roc_auc_score(y, probs))
    return out


# ---------- archive management ---------------------------------------------

def _next_version(cl: dict, model_key: str) -> int:
    versions = cl.get(model_key, [])
    return max((v["version"] for v in versions), default=0) + 1


def _last_accepted_version(cl: dict, model_key: str) -> Optional[int]:
    """Version number whose model file is currently on disk.
    v1 (bootstrap) counts as accepted; subsequent entries must have
    accepted=True. Returns None if no record exists."""
    for entry in reversed(cl.get(model_key, [])):
        if entry["version"] == 1 or entry.get("accepted", False):
            return entry["version"]
    return None


def archive_old(model_path: str, version: int, archive_dir: str) -> str:
    os.makedirs(archive_dir, exist_ok=True)
    base = os.path.basename(model_path)
    stem, ext = os.path.splitext(base)
    dest = os.path.join(archive_dir, f"{stem}_v{version}{ext}")
    shutil.copy2(model_path, dest)
    return dest


def gc_archive(model_stem: str, archive_dir: str, keep: int = KEEP_VERSIONS) -> list[str]:
    pattern = os.path.join(archive_dir, f"{model_stem}_v*.lgbm")
    items = []
    for p in glob.glob(pattern):
        try:
            ver = int(os.path.splitext(p)[0].rsplit("_v", 1)[-1])
        except ValueError:
            continue
        items.append((ver, p))
    items.sort(key=lambda t: t[0])
    removed = []
    while len(items) > keep:
        _, victim = items.pop(0)
        try:
            os.remove(victim)
            removed.append(os.path.basename(victim))
        except OSError:
            pass
    return removed


# ---------- main retrain ----------------------------------------------------

def retrain_ps1(corpus_dir: str, model_path: str,
                num_iterations: int = 200,
                learning_rate: float = 0.05,
                num_leaves: int = 31,
                random_state: int = 42) -> dict:
    print(f"[retrain] loading PS1 corpus from {corpus_dir}")
    X_corpus, y_corpus, _paths = load_ps1_corpus(corpus_dir)
    print(f"[retrain]   corpus: {X_corpus.shape}  (clean={int((y_corpus==0).sum())}, mal={int((y_corpus==1).sum())})")

    X_fb, y_fb, fb_rows = load_feedback_for("ps1")
    print(f"[retrain]   feedback: {X_fb.shape[0]} samples")
    if X_fb.shape[0] and X_fb.shape[1] != X_corpus.shape[1]:
        raise SystemExit(f"feedback feature width {X_fb.shape[1]} != corpus {X_corpus.shape[1]}")

    if X_fb.shape[0]:
        X_all = np.concatenate([X_corpus, X_fb], axis=0)
        y_all = np.concatenate([y_corpus, y_fb], axis=0)
    else:
        X_all, y_all = X_corpus, y_corpus

    print(f"[retrain]   merged: {X_all.shape}  (clean={int((y_all==0).sum())}, mal={int((y_all==1).sum())})")

    # Held-out split — deterministic so old & new are compared on the same rows.
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_all, y_all, test_size=0.2, random_state=random_state, stratify=y_all,
    )

    # ---- score old model on the test split first (it must exist) --------
    if not os.path.isfile(model_path):
        raise SystemExit(f"old model not found: {model_path}")
    old_booster = lgb.Booster(model_file=model_path)
    metrics_before = _evaluate(old_booster, X_te, y_te)
    print(f"[retrain] OLD f1={metrics_before['f1']:.4f}  acc={metrics_before['accuracy']:.4f}  "
          f"(TN={metrics_before['tn']} FP={metrics_before['fp']} "
          f"FN={metrics_before['fn']} TP={metrics_before['tp']})")

    # ---- train new model -------------------------------------------------
    params = {
        "boosting_type": "gbdt",
        "objective": "binary",
        "num_iterations": num_iterations,
        "learning_rate": learning_rate,
        "num_leaves": num_leaves,
        "feature_fraction": 0.8,
        "min_data_in_leaf": 5,
        "verbose": -1,
    }
    print(f"[retrain] training new model: {params}")
    t0 = time.time()
    train_ds = lgb.Dataset(X_tr, label=y_tr, feature_name=PS1_FEATURE_NAMES)
    val_ds = lgb.Dataset(X_te, label=y_te, reference=train_ds)
    new_booster = lgb.train(
        params, train_ds, valid_sets=[val_ds], valid_names=["test"],
        callbacks=[lgb.log_evaluation(period=0)],
    )
    print(f"[retrain] trained in {time.time() - t0:.2f}s")

    metrics_after = _evaluate(new_booster, X_te, y_te)
    print(f"[retrain] NEW f1={metrics_after['f1']:.4f}  acc={metrics_after['accuracy']:.4f}  "
          f"(TN={metrics_after['tn']} FP={metrics_after['fp']} "
          f"FN={metrics_after['fn']} TP={metrics_after['tp']})")

    return {
        "metrics_before": metrics_before,
        "metrics_after": metrics_after,
        "feedback_count": int(X_fb.shape[0]),
        "n_total": int(X_all.shape[0]),
        "n_train": int(X_tr.shape[0]),
        "n_test": int(X_te.shape[0]),
        "new_booster": new_booster,
    }


# ---------- CLI -------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Retrain a classifier on corpus + feedback.")
    ap.add_argument("--type", required=True, choices=["ps1"],
                    help="model to retrain (PE retrain requires EMBER reload, deferred)")
    ap.add_argument("--corpus-dir", default=os.path.join(HERE, "data", "ps1_corpus"))
    ap.add_argument("--model-out", default=os.path.join(MODELS_DIR, "ps1_model.lgbm"))
    ap.add_argument("--num-iterations", type=int, default=200)
    ap.add_argument("--force-replace", action="store_true",
                    help="replace the saved model even if new F1 is not better")
    args = ap.parse_args()

    if args.type != "ps1":
        ap.error(f"unsupported --type {args.type}")

    result = retrain_ps1(
        corpus_dir=args.corpus_dir,
        model_path=args.model_out,
        num_iterations=args.num_iterations,
    )

    f1_before = result["metrics_before"]["f1"]
    f1_after = result["metrics_after"]["f1"]
    delta = f1_after - f1_before

    cl = load_changelog()
    cl = _ensure_initial_version(
        cl, "ps1_model", args.model_out,
        f1_initial=f1_before,
        change="initial baseline",
    )
    # The "previous version" for archival is the last version whose model
    # file is currently on disk -- i.e. the last accepted entry. Rejected
    # entries are bumps in the version counter only.
    prev_version = _last_accepted_version(cl, "ps1_model") or 1
    new_version = _next_version(cl, "ps1_model")

    # Decide whether to accept. Strict improvement; --force-replace overrides.
    accept = (f1_after > f1_before) or args.force_replace
    decision = ("REPLACE" if accept else "KEEP")
    print(f"[retrain] decision: {decision}  (deltaF1 = {delta:+.4f})")

    archive_path: Optional[str] = None
    new_model_path: Optional[str] = None
    if accept:
        # Archive the current file with the *previous* version number, then
        # write the new model in its place.
        archive_path = archive_old(args.model_out, prev_version, ARCHIVE_DIR)
        result["new_booster"].save_model(args.model_out)
        new_model_path = args.model_out
        print(f"[retrain] archived old -> {archive_path}")
        print(f"[retrain] wrote new   -> {new_model_path}")

        removed = gc_archive(
            os.path.splitext(os.path.basename(args.model_out))[0],
            ARCHIVE_DIR,
            keep=KEEP_VERSIONS,
        )
        if removed:
            print(f"[retrain] gc'd old archives: {', '.join(removed)}")

        change = (f"retrain with {result['feedback_count']} feedback samples; "
                  f"deltaF1 {delta:+.4f}")
        cl = append_changelog(
            cl, "ps1_model",
            prev_version=prev_version, new_version=new_version,
            f1_before=f1_before, f1_after=f1_after,
            feedback_added=result["feedback_count"],
            change=change, accepted=True,
        )
    else:
        change = (f"retrain skipped: new F1 ({f1_after:.4f}) < old F1 ({f1_before:.4f}); "
                  f"feedback samples evaluated: {result['feedback_count']}")
        cl = append_changelog(
            cl, "ps1_model",
            prev_version=prev_version, new_version=new_version,
            f1_before=f1_before, f1_after=f1_after,
            feedback_added=result["feedback_count"],
            change=change, accepted=False,
        )
    save_changelog(cl)

    # Append a retrain-log entry no matter what.
    append_retrain_log({
        "timestamp": _now_iso(),
        "model": "ps1_model",
        "previous_version": prev_version,
        "attempted_version": new_version,
        "accepted": accept,
        "decision": decision,
        "metrics_before": result["metrics_before"],
        "metrics_after": result["metrics_after"],
        "delta_f1": delta,
        "feedback_samples": result["feedback_count"],
        "n_train": result["n_train"],
        "n_test": result["n_test"],
        "n_total": result["n_total"],
        "archived_path": archive_path,
        "new_model_path": new_model_path,
    })
    print(f"[retrain] changelog -> {CHANGELOG_PATH}")
    print(f"[retrain] log       -> {RETRAIN_LOG_PATH}")


if __name__ == "__main__":
    main()
