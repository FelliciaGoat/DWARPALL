#!/usr/bin/env python3
"""
STAGE 3: the visit sorter.

Teaches a program to label each visit as scan / brute_force / dropper / recon, then grades it
honestly against the answer key on visits it never trained on.

It compares THREE sorters so the numbers mean something:
  1. "Always guess the most common type"      (the dumbest possible baseline)
  2. "Hand-written rules"                      (a human's if/then guesses, no learning)
  3. "Random forest"                           (the learned classifier)

Usage:
  python3 train_sorter.py --data data
  python3 train_sorter.py --data data --unseen data_unseen     # also test on a fresh dataset
"""
import argparse
import json
import os

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from features import FEATURE_NAMES, load_sessions, session_features

CLASSES = ["scan", "brute_force", "dropper", "recon"]
COL = {n: i for i, n in enumerate(FEATURE_NAMES)}


def build(data_dir):
    """Features come from the cleaned footage; labels come from the answer key (grading only)."""
    sessions = load_sessions(os.path.join(data_dir, "sessions_anon.jsonl"))
    labels = {l["session"]: l for l in json.load(open(os.path.join(data_dir, "labels_anon.json")))}
    ids = sorted(sessions)
    X = np.array([session_features(sessions[s]) for s in ids])
    y = np.array([labels[s]["label"] for s in ids])
    hard = np.array([labels[s]["difficulty"] == "hard" for s in ids])
    return ids, X, y, hard


def hand_written_rules(X):
    """A human's guess with no learning: look at the most obvious clue, in order."""
    out = []
    for r in X:
        if r[COL["n_downloads"]] > 0:
            out.append("dropper")
        elif r[COL["n_commands"]] > 0:
            out.append("recon")
        elif r[COL["n_failed_logins"]] >= 3:
            out.append("brute_force")
        else:
            out.append("scan")
    return np.array(out)


def score(name, y_true, y_pred, hard):
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, labels=CLASSES, zero_division=0)
    res = {
        "overall_accuracy": round(accuracy_score(y_true, y_pred), 4),
        "hard_case_accuracy": round(accuracy_score(y_true[hard], y_pred[hard]), 4) if hard.any() else None,
        "per_class": {c: {"precision": round(p[i], 3), "recall": round(r[i], 3), "f1": round(f[i], 3)}
                      for i, c in enumerate(CLASSES)},
        "macro_f1": round(float(np.mean(f)), 4),
    }
    print(f"  {name:34s} accuracy {res['overall_accuracy']:.3f}   hard cases {res['hard_case_accuracy']}"
          f"   macro-F1 {res['macro_f1']:.3f}")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--unseen", default=None, help="folder of a fresh dataset (different seed)")
    a = ap.parse_args()

    ids, X, y, hard = build(a.data)
    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=0.3, random_state=0, stratify=y)
    print(f"{len(y)} visits: {len(tr)} to learn from, {len(te)} held back for grading "
          f"({int(hard[te].sum())} hard cases among them)\n")

    dummy = DummyClassifier(strategy="most_frequent").fit(X[tr], y[tr])
    forest = RandomForestClassifier(n_estimators=200, random_state=0, class_weight="balanced").fit(X[tr], y[tr])

    print("Results on the held-back visits:")
    results = {
        "always_most_common": score("1. always guess most common type", y[te], dummy.predict(X[te]), hard[te]),
        "hand_written_rules": score("2. hand-written rules", y[te], hand_written_rules(X[te]), hard[te]),
        "random_forest": score("3. random forest (learned)", y[te], forest.predict(X[te]), hard[te]),
    }

    cv = cross_val_score(RandomForestClassifier(n_estimators=100, random_state=0, class_weight="balanced"),
                         X, y, cv=StratifiedKFold(5, shuffle=True, random_state=0))
    results["random_forest_5fold_accuracy"] = {"mean": round(cv.mean(), 4), "std": round(cv.std(), 4)}
    print(f"\n  5-round cross-check of the forest: {cv.mean():.3f} (+/- {cv.std():.3f})")

    if a.unseen:
        _, Xu, yu, hu = build(a.unseen)
        print(f"\nResults on a brand-new dataset ({len(yu)} visits from a different seed):")
        results["unseen"] = {
            "hand_written_rules": score("2. hand-written rules", yu, hand_written_rules(Xu), hu),
            "random_forest": score("3. random forest (learned)", yu, forest.predict(Xu), hu),
        }

    # ---- which clues mattered
    imp = sorted(zip(FEATURE_NAMES, forest.feature_importances_), key=lambda t: -t[1])
    results["clue_importance"] = {n: round(float(v), 4) for n, v in imp}
    print("\nClues the forest relied on most:")
    for n, v in imp[:6]:
        print(f"  {n:24s} {v:.3f}")

    # ---- mistakes
    pred = forest.predict(X[te])
    wrong = [(ids[i], y[i], p) for i, p in zip(te, pred) if p != y[i]]
    print(f"\nForest mistakes on held-back visits: {len(wrong)} of {len(te)}")
    for sid, truth, p in wrong[:10]:
        print(f"  visit {sid}: truly {truth}, guessed {p}")

    # ---- confusion matrix picture for the slides
    cm = confusion_matrix(y[te], pred, labels=CLASSES)
    fig, ax = plt.subplots(figsize=(5.2, 4.4))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(4)); ax.set_xticklabels(CLASSES, rotation=25, ha="right")
    ax.set_yticks(range(4)); ax.set_yticklabels(CLASSES)
    ax.set_xlabel("What the sorter guessed"); ax.set_ylabel("What it really was")
    ax.set_title("Visit sorter: held-back visits")
    for i in range(4):
        for j in range(4):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    fig.tight_layout()
    fig.savefig(os.path.join(a.data, "sorter_confusion.png"), dpi=160)

    # ---- hand the guesses to the next stage (reports), with confidence
    proba = forest.predict_proba(X)
    with open(os.path.join(a.data, "predictions.json"), "w") as f:
        json.dump([{"session": s, "predicted": forest.classes_[p.argmax()],
                    "confidence": round(float(p.max()), 3)} for s, p in zip(ids, proba)], f, indent=1)
    json.dump(results, open(os.path.join(a.data, "sorter_metrics.json"), "w"), indent=1)
    print(f"\nSaved: sorter_metrics.json, sorter_confusion.png, predictions.json in {a.data}/")


if __name__ == "__main__":
    main()
