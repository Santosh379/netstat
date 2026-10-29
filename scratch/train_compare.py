import sys
sys.path.insert(0, ".")
import time
from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    average_precision_score, confusion_matrix
)
from backend.app.ml.schema import FEATURE_NAMES
from backend.app.ml.preprocessor import MLPreprocessor

# Load data
df = pd.read_csv('backend/data/datasets/cicids2017_sample.csv')
raw_labels = df['Label'].astype(str).str.strip()
y_binary = (raw_labels != 'BENIGN').astype(int)
X = df[FEATURE_NAMES].copy()

# Split train (60%), val (15%), test (25%)
X_train_val, X_test, y_train_val, y_test, labels_train_val, labels_test = train_test_split(
    X, y_binary, raw_labels, test_size=0.25, random_state=42, stratify=raw_labels
)
X_train, X_val, y_train, y_val, labels_train, labels_val = train_test_split(
    X_train_val, y_train_val, labels_train_val, test_size=0.20, random_state=42, stratify=labels_train_val
)

print(f"Dataset split -> Train: {len(X_train):,}, Val: {len(X_val):,}, Test: {len(X_test):,}")

prep = MLPreprocessor()
prep.fit(X_train)
X_train_arr = prep.transform_df(X_train)
X_val_arr = prep.transform_df(X_val)
X_test_arr = prep.transform_df(X_test)

# 1. Baseline: IsolationForest
print("\n[1] Training Baseline Isolation Forest on normal baseline...")
iso = IsolationForest(n_estimators=100, contamination=0.10, random_state=42, n_jobs=-1)
iso.fit(X_train_arr[y_train == 0])

val_raw = iso.score_samples(X_val_arr)
min_s, max_s = float(val_raw.min()), float(val_raw.max())
span = max(max_s - min_s, 1.0)
val_iso_scores = np.clip((max_s - val_raw) / span, 0.0, 1.0)

# Evaluate Baseline on Test
test_raw = iso.score_samples(X_test_arr)
test_iso_scores = np.clip((max_s - test_raw) / span, 0.0, 1.0)
iso_preds = (test_iso_scores > 0.5).astype(int)

iso_auc = roc_auc_score(y_test, test_iso_scores)
iso_prec = precision_score(y_test, iso_preds, zero_division=0)
iso_rec = recall_score(y_test, iso_preds, zero_division=0)
iso_f1 = f1_score(y_test, iso_preds, zero_division=0)
iso_cm = confusion_matrix(y_test, iso_preds)
iso_tn, iso_fp, iso_fn, iso_tp = iso_cm.ravel()
iso_fpr = iso_fp / (iso_fp + iso_tn)

print(f"Baseline IsolationForest (Threshold 0.50):")
print(f"  ROC-AUC: {iso_auc:.4f} | Prec: {iso_prec:.4f} | Rec: {iso_rec:.4f} | F1: {iso_f1:.4f} | FPR: {iso_fpr:.4f}")

# 2. Candidate: HistGradientBoosting
print("\n[2] Training Candidate HistGradientBoosting on 17 features...")
hgb = HistGradientBoostingClassifier(random_state=42, max_iter=100)
t0 = time.time()
hgb.fit(X_train_arr, y_train)
hgb_train_time = time.time() - t0

# Tune threshold on validation set
val_probs = hgb.predict_proba(X_val_arr)[:, 1]
best_thresh = 0.5
best_f1 = 0
for t in np.linspace(0.2, 0.8, 31):
    f1 = f1_score(y_val, (val_probs > t).astype(int), zero_division=0)
    if f1 > best_f1:
        best_f1 = f1
        best_thresh = t

print(f"Tuned threshold on validation set: {best_thresh:.3f} (Validation F1: {best_f1:.4f})")

# Evaluate Candidate on Test
t0 = time.time()
test_probs = hgb.predict_proba(X_test_arr)[:, 1]
hgb_latency_us = (time.time() - t0) / len(X_test_arr) * 1_000_000
test_preds = (test_probs > best_thresh).astype(int)

hgb_auc = roc_auc_score(y_test, test_probs)
hgb_pr_auc = average_precision_score(y_test, test_probs)
hgb_prec = precision_score(y_test, test_preds, zero_division=0)
hgb_rec = recall_score(y_test, test_preds, zero_division=0)
hgb_f1 = f1_score(y_test, test_preds, zero_division=0)
hgb_cm = confusion_matrix(y_test, test_preds)
hgb_tn, hgb_fp, hgb_fn, hgb_tp = hgb_cm.ravel()
hgb_fpr = hgb_fp / (hgb_fp + hgb_tn)

print(f"\nCandidate HistGradientBoosting (Held-out Test, Threshold {best_thresh:.3f}):")
print(f"  ROC-AUC:   {hgb_auc:.4f}")
print(f"  PR-AUC:    {hgb_pr_auc:.4f}")
print(f"  Precision: {hgb_prec:.4f}")
print(f"  Recall:    {hgb_rec:.4f}")
print(f"  F1-Score:  {hgb_f1:.4f}")
print(f"  FPR:       {hgb_fpr:.4f} ({hgb_fp}/{hgb_fp+hgb_tn})")
print(f"  Latency:   {hgb_latency_us:.1f} microseconds per flow")
print(f"  Confusion Matrix: [[TN={hgb_tn}, FP={hgb_fp}], [FN={hgb_fn}, TP={hgb_tp}]]")

print("\nPer-Category Recall & Confidence Breakdown:")
test_df = pd.DataFrame({"label": labels_test, "pred": test_preds, "prob": test_probs})
for cat, grp in test_df.groupby("label"):
    rec_rate = grp["pred"].mean() if cat != "BENIGN" else (1 - grp["pred"].mean())
    print(f"  - {cat:15s}: count={len(grp):5d} | Accuracy/Recall={rec_rate*100:5.1f}% | Avg Anomaly Prob={grp['prob'].mean():.3f}")
