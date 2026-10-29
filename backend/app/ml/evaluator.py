"""
Model evaluation module for NetScope AI ML Pipeline.
Computes comprehensive metrics on held-out test data.
"""

from pathlib import Path
from typing import Any
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report
)

from .trainer import ModelArtifact
from .dataset import load_cicids2017_dataset

def evaluate_model(
    artifact: ModelArtifact,
    dataset_path: Path,
    test_size: float = 0.3,
    random_state: int = 42
) -> dict[str, Any]:
    """
    Evaluates the model artifact on held-out test data.
    """
    _, X_test, _, y_test, _, labels_test = load_cicids2017_dataset(
        dataset_path,
        test_size=test_size,
        random_state=random_state
    )

    X_test_arr = artifact.preprocessor.transform_df(X_test)

    # Compute anomaly scores
    if hasattr(artifact.model, "predict_proba"):
        normalized_scores = artifact.model.predict_proba(X_test_arr)[:, 1]
    else:
        raw_scores = artifact.model.score_samples(X_test_arr)
        span = artifact.max_score - artifact.min_score
        if span <= 0:
            span = 1.0
        # Normalized score: 0.0 (normal) to 1.0 (highly anomalous)
        normalized_scores = np.clip((artifact.max_score - raw_scores) / span, 0.0, 1.0)

    preds = (normalized_scores > artifact.threshold).astype(int)

    # Metrics
    auc = float(roc_auc_score(y_test, normalized_scores))
    pr_auc = float(average_precision_score(y_test, normalized_scores))
    prec = float(precision_score(y_test, preds, zero_division=0))
    rec = float(recall_score(y_test, preds, zero_division=0))
    f1 = float(f1_score(y_test, preds, zero_division=0))
    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    # False Positive Rate (FPR) = FP / (FP + TN)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Per-category breakdown
    test_df = pd.DataFrame({
        "label": labels_test,
        "score": normalized_scores,
        "pred": preds
    })

    category_results = {}
    for label, group in test_df.groupby("label"):
        det_rate = float(group["pred"].mean())
        avg_score = float(group["score"].mean())
        category_results[label] = {
            "count": int(len(group)),
            "detection_rate": round(det_rate, 4),
            "avg_anomaly_score": round(avg_score, 4)
        }

    results = {
        "model_name": artifact.metadata.get("model_name"),
        "model_version": artifact.metadata.get("model_version"),
        "test_samples": int(len(y_test)),
        "benign_samples": int((y_test == 0).sum()),
        "anomaly_samples": int((y_test == 1).sum()),
        "decision_threshold": artifact.threshold,
        "roc_auc": round(auc, 4),
        "pr_auc": round(pr_auc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "categories": category_results
    }

    return results

def format_evaluation_report(results: dict[str, Any]) -> str:
    """
    Formats the evaluation results into a clean text table.
    """
    lines = [
        "===========================================================",
        "       NetScope AI - Machine Learning Evaluation Report    ",
        "===========================================================",
        f"Model: {results['model_name']} (v{results['model_version']})",
        f"Evaluated Test Samples: {results['test_samples']:,} ({results['benign_samples']:,} Benign, {results['anomaly_samples']:,} Attacks)",
        f"Decision Threshold:     {results['decision_threshold']:.2f}",
        "-----------------------------------------------------------",
        f"  ROC-AUC Score:        {results['roc_auc']:.4f}",
        f"  Precision (Anomaly):  {results['precision']:.4f}",
        f"  Recall (Anomaly):     {results['recall']:.4f}",
        f"  F1-Score:             {results['f1_score']:.4f}",
        f"  False Positive Rate:  {results['false_positive_rate']:.4f} ({results['false_positives']}/{results['benign_samples']})",
        "-----------------------------------------------------------",
        "Confusion Matrix:",
        f"  [True Benign: {results['true_negatives']:5d}]  [False Anomaly: {results['false_positives']:5d}]",
        f"  [Missed Attack: {results['false_negatives']:5d}]  [Detected Attack: {results['true_positives']:5d}]",
        "-----------------------------------------------------------",
        "Performance by Traffic Category:"
    ]

    for cat, info in results.get("categories", {}).items():
        lines.append(f"  - {cat:15s} Count: {info['count']:5d} | Detection Rate: {info['detection_rate']*100:5.1f}% | Avg Anomaly Score: {info['avg_anomaly_score']:.3f}")

    lines.append("===========================================================")
    return "\n".join(lines)
