"""
Reproducible Training and Evaluation Script for NetScope AI ML Pipeline.
Usage:
    python backend/train_ml_model.py
"""

import os
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir.parent))

from backend.app.ml.trainer import train_isolation_forest
from backend.app.ml.evaluator import evaluate_model, format_evaluation_report
from backend.app.config import settings

def main():
    dataset_path = settings.DATA_DIR / "datasets" / "cicids2017_sample.csv"
    output_model_path = settings.DATA_DIR / "models" / "isolation_forest_v1.joblib"

    if not dataset_path.exists():
        print(f"[ERROR] Dataset not found at {dataset_path}")
        print("Please ensure cicids2017_sample.csv is downloaded into backend/data/datasets/")
        sys.exit(1)

    print("===========================================================")
    print("      NetScope AI: Training Isolation Forest Model        ")
    print("===========================================================")
    print(f"Dataset:    {dataset_path}")
    print(f"Target:     {output_model_path}")
    print(f"Algorithm:  Isolation Forest (CPU, Unsupervised)")
    print("-----------------------------------------------------------")

    # 1. Train model
    artifact, metadata = train_isolation_forest(
        dataset_path=dataset_path,
        output_model_path=output_model_path,
        n_estimators=100,
        contamination=0.10,
        random_state=42,
        decision_threshold=0.50
    )

    # 2. Evaluate model on held-out test split
    print("\n[ML Evaluator] Running comprehensive evaluation on 30% held-out test data...")
    results = evaluate_model(artifact, dataset_path=dataset_path, test_size=0.3, random_state=42)

    # 3. Print report
    report_text = format_evaluation_report(results)
    print("\n" + report_text)

    # 4. Save results JSON next to model
    eval_json_path = output_model_path.with_suffix(".eval.json")
    import json
    with open(eval_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[ML Evaluator] Evaluation metrics saved to {eval_json_path}")
    print("[SUCCESS] Model trained, verified, and saved.")

if __name__ == "__main__":
    main()
