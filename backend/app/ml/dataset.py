"""
Dataset loader and documentation for NetScope AI ML Pipeline.
Source: Canadian Institute for Cybersecurity (CIC-IDS2017), University of New Brunswick (UNB).
Reference: Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018).
Curated sample: Western-OC2-Lab (MIT License, 56,661 flows).
"""

from pathlib import Path
from typing import Tuple, Optional
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from .schema import FEATURE_NAMES

DATASET_METADATA = {
    "name": "CIC-IDS2017 Curated Benchmark Subset",
    "origin": "Canadian Institute for Cybersecurity (CIC), University of New Brunswick",
    "curator": "Western-OC2-Lab (Intrusion-Detection-System-Using-Machine-Learning)",
    "license": "Academic Research & MIT License",
    "total_flows": 56661,
    "benign_flows": 22731,
    "attack_flows": 33930,
    "attack_types": ["DoS", "PortScan", "BruteForce", "WebAttack", "Bot", "Infiltration"],
    "description": "Bi-directional network flows captured in an emulated environment reflecting realistic background and cyberattack traffic."
}

def load_cicids2017_dataset(
    csv_path: Path,
    test_size: float = 0.3,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series, pd.Series]:
    """
    Loads the CIC-IDS2017 dataset, validates feature availability,
    excludes non-feature columns, and splits into train and test sets.

    Returns:
        (X_train, X_test, y_train, y_test, raw_labels_train, raw_labels_test)
        where y is binary: 0 = BENIGN (Normal Baseline), 1 = ANOMALY
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset file not found at {csv_path}")

    df = pd.read_csv(csv_path)

    # Check that required features are present
    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required feature columns: {missing}")

    # Extract target label
    if "Label" not in df.columns:
        raise ValueError("Dataset does not contain 'Label' column")

    raw_labels = df["Label"].astype(str).str.strip()
    y_binary = (raw_labels != "BENIGN").astype(int)

    # Select only the exact 17 feature columns (excludes all labels, IPs, ports, and metadata)
    X = df[FEATURE_NAMES].copy()

    # Stratified train/test split to preserve attack distributions
    X_train, X_test, y_train, y_test, labels_train, labels_test = train_test_split(
        X,
        y_binary,
        raw_labels,
        test_size=test_size,
        random_state=random_state,
        stratify=raw_labels
    )

    return X_train, X_test, y_train, y_test, labels_train, labels_test
