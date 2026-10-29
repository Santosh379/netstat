"""
Preprocessing pipeline for NetScope AI ML Feature Vectors.
Handles invalid values, infinities, NaNs, and schema alignment.
"""

from typing import Any, Optional
import numpy as np
import pandas as pd
from .schema import FEATURE_NAMES, SCHEMA_VERSION

class MLPreprocessor:
    def __init__(self):
        self.version = SCHEMA_VERSION
        self.feature_names = list(FEATURE_NAMES)
        self.feature_medians: dict[str, float] = {}
        self.fitted: bool = False

    def fit(self, X: pd.DataFrame) -> "MLPreprocessor":
        """
        Calculates medians and validation bounds from training data.
        """
        # Validate columns
        missing = [col for col in self.feature_names if col not in X.columns]
        if missing:
            raise ValueError(f"Training DataFrame is missing required feature columns: {missing}")

        cleaned = X[self.feature_names].replace([np.inf, -np.inf], np.nan)
        medians = cleaned.median(numeric_only=True).to_dict()
        self.feature_medians = {k: float(v) if not np.isnan(v) else 0.0 for k, v in medians.items()}
        self.fitted = True
        return self

    def transform_df(self, X: pd.DataFrame) -> np.ndarray:
        """
        Transforms a pandas DataFrame into a sanitized 2D numpy array matching FEATURE_NAMES.
        """
        missing = [col for col in self.feature_names if col not in X.columns]
        if missing:
            raise ValueError(f"Input DataFrame missing required feature columns: {missing}")

        data = X[self.feature_names].copy()
        data = data.replace([np.inf, -np.inf], np.nan)

        if self.fitted:
            data = data.fillna(self.feature_medians)
        else:
            data = data.fillna(0.0)

        # Clip values to non-negative where negative is physically impossible
        arr = data.to_numpy(dtype=np.float64)
        np.clip(arr, a_min=0.0, a_max=None, out=arr)
        return arr

    def transform_array(self, x: np.ndarray) -> np.ndarray:
        """
        Transforms a 1D or 2D feature array, replacing any NaNs or Infs.
        """
        arr = np.array(x, dtype=np.float64)
        if arr.ndim == 1:
            if len(arr) != len(self.feature_names):
                raise ValueError(f"Expected array of length {len(self.feature_names)}, got {len(arr)}")
            arr = arr.reshape(1, -1)
        elif arr.shape[1] != len(self.feature_names):
            raise ValueError(f"Expected array with {len(self.feature_names)} columns, got {arr.shape[1]}")

        # Replace infs and nans
        nan_mask = np.isnan(arr) | np.isinf(arr)
        if np.any(nan_mask):
            for i, name in enumerate(self.feature_names):
                default_val = self.feature_medians.get(name, 0.0)
                arr[:, i] = np.where(np.isnan(arr[:, i]) | np.isinf(arr[:, i]), default_val, arr[:, i])

        np.clip(arr, a_min=0.0, a_max=None, out=arr)
        return arr

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "feature_names": self.feature_names,
            "feature_medians": self.feature_medians,
            "fitted": self.fitted
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MLPreprocessor":
        pre = cls()
        pre.version = data.get("version", SCHEMA_VERSION)
        pre.feature_names = data.get("feature_names", list(FEATURE_NAMES))
        pre.feature_medians = data.get("feature_medians", {})
        pre.fitted = data.get("fitted", True)
        return pre
