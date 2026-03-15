"""
Phase 2 — Anomaly Detection Engine.

Detects unusual patterns in security scan results using:
  - IsolationForest ML model (scikit-learn) when available
  - Z-score statistical baseline when sklearn is absent

Usage::

    from .anomaly_detector import detect_anomaly, fit_global_baseline

    fit_global_baseline(historical_scan_list)
    result = detect_anomaly(new_scan_record)
"""
from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_SKLEARN_AVAILABLE = False
try:
    from sklearn.ensemble import IsolationForest  # type: ignore[import-not-found]
    import numpy as np  # type: ignore[import-not-found]
    _SKLEARN_AVAILABLE = True
except Exception:
    pass

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_FEATURE_NAMES = [
    "total_findings",
    "critical_count",
    "high_count",
    "weighted_severity_sum",
    "risk_score",
    "duration_seconds",
    "unique_categories",
    "findings_per_minute",
]


def _extract_features(record: Dict[str, Any]) -> List[float]:
    """
    Convert a scan record into a fixed-length numeric feature vector.

    Expected optional keys in record:
        findings (list), risk_score (int), duration_seconds (int)
    """
    findings: List[Dict[str, Any]] = record.get("findings", [])
    total = float(len(findings))
    critical = float(sum(1 for f in findings if f.get("severity") == "critical"))
    high = float(sum(1 for f in findings if f.get("severity") == "high"))
    weighted = float(sum(_SEVERITY_WEIGHT.get(f.get("severity", "info"), 0) for f in findings))
    risk = float(record.get("risk_score", 0))
    duration = float(max(1, record.get("duration_seconds", 60)))
    categories = float(len({f.get("category", "") for f in findings}))
    rate = (total / duration) * 60  # findings per minute
    return [total, critical, high, weighted, risk, duration, categories, rate]


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Dual-mode anomaly detector (IsolationForest + z-score fallback).

    Train on historical scan data with fit(), then score new records with score().
    """

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self._model: Optional[Any] = None
        self._baseline: Dict[str, List[float]] = {"mean": [0.0] * 8, "std": [1.0] * 8}
        self._fitted = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, scans: List[Dict[str, Any]]) -> None:
        """
        Train on a list of historical scan records.

        Falls back to z-score statistics when sklearn is absent or sample
        count < 5 (IsolationForest needs enough samples).
        """
        feature_matrix = [_extract_features(s) for s in scans]

        if _SKLEARN_AVAILABLE and len(feature_matrix) >= 5:
            X = np.array(feature_matrix, dtype=float)
            self._model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
                max_samples="auto",
            )
            self._model.fit(X)
            # Also compute stats for feature-level anomaly explanation
            self._baseline = self._compute_stats(feature_matrix)
            self._fitted = True
            logger.info("AnomalyDetector fitted (IsolationForest) on %d samples", len(feature_matrix))
        else:
            self._fit_zscore(feature_matrix)

    def _fit_zscore(self, feature_matrix: List[List[float]]) -> None:
        self._baseline = self._compute_stats(feature_matrix)
        self._fitted = True
        logger.info("AnomalyDetector fitted (z-score) on %d samples", len(feature_matrix))

    @staticmethod
    def _compute_stats(matrix: List[List[float]]) -> Dict[str, List[float]]:
        if not matrix:
            dim = len(_FEATURE_NAMES)
            return {"mean": [0.0] * dim, "std": [1.0] * dim}
        n = len(matrix)
        dim = len(matrix[0])
        means = [sum(row[i] for row in matrix) / n for i in range(dim)]
        stds: List[float] = []
        for i in range(dim):
            variance = sum((row[i] - means[i]) ** 2 for row in matrix) / max(1, n - 1)
            stds.append(math.sqrt(variance) or 1.0)
        return {"mean": means, "std": stds}

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a single scan record for anomalousness.

        Returns dict with:
            - anomaly_score (float): more positive = more normal (IForest) or z-score
            - is_anomaly (bool)
            - confidence (float 0..1)
            - anomalous_features (list[str])
            - explanation (str)
            - method (str)
        """
        if not self._fitted:
            return self._not_fitted_result()

        features = _extract_features(record)

        if _SKLEARN_AVAILABLE and self._model is not None:
            return self._score_iforest(features)
        else:
            return self._score_zscore(features)

    def _score_iforest(self, features: List[float]) -> Dict[str, Any]:
        X = np.array([features], dtype=float)
        raw = float(self._model.decision_function(X)[0])  # type: ignore[index]
        label = int(self._model.predict(X)[0])  # type: ignore[index]
        is_anomaly = label == -1
        # decision_function: negative → anomalous; normalise to confidence 0-1
        confidence = float(min(1.0, max(0.0, -raw + 0.3)))
        anomalous = self._anomalous_features(features)
        return {
            "anomaly_score": round(raw, 4),
            "is_anomaly": is_anomaly,
            "confidence": round(confidence, 4),
            "anomalous_features": anomalous,
            "explanation": self._explain(is_anomaly, anomalous, features),
            "method": "isolation_forest",
        }

    def _score_zscore(self, features: List[float]) -> Dict[str, Any]:
        mean = self._baseline["mean"]
        std = self._baseline["std"]
        z_scores = [(features[i] - mean[i]) / std[i] for i in range(len(features))]
        max_z = max(abs(z) for z in z_scores)
        is_anomaly = max_z > 3.0
        confidence = float(min(1.0, max_z / 6.0))
        anomalous = [_FEATURE_NAMES[i] for i, z in enumerate(z_scores) if abs(z) > 2.0]
        return {
            "anomaly_score": round(max_z, 4),
            "is_anomaly": is_anomaly,
            "confidence": round(confidence, 4),
            "anomalous_features": anomalous,
            "explanation": self._explain(is_anomaly, anomalous, features),
            "method": "z_score",
        }

    def _anomalous_features(self, features: List[float]) -> List[str]:
        mean = self._baseline["mean"]
        std = self._baseline["std"]
        return [
            _FEATURE_NAMES[i]
            for i in range(len(features))
            if std[i] > 0 and abs(features[i] - mean[i]) / std[i] > 2.0
        ]

    @staticmethod
    def _explain(
        is_anomaly: bool,
        anomalous: List[str],
        features: List[float],
    ) -> str:
        if not is_anomaly:
            return "Scan results are within normal baseline parameters."
        feat_map = dict(zip(_FEATURE_NAMES, features))
        parts: List[str] = []
        if "critical_count" in anomalous:
            parts.append(f"critical findings spike ({int(feat_map['critical_count'])})")
        if "findings_per_minute" in anomalous:
            parts.append(f"abnormal finding rate ({feat_map['findings_per_minute']:.1f}/min)")
        if "total_findings" in anomalous:
            parts.append(f"total finding volume ({int(feat_map['total_findings'])}) exceeds baseline")
        if "unique_categories" in anomalous:
            parts.append(f"unusually wide attack surface ({int(feat_map['unique_categories'])} categories)")
        if "weighted_severity_sum" in anomalous:
            parts.append(f"elevated severity weighted score ({int(feat_map['weighted_severity_sum'])})")
        if not parts:
            parts = ["multi-dimensional statistical deviation from baseline"]
        return "⚠ ANOMALY DETECTED: " + "; ".join(parts) + ". Immediate investigation recommended."

    @staticmethod
    def _not_fitted_result() -> Dict[str, Any]:
        return {
            "anomaly_score": 0.0,
            "is_anomaly": False,
            "confidence": 0.0,
            "anomalous_features": [],
            "explanation": "Detector not fitted. Call fit() with baseline historical data first.",
            "method": "unfitted",
        }


# ---------------------------------------------------------------------------
# Module-level singleton (lazy baseline)
# ---------------------------------------------------------------------------

_global_detector = AnomalyDetector()
_baseline_loaded = False


def fit_global_baseline(scans: List[Dict[str, Any]]) -> None:
    """Fit the module-level global detector on historical scan records."""
    global _baseline_loaded
    _global_detector.fit(scans)
    _baseline_loaded = True


def detect_anomaly(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score a single scan record using the global detector.

    Auto-fits on the single record (z-score only) if no baseline has been loaded.
    """
    if not _baseline_loaded:
        _global_detector.fit([record])
    return _global_detector.score(record)


def batch_detect(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Score all records.  If no baseline loaded, fits on the first N-1 records.
    """
    global _baseline_loaded
    if not _baseline_loaded and len(records) >= 2:
        _global_detector.fit(records[:-1])
        _baseline_loaded = True
    return [
        {"scan_id": r.get("id", ""), **_global_detector.score(r)}
        for r in records
    ]
