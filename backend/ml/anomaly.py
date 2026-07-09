"""Anomaly detection for security alerts using Isolation Forest.

Identifies unusual network traffic patterns that don't match known
attack categories — potential zero-day attacks or novel threats.
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Optional

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "trained_models")

# Subset of features most useful for anomaly detection
ANOMALY_FEATURES = [
    "dur", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sinpkt", "dinpkt", "tcprtt",
    "smean", "dmean", "ct_srv_src", "ct_dst_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm",
]


class AnomalyDetector:
    """Detects anomalous security alerts using Isolation Forest."""

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._load_model()

    def _load_model(self):
        """Load trained model from disk."""
        model_path = os.path.join(MODEL_DIR, "anomaly_detector.joblib")
        scaler_path = os.path.join(MODEL_DIR, "anomaly_scaler.joblib")

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            print("Loaded trained anomaly detection model.")
        else:
            print("No anomaly model found. Run `python -m ml.train` first.")

    def train(self, df: pd.DataFrame, contamination: float = 0.1):
        """Train the Isolation Forest on normal + attack traffic.

        Args:
            df: DataFrame with UNSW-NB15 features
            contamination: Expected proportion of anomalies (0.0-0.5)
        """
        print("Training Isolation Forest anomaly detector...")

        available = [f for f in ANOMALY_FEATURES if f in df.columns]
        X = df[available].fillna(0).values

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=150,
            contamination=contamination,
            max_samples="auto",
            n_jobs=-1,
            random_state=42,
        )
        self.model.fit(X_scaled)

        # Evaluate
        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        n_anomalies = (predictions == -1).sum()
        print(f"Detected {n_anomalies}/{len(X)} anomalies ({n_anomalies/len(X)*100:.1f}%)")
        print(f"Anomaly score range: [{scores.min():.4f}, {scores.max():.4f}]")

        self._save_model()

    def _save_model(self):
        """Save model to disk."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, os.path.join(MODEL_DIR, "anomaly_detector.joblib"))
        joblib.dump(self.scaler, os.path.join(MODEL_DIR, "anomaly_scaler.joblib"))
        print("Anomaly detection model saved.")

    def detect(self, features: dict) -> dict:
        """Check if a single alert is anomalous.

        Args:
            features: Dict of network features

        Returns:
            Dict with is_anomaly flag and anomaly_score
        """
        if self.model is None:
            return {"is_anomaly": False, "anomaly_score": 0.0}

        available = [f for f in ANOMALY_FEATURES if f in features]
        values = [features.get(f, 0) for f in ANOMALY_FEATURES]
        X = np.array([values])
        X_scaled = self.scaler.transform(X)

        prediction = self.model.predict(X_scaled)[0]
        score = float(self.model.decision_function(X_scaled)[0])

        return {
            "is_anomaly": prediction == -1,
            "anomaly_score": score,
        }

    def detect_batch(self, features_list: list[dict]) -> list[dict]:
        """Check anomaly status for a batch of alerts."""
        return [self.detect(f) for f in features_list]
