"""Alert classifier using Random Forest trained on UNSW-NB15.

Classifies network traffic alerts into attack categories:
Normal, Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic,
Reconnaissance, Shellcode, Worms.
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score
from typing import Optional

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "trained_models")

# Features used for classification (numeric subset of UNSW-NB15)
NUMERIC_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb",
    "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean",
    "dmean", "trans_depth", "response_body_len", "ct_srv_src",
    "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login",
    "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst",
    "is_sm_ips_ports",
]

CATEGORICAL_FEATURES = ["proto", "service", "state"]

ATTACK_CATEGORIES = [
    "Normal", "Analysis", "Backdoor", "DoS", "Exploits",
    "Fuzzers", "Generic", "Reconnaissance", "Shellcode", "Worms",
]

# Severity mapping based on attack category
SEVERITY_MAP = {
    "Normal": "info",
    "Analysis": "low",
    "Fuzzers": "low",
    "Reconnaissance": "medium",
    "Generic": "medium",
    "DoS": "high",
    "Exploits": "high",
    "Backdoor": "critical",
    "Shellcode": "critical",
    "Worms": "critical",
}


class AlertClassifier:
    """Classifies security alerts by attack type and severity."""

    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.cat_encoders: dict[str, LabelEncoder] = {}
        self._load_model()

    def _load_model(self):
        """Load trained model from disk if available."""
        model_path = os.path.join(MODEL_DIR, "classifier.joblib")
        scaler_path = os.path.join(MODEL_DIR, "scaler.joblib")
        label_enc_path = os.path.join(MODEL_DIR, "label_encoder.joblib")
        cat_enc_path = os.path.join(MODEL_DIR, "cat_encoders.joblib")

        if all(os.path.exists(p) for p in [model_path, scaler_path, label_enc_path, cat_enc_path]):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoder = joblib.load(label_enc_path)
            self.cat_encoders = joblib.load(cat_enc_path)
            print("Loaded trained classifier model.")
        else:
            print("No trained model found. Run `python -m ml.train` first.")

    @staticmethod
    def preprocess_dataframe(df: pd.DataFrame, fit: bool = False,
                             scaler: Optional[StandardScaler] = None,
                             cat_encoders: Optional[dict] = None):
        """Preprocess a DataFrame for training or inference.

        Args:
            df: Raw DataFrame with UNSW-NB15 features
            fit: If True, fit scaler and encoders (training mode)
            scaler: Existing scaler for transform-only mode
            cat_encoders: Existing categorical encoders

        Returns:
            Tuple of (processed numpy array, scaler, cat_encoders)
        """
        df = df.copy()

        if scaler is None:
            scaler = StandardScaler()
        if cat_encoders is None:
            cat_encoders = {}

        # Encode categorical features
        for col in CATEGORICAL_FEATURES:
            if col in df.columns:
                if fit:
                    enc = LabelEncoder()
                    df[col] = enc.fit_transform(df[col].astype(str))
                    cat_encoders[col] = enc
                else:
                    enc = cat_encoders.get(col)
                    if enc:
                        # Handle unseen categories
                        df[col] = df[col].astype(str).apply(
                            lambda x: enc.transform([x])[0]
                            if x in enc.classes_
                            else -1
                        )
                    else:
                        df[col] = 0

        # Select features
        feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
        available_cols = [c for c in feature_cols if c in df.columns]
        X = df[available_cols].fillna(0).values

        # Scale
        if fit:
            X = scaler.fit_transform(X)
        else:
            X = scaler.transform(X)

        return X, scaler, cat_encoders

    def train(self, train_df: pd.DataFrame, test_df: Optional[pd.DataFrame] = None):
        """Train the classifier on UNSW-NB15 data.

        Args:
            train_df: Training DataFrame with 'attack_cat' column
            test_df: Optional test DataFrame for evaluation
        """
        print("Preprocessing training data...")
        self.label_encoder = LabelEncoder()
        y_train = self.label_encoder.fit_transform(
            train_df["attack_cat"].str.strip().fillna("Normal")
        )

        X_train, self.scaler, self.cat_encoders = self.preprocess_dataframe(
            train_df, fit=True
        )

        print(f"Training Random Forest on {len(X_train)} samples...")
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced",
        )
        self.model.fit(X_train, y_train)

        # Evaluate on training data
        train_pred = self.model.predict(X_train)
        train_acc = accuracy_score(y_train, train_pred)
        print(f"Training accuracy: {train_acc:.4f}")

        # Evaluate on test data if provided
        if test_df is not None:
            y_test = self.label_encoder.transform(
                test_df["attack_cat"].str.strip().fillna("Normal")
            )
            X_test, _, _ = self.preprocess_dataframe(
                test_df, fit=False,
                scaler=self.scaler,
                cat_encoders=self.cat_encoders
            )
            test_pred = self.model.predict(X_test)
            test_acc = accuracy_score(y_test, test_pred)
            print(f"\nTest accuracy: {test_acc:.4f}")
            print("\nClassification Report:")
            print(classification_report(
                y_test, test_pred,
                target_names=self.label_encoder.classes_
            ))

        # Save model
        self._save_model()

    def _save_model(self):
        """Save trained model artifacts to disk."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, os.path.join(MODEL_DIR, "classifier.joblib"))
        joblib.dump(self.scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
        joblib.dump(self.label_encoder, os.path.join(MODEL_DIR, "label_encoder.joblib"))
        joblib.dump(self.cat_encoders, os.path.join(MODEL_DIR, "cat_encoders.joblib"))
        print(f"Model saved to {MODEL_DIR}/")

    def classify(self, features: dict) -> dict:
        """Classify a single alert.

        Args:
            features: Dict of alert features matching UNSW-NB15 schema

        Returns:
            Dict with attack_category, severity, confidence, probabilities
        """
        if self.model is None:
            return self._fallback_classify(features)

        df = pd.DataFrame([features])
        X, _, _ = self.preprocess_dataframe(
            df, fit=False,
            scaler=self.scaler,
            cat_encoders=self.cat_encoders
        )

        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = float(np.max(probabilities))

        attack_cat = self.label_encoder.inverse_transform([prediction])[0]
        severity = SEVERITY_MAP.get(attack_cat, "medium")

        # Build probability breakdown
        prob_breakdown = {
            cat: float(prob)
            for cat, prob in zip(self.label_encoder.classes_, probabilities)
        }

        return {
            "attack_category": attack_cat,
            "severity": severity,
            "confidence": confidence,
            "probabilities": prob_breakdown,
        }

    def classify_batch(self, features_list: list[dict]) -> list[dict]:
        """Classify a batch of alerts."""
        return [self.classify(f) for f in features_list]

    def _fallback_classify(self, features: dict) -> dict:
        """Rule-based fallback when no trained model is available."""
        sbytes = features.get("sbytes", 0)
        rate = features.get("rate", 0)
        sttl = features.get("sttl", 64)
        ct_dst_src_ltm = features.get("ct_dst_src_ltm", 0)

        # Simple heuristic rules
        if rate > 1000 and sbytes > 50000:
            return {"attack_category": "DoS", "severity": "high", "confidence": 0.6, "probabilities": {}}
        elif sttl < 20 and ct_dst_src_ltm > 50:
            return {"attack_category": "Reconnaissance", "severity": "medium", "confidence": 0.5, "probabilities": {}}
        elif sbytes > 100000:
            return {"attack_category": "Exploits", "severity": "high", "confidence": 0.4, "probabilities": {}}
        else:
            return {"attack_category": "Normal", "severity": "info", "confidence": 0.7, "probabilities": {}}
