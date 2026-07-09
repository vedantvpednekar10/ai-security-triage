"""Training pipeline for the Security Alert Triage system.

Downloads the UNSW-NB15 dataset and trains:
1. Random Forest classifier (attack type classification)
2. Isolation Forest (anomaly detection)

Usage:
    python -m ml.train
"""

import os
import sys
import pandas as pd
import requests
from io import BytesIO

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ml.classifier import AlertClassifier
from ml.anomaly import AnomalyDetector

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

# UNSW-NB15 dataset URLs (hosted on the research group's GitHub)
UNSW_TRAIN_URL = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_training-set.csv"
UNSW_TEST_URL = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv"


def download_dataset():
    """Download UNSW-NB15 training and testing sets."""
    os.makedirs(DATA_DIR, exist_ok=True)

    train_path = os.path.join(DATA_DIR, "UNSW_NB15_training-set.csv")
    test_path = os.path.join(DATA_DIR, "UNSW_NB15_testing-set.csv")

    if os.path.exists(train_path) and os.path.exists(test_path):
        print("Dataset files already exist. Skipping download.")
        return train_path, test_path

    print("Downloading UNSW-NB15 training set...")
    resp = requests.get(UNSW_TRAIN_URL, timeout=120)
    resp.raise_for_status()
    with open(train_path, "wb") as f:
        f.write(resp.content)
    print(f"  Saved to {train_path}")

    print("Downloading UNSW-NB15 testing set...")
    resp = requests.get(UNSW_TEST_URL, timeout=120)
    resp.raise_for_status()
    with open(test_path, "wb") as f:
        f.write(resp.content)
    print(f"  Saved to {test_path}")

    return train_path, test_path


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and preprocess the raw UNSW-NB15 DataFrame."""
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Strip whitespace from attack_cat
    if "attack_cat" in df.columns:
        df["attack_cat"] = df["attack_cat"].str.strip().fillna("Normal")
        # Normalize empty strings
        df.loc[df["attack_cat"] == "", "attack_cat"] = "Normal"

    # Drop the 'id' column if present (it's just a row index)
    if "id" in df.columns:
        df = df.drop(columns=["id"])

    # Fill NaN in numeric columns with 0
    numeric_cols = df.select_dtypes(include=["number"]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)

    # Fill NaN in string columns with "-"
    str_cols = df.select_dtypes(include=["object"]).columns
    df[str_cols] = df[str_cols].fillna("-")

    return df


def main():
    """Main training pipeline."""
    print("=" * 60)
    print("Security Alert Triage - Model Training Pipeline")
    print("=" * 60)

    # Step 1: Download data
    print("\n[1/4] Downloading UNSW-NB15 dataset...")
    try:
        train_path, test_path = download_dataset()
    except Exception as e:
        print(f"\nFailed to download dataset: {e}")
        print("\nManual download instructions:")
        print(f"  1. Download training set from: {UNSW_TRAIN_URL}")
        print(f"  2. Download testing set from:  {UNSW_TEST_URL}")
        print(f"  3. Save both to: {DATA_DIR}/")
        print("  4. Re-run this script.")
        sys.exit(1)

    # Step 2: Load and clean data
    print("\n[2/4] Loading and cleaning data...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    train_df = clean_dataset(train_df)
    test_df = clean_dataset(test_df)

    print(f"  Training set: {len(train_df)} records")
    print(f"  Testing set:  {len(test_df)} records")
    print(f"  Attack categories: {train_df['attack_cat'].nunique()}")
    print(f"\n  Category distribution (train):")
    for cat, count in train_df["attack_cat"].value_counts().items():
        print(f"    {cat:20s}: {count:6d} ({count/len(train_df)*100:.1f}%)")

    # Step 3: Train classifier
    print("\n[3/4] Training attack classifier...")
    classifier = AlertClassifier.__new__(AlertClassifier)
    classifier.model = None
    classifier.scaler = None
    classifier.label_encoder = None
    classifier.cat_encoders = {}
    classifier.train(train_df, test_df)

    # Step 4: Train anomaly detector
    print("\n[4/4] Training anomaly detector...")
    anomaly_detector = AnomalyDetector.__new__(AnomalyDetector)
    anomaly_detector.model = None
    anomaly_detector.scaler = None
    anomaly_detector.train(train_df, contamination=0.1)

    print("\n" + "=" * 60)
    print("Training complete!")
    print(f"Models saved to: {os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'trained_models'))}")
    print("=" * 60)


if __name__ == "__main__":
    main()
