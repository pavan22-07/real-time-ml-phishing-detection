"""
Preprocessing and Data Leakage Prevention Module.
Extracts features across the cleaned dataset, implements domain-aware grouped splitting,
and constructs reproducible sklearn transformers.
"""

import json
from pathlib import Path
from typing import Tuple, Dict, Any, List
import pandas as pd
import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from ml_engine.config import (
    ML_DATASET_PATH,
    PROCESSED_DATA_DIR,
    REPORTS_DIR,
    FEATURES_DATASET_PATH,
    RANDOM_SEED,
    TRAIN_RATIO,
    VAL_RATIO,
    TEST_RATIO
)
from ml_engine.feature_extraction import (
    extract_features_with_metadata,
    FEATURE_NAMES
)


def extract_dataset_features(df: pd.DataFrame = None) -> pd.DataFrame:
    """
    Extract features for all URLs in the dataset.
    Saves to data/processed/extracted_features.csv.
    """
    if df is None:
        if not ML_DATASET_PATH.exists():
            from ml_engine.data_cleaning import clean_dataset
            df = clean_dataset()
        else:
            df = pd.read_csv(ML_DATASET_PATH)

    print(f"[+] Extracting features for {len(df):,} URLs...")
    feature_records = []
    registered_domains = []

    for url in df["url"]:
        feats, meta = extract_features_with_metadata(url)
        feature_records.append(feats)
        registered_domains.append(meta["registered_domain"])

    features_df = pd.DataFrame(feature_records, columns=FEATURE_NAMES)
    features_df["url"] = df["url"].values
    features_df["label"] = df["label"].values
    features_df["registered_domain"] = registered_domains

    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    features_df.to_csv(FEATURES_DATASET_PATH, index=False)
    print(f"[+] Feature extraction complete. Saved to: {FEATURES_DATASET_PATH}")
    return features_df


def perform_domain_aware_split(
    df: pd.DataFrame,
    random_seed: int = RANDOM_SEED,
    export: bool = True
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """
    Perform a domain-aware grouped split:
    - Train: 70%
    - Validation: 15%
    - Test: 15%
    Grouped by `registered_domain` to ensure URLs from the same registered domain
    never leak across train, validation, and test splits.
    """
    print("[+] Performing domain-aware grouped split by registered_domain...")

    # First split: Train (70%) vs Temp (30%)
    temp_ratio = VAL_RATIO + TEST_RATIO  # 0.30
    gss_train_temp = GroupShuffleSplit(
        n_splits=1,
        test_size=temp_ratio,
        random_state=random_seed
    )

    train_idx, temp_idx = next(gss_train_temp.split(df, groups=df["registered_domain"]))
    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    temp_df = df.iloc[temp_idx].copy().reset_index(drop=True)

    # Second split: Validation (15% of total = 50% of temp) vs Test (15% of total = 50% of temp)
    gss_val_test = GroupShuffleSplit(
        n_splits=1,
        test_size=0.50,
        random_state=random_seed
    )

    val_sub_idx, test_sub_idx = next(gss_val_test.split(temp_df, groups=temp_df["registered_domain"]))
    val_df = temp_df.iloc[val_sub_idx].copy().reset_index(drop=True)
    test_df = temp_df.iloc[test_sub_idx].copy().reset_index(drop=True)

    # Validate zero domain leakage
    train_domains = set(train_df["registered_domain"])
    val_domains = set(val_df["registered_domain"])
    test_domains = set(test_df["registered_domain"])

    train_val_overlap = train_domains.intersection(val_domains)
    train_test_overlap = train_domains.intersection(test_domains)
    val_test_overlap = val_domains.intersection(test_domains)

    leakage_detected = bool(train_val_overlap or train_test_overlap or val_test_overlap)
    if leakage_detected:
        raise ValueError("CRITICAL ERROR: Domain leakage detected across splits!")

    split_stats = {
        "total_records": len(df),
        "train": {
            "count": len(train_df),
            "percentage": round(len(train_df) / len(df) * 100, 2),
            "legitimate": int((train_df["label"] == 0).sum()),
            "phishing": int((train_df["label"] == 1).sum()),
            "phishing_ratio": round(float((train_df["label"] == 1).mean()), 4),
            "unique_domains": len(train_domains)
        },
        "validation": {
            "count": len(val_df),
            "percentage": round(len(val_df) / len(df) * 100, 2),
            "legitimate": int((val_df["label"] == 0).sum()),
            "phishing": int((val_df["label"] == 1).sum()),
            "phishing_ratio": round(float((val_df["label"] == 1).mean()), 4),
            "unique_domains": len(val_domains)
        },
        "test": {
            "count": len(test_df),
            "percentage": round(len(test_df) / len(df) * 100, 2),
            "legitimate": int((test_df["label"] == 0).sum()),
            "phishing": int((test_df["label"] == 1).sum()),
            "phishing_ratio": round(float((test_df["label"] == 1).mean()), 4),
            "unique_domains": len(test_domains)
        },
        "leakage_verification": {
            "train_val_domain_overlap": len(train_val_overlap),
            "train_test_domain_overlap": len(train_test_overlap),
            "val_test_domain_overlap": len(val_test_overlap),
            "is_zero_leakage": not leakage_detected
        }
    }

    if export:
        # Save split files
        train_path = PROCESSED_DATA_DIR / "train.csv"
        val_path = PROCESSED_DATA_DIR / "val.csv"
        test_path = PROCESSED_DATA_DIR / "test.csv"
        split_report_path = REPORTS_DIR / "data_split_report.json"

        train_df.to_csv(train_path, index=False)
        val_df.to_csv(val_path, index=False)
        test_df.to_csv(test_path, index=False)

        with open(split_report_path, "w", encoding="utf-8") as f:
            json.dump(split_stats, f, indent=4)

        print(f"[+] Domain-aware splits saved to:\n    - {train_path}\n    - {val_path}\n    - {test_path}")
        print(f"[+] Split report saved to: {split_report_path}")
        print(f"    Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,}")
        print(f"    Domain leakage check: Zero overlap confirmed ({not leakage_detected})")

    return train_df, val_df, test_df, split_stats


def create_preprocessing_pipeline() -> Pipeline:
    """
    Create a reusable scikit-learn preprocessing pipeline.
    Imputes any missing values with median and scales numerical features.
    """
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])
    return pipeline


def prepare_datasets(force_recompute: bool = False):
    """
    High-level entrypoint to extract features and generate splits.
    """
    if not FEATURES_DATASET_PATH.exists() or force_recompute:
        df = extract_dataset_features()
    else:
        print(f"[+] Loading existing extracted features from: {FEATURES_DATASET_PATH}")
        df = pd.read_csv(FEATURES_DATASET_PATH)

    train_df, val_df, test_df, stats = perform_domain_aware_split(df)
    return train_df, val_df, test_df, stats


if __name__ == "__main__":
    prepare_datasets()
