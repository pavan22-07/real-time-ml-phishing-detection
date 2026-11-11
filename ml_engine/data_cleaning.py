"""
Data Cleaning Module for Phishing Detection.
Loads raw data, performs validation, removes duplicates and anomalies,
and outputs a cleaned dataset and report.
"""

import json
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd

from ml_engine.config import (
    RAW_DATASET_PATH,
    PROCESSED_DATA_DIR,
    PROCESSED_DATASET_PATH,
    ML_DATASET_PATH,
    REPORTS_DIR,
    PROJECT_ROOT
)
from ml_engine.dataset_loader import load_raw_dataset


def clean_dataset(raw_df: pd.DataFrame = None, export: bool = True) -> pd.DataFrame:
    """
    Clean the dataset:
    - Validate URL presence and format
    - Drop missing values
    - Remove duplicate URLs
    - Ensure binary label (0 = LEGITIMATE, 1 = PHISHING)
    - Output reports
    """
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if raw_df is None:
        raw_df = load_raw_dataset()

    initial_count = len(raw_df)
    print(f"[+] Starting data cleaning with {initial_count:,} raw records.")

    # Check required columns
    if "url" not in raw_df.columns or "label" not in raw_df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    # 1. Check missing values
    missing_urls = int(raw_df["url"].isnull().sum())
    missing_labels = int(raw_df["label"].isnull().sum())

    # Drop nulls in url or label
    df_clean = raw_df.dropna(subset=["url", "label"]).copy()

    # Ensure URL is string and trimmed
    df_clean["url"] = df_clean["url"].astype(str).str.strip()
    empty_urls = int((df_clean["url"] == "").sum())
    df_clean = df_clean[df_clean["url"] != ""].copy()

    # 2. Label normalization & validation
    # Ensure labels are binary integers {0, 1}
    df_clean["label"] = pd.to_numeric(df_clean["label"], errors="coerce")
    invalid_labels = int(df_clean["label"].isnull().sum())
    df_clean = df_clean.dropna(subset=["label"]).copy()
    df_clean["label"] = df_clean["label"].astype(int)

    unexpected_labels = int((~df_clean["label"].isin([0, 1])).sum())
    df_clean = df_clean[df_clean["label"].isin([0, 1])].copy()

    # 3. Check duplicate URLs
    duplicate_urls = int(df_clean["url"].duplicated().sum())
    # Check conflicting labels for same URL
    conflict_count = int((df_clean.groupby("url")["label"].nunique() > 1).sum())

    # Drop duplicate URLs keeping the first occurrence
    df_clean = df_clean.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    final_count = len(df_clean)

    # Class distribution
    legitimate_count = int((df_clean["label"] == 0).sum())
    phishing_count = int((df_clean["label"] == 1).sum())
    legitimate_ratio = float(legitimate_count / final_count) if final_count > 0 else 0.0
    phishing_ratio = float(phishing_count / final_count) if final_count > 0 else 0.0

    # Build report
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "initial_raw_records": initial_count,
        "final_cleaned_records": final_count,
        "removed_records": initial_count - final_count,
        "missing_urls": missing_urls,
        "missing_labels": missing_labels,
        "empty_urls": empty_urls,
        "invalid_labels": invalid_labels,
        "unexpected_labels": unexpected_labels,
        "duplicate_urls_removed": duplicate_urls,
        "conflicting_url_labels": conflict_count,
        "class_distribution": {
            "legitimate_0": {
                "count": legitimate_count,
                "percentage": round(legitimate_ratio * 100, 2)
            },
            "phishing_1": {
                "count": phishing_count,
                "percentage": round(phishing_ratio * 100, 2)
            }
        },
        "imbalance_ratio": round(legitimate_count / phishing_count, 2) if phishing_count > 0 else None
    }

    clean_export = df_clean[["url", "label"]]

    if export:
        report_path = REPORTS_DIR / "data_cleaning_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        clean_export.to_csv(ML_DATASET_PATH, index=False)
        clean_export.to_csv(PROCESSED_DATASET_PATH, index=False)

        print(f"[+] Cleaned dataset saved to:\n    - {ML_DATASET_PATH}\n    - {PROCESSED_DATASET_PATH}")
        print(f"[+] Cleaning report saved to: {report_path}")
        print(f"    Total records: {final_count:,} (Legitimate: {legitimate_count:,}, Phishing: {phishing_count:,})")
        print(f"    Class balance: {round(legitimate_ratio*100, 1)}% legitimate / {round(phishing_ratio*100, 1)}% phishing")

    return clean_export

    return clean_export


if __name__ == "__main__":
    clean_dataset()
