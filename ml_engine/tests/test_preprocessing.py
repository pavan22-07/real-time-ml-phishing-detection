"""
Unit tests for Preprocessing, Pipeline Transformers, and Data Leakage Prevention.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
import pandas as pd

import ml_engine.preprocessing as prep_module
from ml_engine.config import PROCESSED_DATA_DIR, REPORTS_DIR
from ml_engine.dataset_loader import compute_sha256
from ml_engine.preprocessing import (
    create_preprocessing_pipeline,
    perform_domain_aware_split
)
from ml_engine.feature_extraction import FEATURE_NAMES


class PreprocessingTests(unittest.TestCase):

    def test_imputation_and_scaling(self):
        """Verify SimpleImputer and StandardScaler operate without error on missing values."""
        pipeline = create_preprocessing_pipeline()
        X_sample = pd.DataFrame({
            "f1": [1.0, np.nan, 3.0, 4.0],
            "f2": [10.0, 20.0, 30.0, 40.0]
        })
        transformed = pipeline.fit_transform(X_sample)
        self.assertEqual(transformed.shape, (4, 2))
        self.assertFalse(np.isnan(transformed).any())

    def test_domain_aware_split_zero_leakage(self):
        """Verify domain-aware splitting guarantees zero domain overlap between train, val, and test."""
        # Synthetic domain dataset
        data = {
            "url": [f"https://domain{i}.com/page{j}" for i in range(20) for j in range(5)],
            "registered_domain": [f"domain{i}.com" for i in range(20) for j in range(5)],
            "label": [i % 2 for i in range(20) for _ in range(5)]
        }
        for name in FEATURE_NAMES:
            data[name] = np.random.rand(100)

        df = pd.DataFrame(data)
        train_df, val_df, test_df, stats = perform_domain_aware_split(df, random_seed=42, export=False)

        train_domains = set(train_df["registered_domain"])
        val_domains = set(val_df["registered_domain"])
        test_domains = set(test_df["registered_domain"])

        self.assertEqual(len(train_domains.intersection(val_domains)), 0)
        self.assertEqual(len(train_domains.intersection(test_domains)), 0)
        self.assertEqual(len(val_domains.intersection(test_domains)), 0)
        self.assertTrue(stats["leakage_verification"]["is_zero_leakage"])

    def test_split_reproducibility(self):
        """Verify fixed random seed produces identical splits."""
        data = {
            "url": [f"https://domain{i}.com/page" for i in range(30)],
            "registered_domain": [f"domain{i}.com" for i in range(30)],
            "label": [i % 2 for i in range(30)]
        }
        for name in FEATURE_NAMES:
            data[name] = np.random.rand(30)

        df = pd.DataFrame(data)
        train1, val1, test1, _ = perform_domain_aware_split(df, random_seed=42, export=False)
        train2, val2, test2, _ = perform_domain_aware_split(df, random_seed=42, export=False)

        self.assertEqual(train1["url"].tolist(), train2["url"].tolist())
        self.assertEqual(val1["url"].tolist(), val2["url"].tolist())
        self.assertEqual(test1["url"].tolist(), test2["url"].tolist())

    def test_production_splits_not_overwritten_and_isolated_export(self):
        """
        Regression test: running preprocessing tests must never modify production
        train/val/test CSVs or split reports, and production splits remain full size.
        """
        prod_files = [
            PROCESSED_DATA_DIR / "train.csv",
            PROCESSED_DATA_DIR / "val.csv",
            PROCESSED_DATA_DIR / "test.csv",
            REPORTS_DIR / "data_split_report.json",
        ]
        before_hashes = {p: compute_sha256(p) for p in prod_files if p.exists()}
        self.assertEqual(len(before_hashes), 4, "Production split files must exist before test.")

        data = {
            "url": [f"https://iso{i}.com/page" for i in range(20)],
            "registered_domain": [f"iso{i}.com" for i in range(20)],
            "label": [i % 2 for i in range(20)]
        }
        for name in FEATURE_NAMES:
            data[name] = np.random.rand(20)
        df = pd.DataFrame(data)

        # 1. Non-export split
        perform_domain_aware_split(df, random_seed=42, export=False)

        # 2. Isolated export split in temporary directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_proc = Path(tmp_dir) / "processed"
            tmp_rep = Path(tmp_dir) / "reports"
            tmp_proc.mkdir(parents=True, exist_ok=True)
            tmp_rep.mkdir(parents=True, exist_ok=True)
            with patch.object(prep_module, "PROCESSED_DATA_DIR", tmp_proc), \
                 patch.object(prep_module, "REPORTS_DIR", tmp_rep):
                perform_domain_aware_split(df, random_seed=42, export=True)
            self.assertTrue((tmp_proc / "train.csv").exists())
            self.assertTrue((tmp_rep / "data_split_report.json").exists())

        after_hashes = {p: compute_sha256(p) for p in prod_files}
        self.assertEqual(before_hashes, after_hashes, "Production split files were modified by tests!")

        # Verify full 115,231-row split counts remain intact
        with open(PROCESSED_DATA_DIR / "train.csv", encoding="utf-8") as f:
            train_len = sum(1 for _ in f) - 1
        with open(PROCESSED_DATA_DIR / "val.csv", encoding="utf-8") as f:
            val_len = sum(1 for _ in f) - 1
        with open(PROCESSED_DATA_DIR / "test.csv", encoding="utf-8") as f:
            test_len = sum(1 for _ in f) - 1
        self.assertEqual(train_len + val_len + test_len, 115231)


if __name__ == "__main__":
    unittest.main()
