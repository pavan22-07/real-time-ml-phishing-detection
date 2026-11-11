"""
Unit tests for Dataset Loading and Cleaning.
"""

import unittest
from pathlib import Path
import tempfile
import pandas as pd

from ml_engine.config import (
    RAW_DATASET_PATH,
    ML_DATASET_PATH,
    DATASET_METADATA_PATH
)
from ml_engine.dataset_loader import load_raw_dataset, compute_sha256
from ml_engine.data_cleaning import clean_dataset


class DatasetTests(unittest.TestCase):

    def test_raw_dataset_exists_and_readable(self):
        """Verify the raw dataset is present, non-empty, and valid CSV."""
        self.assertTrue(RAW_DATASET_PATH.exists(), f"Raw dataset missing at {RAW_DATASET_PATH}")
        df = load_raw_dataset(nrows=100)
        self.assertGreater(len(df), 0)
        self.assertIn("url", df.columns)
        self.assertIn("label", df.columns)

    def test_dataset_metadata_integrity(self):
        """Verify dataset metadata JSON contains required provenance fields."""
        self.assertTrue(DATASET_METADATA_PATH.exists())
        import json
        with open(DATASET_METADATA_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertIn("dataset_name", meta)
        self.assertIn("doi", meta)
        self.assertIn("licence", meta)
        self.assertIn("sha256", meta)
        self.assertTrue(meta.get("integrity_verified"))

    def test_missing_required_columns_raises_error(self):
        """Verify cleaning raises ValueError when required columns are absent."""
        invalid_df = pd.DataFrame({"link": ["https://example.com"], "target": [0]})
        with self.assertRaises(ValueError):
            clean_dataset(raw_df=invalid_df, export=False)

    def test_label_normalization(self):
        """Verify labels are strictly normalized into integers 0 and 1."""
        test_df = pd.DataFrame({
            "url": ["https://example1.com", "https://example2.com", "https://example3.com"],
            "label": ["0", 1.0, 0]
        })
        cleaned = clean_dataset(raw_df=test_df, export=False)
        self.assertTrue(all(cleaned["label"].isin([0, 1])))
        self.assertEqual(cleaned["label"].dtype, int)

    def test_duplicate_removal(self):
        """Verify duplicate URLs are detected and removed."""
        test_df = pd.DataFrame({
            "url": ["https://dup.com", "https://dup.com", "https://unique.com"],
            "label": [0, 0, 1]
        })
        cleaned = clean_dataset(raw_df=test_df, export=False)
        self.assertEqual(len(cleaned), 2)
        self.assertEqual(cleaned["url"].tolist(), ["https://dup.com", "https://unique.com"])

    def test_empty_and_null_urls_removal(self):
        """Verify null and empty whitespace URLs are dropped."""
        test_df = pd.DataFrame({
            "url": ["https://valid.com", None, "   ", "https://valid2.com"],
            "label": [0, 1, 0, 1]
        })
        cleaned = clean_dataset(raw_df=test_df, export=False)
        self.assertEqual(len(cleaned), 2)

    def test_class_distribution_in_ml_dataset(self):
        """Verify ML dataset contains both legitimate and phishing samples."""
        self.assertTrue(ML_DATASET_PATH.exists())
        df = pd.read_csv(ML_DATASET_PATH)
        labels = set(df["label"].unique())
        self.assertEqual(labels, {0, 1})
        self.assertGreater((df["label"] == 0).sum(), 1000)
        self.assertGreater((df["label"] == 1).sum(), 1000)


if __name__ == "__main__":
    unittest.main()
