"""
Unit tests for Model Training and Artifact Management.
"""

import unittest
import tempfile
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

from ml_engine.config import (
    BEST_MODEL_PATH,
    MODEL_METADATA_PATH,
    FEATURE_SCHEMA_PATH,
    LOGISTIC_REGRESSION_CONFIG,
    DECISION_TREE_CONFIG,
    RANDOM_FOREST_CONFIG
)
from ml_engine.feature_extraction import FEATURE_NAMES
from ml_engine.model_manager import save_model_artifact, load_model_artifact


class TrainingTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Create small synthetic feature matrix for rapid training verification."""
        np.random.seed(42)
        n_samples = 150
        cls.X = pd.DataFrame(np.random.randn(n_samples, len(FEATURE_NAMES)), columns=FEATURE_NAMES)
        cls.y = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])

    def test_logistic_regression_pipeline(self):
        """Verify Logistic Regression trains and predicts probabilities."""
        pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(**LOGISTIC_REGRESSION_CONFIG))
        ])
        pipe.fit(self.X, self.y)
        preds = pipe.predict(self.X)
        probas = pipe.predict_proba(self.X)

        self.assertEqual(len(preds), len(self.y))
        self.assertEqual(probas.shape, (len(self.y), 2))
        self.assertTrue(np.allclose(probas.sum(axis=1), 1.0))

    def test_decision_tree_pipeline(self):
        """Verify Decision Tree trains and yields feature importances."""
        pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", DecisionTreeClassifier(**DECISION_TREE_CONFIG))
        ])
        pipe.fit(self.X, self.y)
        clf = pipe.named_steps["classifier"]
        self.assertEqual(len(clf.feature_importances_), len(FEATURE_NAMES))
        self.assertAlmostEqual(clf.feature_importances_.sum(), 1.0, places=4)

    def test_random_forest_pipeline(self):
        """Verify Random Forest trains and outputs valid probabilities."""
        pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(**RANDOM_FOREST_CONFIG))
        ])
        pipe.fit(self.X, self.y)
        probas = pipe.predict_proba(self.X)
        self.assertEqual(probas.shape, (len(self.y), 2))

    def test_model_artifact_save_and_load(self):
        """Verify joblib serialization and deserialization integrity."""
        pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", DecisionTreeClassifier(max_depth=3, random_state=42))
        ])
        pipe.fit(self.X, self.y)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            model_file = tmp_path / "test_model.joblib"
            meta_file = tmp_path / "test_meta.json"
            schema_file = tmp_path / "test_schema.json"

            sample_meta = {
                "model_name": "TestDecisionTree",
                "model_version": "0.1.0",
                "random_seed": 42
            }

            save_model_artifact(
                pipeline=pipe,
                metadata=sample_meta,
                feature_schema=FEATURE_NAMES,
                model_path=model_file,
                metadata_path=meta_file,
                schema_path=schema_file
            )

            loaded_pipe, loaded_meta, loaded_schema = load_model_artifact(
                model_path=model_file,
                metadata_path=meta_file,
                schema_path=schema_file
            )

            self.assertEqual(loaded_meta["model_name"], "TestDecisionTree")
            self.assertEqual(len(loaded_schema), len(FEATURE_NAMES))

            # Verify predictions match exactly
            orig_preds = pipe.predict(self.X)
            loaded_preds = loaded_pipe.predict(self.X)
            np.testing.assert_array_equal(orig_preds, loaded_preds)

    def test_production_model_artifact_exists(self):
        """Verify that the production trained model artifact exists on disk."""
        self.assertTrue(BEST_MODEL_PATH.exists(), f"Artifact missing at {BEST_MODEL_PATH}")
        self.assertTrue(MODEL_METADATA_PATH.exists())
        self.assertTrue(FEATURE_SCHEMA_PATH.exists())


if __name__ == "__main__":
    unittest.main()
