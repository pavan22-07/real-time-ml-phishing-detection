"""
Real-Time URL Prediction Module for Phishing Detection.
Loads the trained model artifact, extracts static URL features, and outputs
phishing and legitimate probabilities in a standardized JSON-compatible structure.
"""

import sys
import json
from typing import Dict, Any, Optional
import pandas as pd

from ml_engine.config import (
    BEST_MODEL_PATH,
    MODEL_METADATA_PATH,
    FEATURE_SCHEMA_PATH
)
from ml_engine.feature_extraction import (
    extract_features_from_url,
    FEATURE_NAMES
)
from ml_engine.model_manager import load_model_artifact

# In-memory cached model and metadata
_CACHED_PIPELINE = None
_CACHED_METADATA = None
_CACHED_SCHEMA = None


def get_model(force_reload: bool = False):
    """Retrieve or lazily load the trained model pipeline and metadata."""
    global _CACHED_PIPELINE, _CACHED_METADATA, _CACHED_SCHEMA
    if _CACHED_PIPELINE is None or force_reload:
        _CACHED_PIPELINE, _CACHED_METADATA, _CACHED_SCHEMA = load_model_artifact(
            model_path=BEST_MODEL_PATH,
            metadata_path=MODEL_METADATA_PATH,
            schema_path=FEATURE_SCHEMA_PATH
        )
    return _CACHED_PIPELINE, _CACHED_METADATA, _CACHED_SCHEMA


def predict_url(url: str) -> Dict[str, Any]:
    """
    Accepts a URL string, validates input, extracts features,
    and returns a structured prediction response.

    Does NOT implement ALLOW/WARN/BLOCK (that belongs to the decision layer).
    """
    # 1. Input Validation
    if url is None:
        return {
            "url": None,
            "prediction": "ERROR",
            "label": None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "model_name": None,
            "model_version": None,
            "status": "ERROR",
            "error_message": "Input URL cannot be None."
        }

    if not isinstance(url, str) or not url.strip():
        return {
            "url": url if isinstance(url, str) else str(url),
            "prediction": "ERROR",
            "label": None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "model_name": None,
            "model_version": None,
            "status": "ERROR",
            "error_message": "Input URL cannot be empty or whitespace."
        }

    clean_url = url.strip()

    # 2. Model Loading
    try:
        pipeline, metadata, schema = get_model()
    except FileNotFoundError as fnf_err:
        return {
            "url": clean_url,
            "prediction": "ERROR",
            "label": None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "model_name": None,
            "model_version": None,
            "status": "ERROR",
            "error_message": f"Model artifact unavailable: {fnf_err}"
        }
    except Exception as exc:
        return {
            "url": clean_url,
            "prediction": "ERROR",
            "label": None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "model_name": None,
            "model_version": None,
            "status": "ERROR",
            "error_message": f"Failed to load model artifact: {exc}"
        }

    # 3. Feature Extraction
    try:
        feature_dict = extract_features_from_url(clean_url)
        ordered_schema = schema if schema else FEATURE_NAMES
        # Construct single-row DataFrame with explicit schema column order
        features_df = pd.DataFrame([feature_dict], columns=ordered_schema)
    except Exception as exc:
        return {
            "url": clean_url,
            "prediction": "ERROR",
            "label": None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "model_name": metadata.get("model_name", "Unknown"),
            "model_version": metadata.get("model_version", "1.0"),
            "status": "ERROR",
            "error_message": f"Feature extraction failed: {exc}"
        }

    # 4. Model Prediction
    try:
        # Probability estimates: classes_ are [0, 1] -> [P(legitimate), P(phishing)]
        probabilities = pipeline.predict_proba(features_df)[0]
        legitimate_prob = float(probabilities[0])
        phishing_prob = float(probabilities[1])

        # Predicted label
        raw_pred = int(pipeline.predict(features_df)[0])
        prediction_label = "PHISHING" if raw_pred == 1 else "LEGITIMATE"

        return {
            "url": clean_url,
            "prediction": prediction_label,
            "label": raw_pred,
            "phishing_probability": round(phishing_prob, 4),
            "legitimate_probability": round(legitimate_prob, 4),
            "model_name": metadata.get("model_name", "Random Forest"),
            "model_version": metadata.get("model_version", "1.0.0"),
            "status": "SUCCESS"
        }

    except Exception as exc:
        return {
            "url": clean_url,
            "prediction": "ERROR",
            "label": None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "model_name": metadata.get("model_name", "Unknown"),
            "model_version": metadata.get("model_version", "1.0"),
            "status": "ERROR",
            "error_message": f"Inference execution failed: {exc}"
        }


if __name__ == "__main__":
    test_url = sys.argv[1] if len(sys.argv) > 1 else "https://www.wikipedia.org"
    result = predict_url(test_url)
    print(json.dumps(result, indent=4))
