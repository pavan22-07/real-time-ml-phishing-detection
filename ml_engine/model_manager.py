"""
Model Manager for Phishing Detection.
Handles artifact serialization, integrity verification, metadata tracking, and model loading.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple
import joblib

from ml_engine.config import (
    BEST_MODEL_PATH,
    MODEL_METADATA_PATH,
    FEATURE_SCHEMA_PATH,
    MODELS_DIR
)


def save_model_artifact(
    pipeline: Any,
    metadata: Dict[str, Any],
    feature_schema: list,
    model_path: Path = BEST_MODEL_PATH,
    metadata_path: Path = MODEL_METADATA_PATH,
    schema_path: Path = FEATURE_SCHEMA_PATH
) -> None:
    """
    Save the complete scikit-learn pipeline, metadata, and feature schema.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Save pipeline artifact with joblib
    joblib.dump(pipeline, model_path, compress=3)

    # 2. Save feature schema
    schema_data = {
        "feature_count": len(feature_schema),
        "features": feature_schema
    }
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema_data, f, indent=4)

    # 3. Save comprehensive metadata
    metadata["saved_timestamp"] = datetime.now(timezone.utc).isoformat()
    metadata["feature_count"] = len(feature_schema)
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    print(f"[+] Model artifact successfully saved to: {model_path}")
    print(f"[+] Model metadata saved to: {metadata_path}")
    print(f"[+] Feature schema saved to: {schema_path}")


def load_model_artifact(
    model_path: Path = BEST_MODEL_PATH,
    metadata_path: Path = MODEL_METADATA_PATH,
    schema_path: Path = FEATURE_SCHEMA_PATH
) -> Tuple[Any, Dict[str, Any], list]:
    """
    Load the trained model pipeline, metadata, and feature schema.
    Validates presence of all necessary artifacts.
    """
    if not model_path.exists():
        raise FileNotFoundError(
            f"Trained model artifact not found at: {model_path}. "
            "Please run 'python -m ml_engine.train' first."
        )

    pipeline = joblib.load(model_path)

    metadata = {}
    if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

    feature_schema = []
    if schema_path.exists():
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_data = json.load(f)
            feature_schema = schema_data.get("features", [])

    return pipeline, metadata, feature_schema


if __name__ == "__main__":
    try:
        pipeline, meta, schema = load_model_artifact()
        print(f"Loaded model: {meta.get('model_name', 'Unknown')}")
        print(f"Version: {meta.get('model_version', '1.0')}")
        print(f"Features count: {len(schema)}")
    except Exception as exc:
        print(f"Model manager check: {exc}")
