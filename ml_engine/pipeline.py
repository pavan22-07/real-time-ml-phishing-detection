"""
Integration Pipeline Interface for Django Backend and Cybersecurity Engine.

Provides an independent, robust bridge between the Machine Learning engine
and the Django backend/security evaluation layer.
"""

from typing import Dict, Any, List, Optional
import pandas as pd

from ml_engine.predict import predict_url, get_model
from ml_engine.feature_extraction import FEATURE_NAMES, extract_features_from_url


class MLInferencePipeline:
    """
    Independent Machine Learning inference interface.
    Designed for seamless consumption by Django views, Celery tasks,
    or composite security decision services.
    """

    def __init__(self, preload: bool = True):
        self.is_ready = False
        if preload:
            self._warmup()

    def _warmup(self) -> None:
        """Preload model artifact into memory for low-latency inference."""
        try:
            get_model()
            self.is_ready = True
        except Exception:
            self.is_ready = False

    def predict(self, url: str) -> Dict[str, Any]:
        """
        Run inference for a single URL.
        Returns a clean dictionary matching the integration contract.
        """
        return predict_url(url)

    def predict_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Run inference across a list of URLs.
        """
        if not urls or not isinstance(urls, list):
            return []
        return [predict_url(u) for u in urls]

    def get_feature_vector(self, url: str) -> Dict[str, Any]:
        """Extract and return the raw 33-feature numerical dictionary for a URL."""
        return extract_features_from_url(url)

    def get_metadata(self) -> Dict[str, Any]:
        """Return loaded model metadata and feature schema."""
        _, metadata, schema = get_model()
        return {
            "model_name": metadata.get("model_name", "Unknown"),
            "model_version": metadata.get("model_version", "1.0.0"),
            "training_date": metadata.get("training_date"),
            "dataset_source": metadata.get("dataset_source"),
            "feature_count": len(schema) if schema else len(FEATURE_NAMES),
            "features": schema if schema else FEATURE_NAMES,
            "status": "READY" if self.is_ready else "ERROR"
        }

    @staticmethod
    def format_combined_response(
        cybersecurity_output: Optional[Dict[str, Any]],
        ml_output: Dict[str, Any],
        proposed_action: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Helper contract method illustrating how the Django backend combines
        cybersecurity findings and ML inference without coupling modules.
        """
        return {
            "url": ml_output.get("url"),
            "ml_engine": {
                "prediction": ml_output.get("prediction"),
                "label": ml_output.get("label"),
                "phishing_probability": ml_output.get("phishing_probability"),
                "legitimate_probability": ml_output.get("legitimate_probability"),
                "confidence": max(
                    ml_output.get("phishing_probability") or 0.0,
                    ml_output.get("legitimate_probability") or 0.0
                ),
                "model_name": ml_output.get("model_name"),
                "model_version": ml_output.get("model_version"),
                "status": ml_output.get("status")
            },
            "cybersecurity_engine": cybersecurity_output,
            "combined_layer": {
                "decision": proposed_action,
                "strategy": "Dual-engine correlation (Cybersecurity deterministic rules + ML statistical confidence)"
            }
        }


# Convenience singleton for application import
ml_pipeline = MLInferencePipeline(preload=False)
