"""
Configuration settings for the Machine Learning phishing detection engine.
"""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
REPORTS_DIR = DATA_DIR / "reports"
ML_ENGINE_DIR = PROJECT_ROOT / "ml_engine"
MODELS_DIR = ML_ENGINE_DIR / "models"
TLD_CACHE_DIR = DATA_DIR / ".tld_cache"

# File Paths
RAW_DATASET_PATH = RAW_DATA_DIR / "url_phish_mendeley_v2.csv"
DATASET_METADATA_PATH = RAW_DATA_DIR / "dataset_metadata.json"
ML_DATASET_PATH = DATA_DIR / "ml_dataset.csv"
PROCESSED_DATASET_PATH = PROCESSED_DATA_DIR / "cleaned_dataset.csv"
FEATURES_DATASET_PATH = PROCESSED_DATA_DIR / "extracted_features.csv"

BEST_MODEL_PATH = MODELS_DIR / "best_model.joblib"
MODEL_METADATA_PATH = MODELS_DIR / "model_metadata.json"
FEATURE_SCHEMA_PATH = MODELS_DIR / "feature_schema.json"

# Dataset Source Configuration
DATASET_INFO = {
    "name": "URL-Phish: A Feature-Engineered Dataset for Phishing Detection",
    "version": "2",
    "doi": "10.17632/65z9twcx3r.2",
    "dataset_id": "65z9twcx3r",
    "file_id": "0e9c55e4-9adb-43f5-8403-1bbd143ebdb6",
    "download_url": "https://data.mendeley.com/public-files/datasets/65z9twcx3r/files/0e9c55e4-9adb-43f5-8403-1bbd143ebdb6/file_downloaded",
    "licence": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
    "authors": "Linh Dam Minh, Hung Tran Cong",
    "institution": "Posts and Telecommunications Institute of Technology",
    "expected_size_bytes": 15149338
}

# Machine Learning Reproducibility & Splitting
RANDOM_SEED = 42
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# Hyperparameter configurations
LOGISTIC_REGRESSION_CONFIG = {
    "C": 1.0,
    "max_iter": 1000,
    "class_weight": "balanced",
    "solver": "lbfgs",
    "random_state": RANDOM_SEED
}

DECISION_TREE_CONFIG = {
    "max_depth": 10,
    "min_samples_split": 10,
    "min_samples_leaf": 5,
    "class_weight": "balanced",
    "random_state": RANDOM_SEED
}

RANDOM_FOREST_CONFIG = {
    "n_estimators": 100,
    "max_depth": 15,
    "min_samples_split": 10,
    "min_samples_leaf": 3,
    "class_weight": "balanced",
    "random_state": RANDOM_SEED,
    "n_jobs": -1
}
