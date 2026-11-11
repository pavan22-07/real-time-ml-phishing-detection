"""
Model Training Module for Phishing Detection.
Trains Logistic Regression, Decision Tree, and Random Forest classifiers.
Evaluates validation performance, selects the best model, and saves artifacts.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from ml_engine.config import (
    PROCESSED_DATA_DIR,
    REPORTS_DIR,
    RANDOM_SEED,
    LOGISTIC_REGRESSION_CONFIG,
    DECISION_TREE_CONFIG,
    RANDOM_FOREST_CONFIG,
    DATASET_INFO,
    BEST_MODEL_PATH,
    MODEL_METADATA_PATH,
    FEATURE_SCHEMA_PATH
)
from ml_engine.feature_extraction import FEATURE_NAMES
from ml_engine.model_manager import save_model_artifact
from ml_engine.preprocessing import prepare_datasets


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> Dict[str, Any]:
    """Compute comprehensive evaluation metrics for binary classification."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    try:
        roc_auc = float(roc_auc_score(y_true, y_proba))
    except Exception:
        roc_auc = 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        },
        "false_positive_rate": round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0,
        "false_negative_rate": round(float(fn / (fn + tp)), 4) if (fn + tp) > 0 else 0.0
    }


def train_and_select_models() -> Tuple[Dict[str, Pipeline], Dict[str, Any], str]:
    """
    Train Logistic Regression, Decision Tree, and Random Forest.
    Evaluate on validation set and select the best model.
    """
    train_path = PROCESSED_DATA_DIR / "train.csv"
    val_path = PROCESSED_DATA_DIR / "val.csv"
    test_path = PROCESSED_DATA_DIR / "test.csv"

    if not train_path.exists() or not val_path.exists():
        prepare_datasets()

    print("[+] Loading train, validation, and test datasets...")
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    X_train = train_df[FEATURE_NAMES]
    y_train = train_df["label"].values

    X_val = val_df[FEATURE_NAMES]
    y_val = val_df["label"].values

    X_test = test_df[FEATURE_NAMES]
    y_test = test_df["label"].values

    print(f"    Train instances: {len(X_train):,} (Phishing: {(y_train == 1).sum():,}, Benign: {(y_train == 0).sum():,})")
    print(f"    Val instances:   {len(X_val):,} (Phishing: {(y_val == 1).sum():,}, Benign: {(y_val == 0).sum():,})")
    print(f"    Test instances:  {len(X_test):,} (Phishing: {(y_test == 1).sum():,}, Benign: {(y_test == 0).sum():,})")

    # 1. Pipeline Definition
    models = {
        "Logistic Regression": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(**LOGISTIC_REGRESSION_CONFIG))
        ]),
        "Decision Tree": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", DecisionTreeClassifier(**DECISION_TREE_CONFIG))
        ]),
        "Random Forest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(**RANDOM_FOREST_CONFIG))
        ])
    }

    eval_results = {}
    validation_metrics = {}

    print("\n" + "=" * 60)
    print("STARTING MODEL TRAINING & VALIDATION EVALUATION")
    print("=" * 60)

    for name, pipeline in models.items():
        print(f"\n[+] Training {name}...")
        start_time = datetime.now()
        pipeline.fit(X_train, y_train)
        duration = (datetime.now() - start_time).total_seconds()
        print(f"    Training completed in {duration:.2f} seconds.")

        # Validation prediction
        y_val_pred = pipeline.predict(X_val)
        y_val_proba = pipeline.predict_proba(X_val)[:, 1]

        val_metrics = compute_metrics(y_val, y_val_pred, y_val_proba)
        val_metrics["training_duration_seconds"] = round(duration, 2)
        validation_metrics[name] = val_metrics

        print(f"    Validation Metrics for {name}:")
        print(f"      - Accuracy:  {val_metrics['accuracy']:.4f}")
        print(f"      - Precision: {val_metrics['precision']:.4f}")
        print(f"      - Recall:    {val_metrics['recall']:.4f}")
        print(f"      - F1-Score:  {val_metrics['f1_score']:.4f}")
        print(f"      - ROC-AUC:   {val_metrics['roc_auc']:.4f}")
        print(f"      - Confusion Matrix: TN={val_metrics['confusion_matrix']['tn']}, FP={val_metrics['confusion_matrix']['fp']}, FN={val_metrics['confusion_matrix']['fn']}, TP={val_metrics['confusion_matrix']['tp']}")

    # Model Selection using Validation F1-score & Recall
    # In phishing detection, we prioritize high F1-score while penalizing missed phishing (high recall)
    best_name = max(validation_metrics.keys(), key=lambda m: (validation_metrics[m]["f1_score"], validation_metrics[m]["recall"]))
    best_pipeline = models[best_name]

    print("\n" + "=" * 60)
    print(f"BEST MODEL SELECTED: {best_name}")
    print(f"Validation F1-score: {validation_metrics[best_name]['f1_score']:.4f} | Recall: {validation_metrics[best_name]['recall']:.4f}")
    print("=" * 60)

    # Final Test Set Evaluation ONLY for the selected best model (and recorded for comparison)
    print(f"\n[+] Evaluating selected best model ({best_name}) on final unseen test set...")
    y_test_pred = best_pipeline.predict(X_test)
    y_test_proba = best_pipeline.predict_proba(X_test)[:, 1]
    final_test_metrics = compute_metrics(y_test, y_test_pred, y_test_proba)

    print(f"    Final Test Set Metrics for {best_name}:")
    print(f"      - Accuracy:  {final_test_metrics['accuracy']:.4f}")
    print(f"      - Precision: {final_test_metrics['precision']:.4f}")
    print(f"      - Recall:    {final_test_metrics['recall']:.4f}")
    print(f"      - F1-Score:  {final_test_metrics['f1_score']:.4f}")
    print(f"      - ROC-AUC:   {final_test_metrics['roc_auc']:.4f}")
    print(f"      - Confusion Matrix: TN={final_test_metrics['confusion_matrix']['tn']}, FP={final_test_metrics['confusion_matrix']['fp']}, FN={final_test_metrics['confusion_matrix']['fn']}, TP={final_test_metrics['confusion_matrix']['tp']}")

    # Build metadata
    hyperparams = {
        "Logistic Regression": LOGISTIC_REGRESSION_CONFIG,
        "Decision Tree": DECISION_TREE_CONFIG,
        "Random Forest": RANDOM_FOREST_CONFIG
    }

    metadata = {
        "model_name": best_name,
        "model_version": "1.0.0",
        "training_date": datetime.now(timezone.utc).isoformat(),
        "dataset_source": DATASET_INFO["name"],
        "dataset_version": DATASET_INFO["version"],
        "dataset_doi": DATASET_INFO["doi"],
        "training_records": len(X_train),
        "validation_records": len(X_val),
        "test_records": len(X_test),
        "features": FEATURE_NAMES,
        "hyperparameters": hyperparams[best_name],
        "all_hyperparameters": hyperparams,
        "random_seed": RANDOM_SEED,
        "validation_metrics": validation_metrics,
        "final_test_metrics": final_test_metrics,
        "selection_rationale": (
            f"{best_name} achieved the highest validation F1-score ({validation_metrics[best_name]['f1_score']:.4f}) "
            f"and strong generalization recall ({validation_metrics[best_name]['recall']:.4f}), effectively minimizing "
            "costly false negatives while maintaining low false positives under domain-aware evaluation."
        )
    }

    # Save best model artifact
    save_model_artifact(
        pipeline=best_pipeline,
        metadata=metadata,
        feature_schema=FEATURE_NAMES
    )

    # Save summary report
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    summary_report_path = REPORTS_DIR / "training_summary.json"
    with open(summary_report_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Training summary report saved to: {summary_report_path}")

    return models, metadata, best_name


if __name__ == "__main__":
    train_and_select_models()
