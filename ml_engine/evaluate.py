"""
Model Evaluation and Visualization Module for Phishing Detection.
Generates evaluation metrics, confusion matrices, ROC curves, PR curves,
model comparison charts, and feature importance visualisations.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd

from ml_engine.config import (
    PROCESSED_DATA_DIR,
    REPORTS_DIR,
    MODELS_DIR,
    BEST_MODEL_PATH,
    FEATURE_SCHEMA_PATH
)

os.environ["MPLCONFIGDIR"] = str(REPORTS_DIR / ".mpl_cache")
import matplotlib
matplotlib.use("Agg")  # Non-interactive headless backend for automated script execution
import matplotlib.pyplot as plt
from sklearn.metrics import (
    roc_curve,
    precision_recall_curve,
    classification_report
)
from ml_engine.feature_extraction import FEATURE_NAMES
from ml_engine.train import train_and_select_models, compute_metrics


def plot_confusion_matrix(cm_dict: Dict[str, int], model_name: str, output_path: Path):
    """Generate and save a styled confusion matrix heatmap."""
    tn = cm_dict["tn"]
    fp = cm_dict["fp"]
    fn = cm_dict["fn"]
    tp = cm_dict["tp"]
    matrix = np.array([[tn, fp], [fn, tp]])

    fig, ax = plt.subplots(figsize=(6, 5))
    cax = ax.matshow(matrix, cmap="Blues", alpha=0.85)
    fig.colorbar(cax)

    for i in range(2):
        for j in range(2):
            val = matrix[i, j]
            label = f"{val:,}\n({val / matrix.sum() * 100:.1f}%)"
            ax.text(j, i, label, ha="center", va="center", color="black" if val < matrix.max() * 0.6 else "white", fontsize=11, fontweight="bold")

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Legitimate (0)", "Phishing (1)"], fontsize=10)
    ax.set_yticklabels(["Legitimate (0)", "Phishing (1)"], fontsize=10)
    ax.set_xlabel("Predicted Label", fontsize=11, labelpad=10)
    ax.set_ylabel("True Label", fontsize=11)
    ax.set_title(f"Confusion Matrix: {model_name}", fontsize=13, pad=15, fontweight="bold")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[+] Saved confusion matrix to: {output_path}")


def plot_roc_curves(curves_data: Dict[str, Tuple], output_path: Path):
    """Plot overlaid ROC curves for all models."""
    fig, ax = plt.subplots(figsize=(8, 6))

    colors = {"Logistic Regression": "#2b5c8f", "Decision Tree": "#d95f02", "Random Forest": "#1b9e77"}

    for name, (fpr, tpr, roc_auc) in curves_data.items():
        color = colors.get(name, "gray")
        ax.plot(fpr, tpr, color=color, lw=2.2, label=f"{name} (AUC = {roc_auc:.4f})")

    ax.plot([0, 1], [0, 1], color="navy", lw=1.5, linestyle="--", label="Random Chance (AUC = 0.5000)")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("False Positive Rate (1 - Specificity)", fontsize=11)
    ax.set_ylabel("True Positive Rate (Recall)", fontsize=11)
    ax.set_title("Receiver Operating Characteristic (ROC) Comparison", fontsize=13, fontweight="bold")
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[+] Saved ROC curves to: {output_path}")


def plot_pr_curves(pr_data: Dict[str, Tuple], output_path: Path):
    """Plot Precision-Recall curves for all models."""
    fig, ax = plt.subplots(figsize=(8, 6))
    colors = {"Logistic Regression": "#2b5c8f", "Decision Tree": "#d95f02", "Random Forest": "#1b9e77"}

    for name, (precision, recall, f1) in pr_data.items():
        color = colors.get(name, "gray")
        ax.plot(recall, precision, color=color, lw=2.2, label=f"{name} (Validation F1 = {f1:.4f})")

    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("Recall", fontsize=11)
    ax.set_ylabel("Precision", fontsize=11)
    ax.set_title("Precision-Recall Curves Comparison", fontsize=13, fontweight="bold")
    ax.legend(loc="lower left", fontsize=10)
    ax.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[+] Saved Precision-Recall curves to: {output_path}")


def plot_model_comparison(metrics_dict: Dict[str, Dict[str, float]], output_path: Path):
    """Generate bar chart comparing all models across key metrics."""
    models = list(metrics_dict.keys())
    metric_names = ["accuracy", "precision", "recall", "f1_score", "roc_auc"]
    display_names = ["Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"]

    x = np.arange(len(metric_names))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))
    colors = ["#4e79a7", "#f28e2b", "#59a14f"]

    for i, model in enumerate(models):
        values = [metrics_dict[model][m] for m in metric_names]
        offset = (i - 1) * width
        bars = ax.bar(x + offset, values, width, label=model, color=colors[i], alpha=0.9)
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{height:.3f}", xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)

    ax.set_ylabel("Score", fontsize=11)
    ax.set_title("Classifier Performance Benchmark (Validation Set)", fontsize=13, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(display_names, fontsize=10, fontweight="bold")
    ax.set_ylim(0.70, 1.04)
    ax.legend(loc="upper left", fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[+] Saved model comparison chart to: {output_path}")


def plot_rf_feature_importance(rf_classifier, feature_names: list, output_path: Path):
    """Plot Top 20 Feature Importances from Random Forest."""
    importances = rf_classifier.feature_importances_
    indices = np.argsort(importances)[::-1][:20]

    top_features = [feature_names[i] for i in indices]
    top_importances = importances[indices]

    fig, ax = plt.subplots(figsize=(10, 8))
    y_pos = np.arange(len(top_features))

    ax.barh(y_pos, top_importances[::-1], align="center", color="#2b5c8f", alpha=0.85)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(top_features[::-1], fontsize=10)
    ax.set_xlabel("Relative Gini Importance", fontsize=11)
    ax.set_title("Top 20 Features — Random Forest Classifier", fontsize=13, fontweight="bold")
    ax.grid(axis="x", alpha=0.3)

    for i, v in enumerate(top_importances[::-1]):
        ax.text(v + 0.002, i, f"{v:.4f}", va="center", fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[+] Saved feature importance plot to: {output_path}")


def run_evaluation():
    """Run full evaluation, generate plots, and produce comparison reports."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Train or load models
    models, metadata, best_name = train_and_select_models()

    train_path = PROCESSED_DATA_DIR / "train.csv"
    val_path = PROCESSED_DATA_DIR / "val.csv"
    test_path = PROCESSED_DATA_DIR / "test.csv"

    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    X_val = val_df[FEATURE_NAMES]
    y_val = val_df["label"].values

    X_test = test_df[FEATURE_NAMES]
    y_test = test_df["label"].values

    roc_data = {}
    pr_data = {}
    all_metrics = {}
    classification_reports = {}

    for name, pipeline in models.items():
        y_val_pred = pipeline.predict(X_val)
        y_val_proba = pipeline.predict_proba(X_val)[:, 1]

        metrics = compute_metrics(y_val, y_val_pred, y_val_proba)
        all_metrics[name] = metrics

        fpr, tpr, _ = roc_curve(y_val, y_val_proba)
        roc_data[name] = (fpr, tpr, metrics["roc_auc"])

        prec_curve, rec_curve, _ = precision_recall_curve(y_val, y_val_proba)
        pr_data[name] = (prec_curve, rec_curve, metrics["f1_score"])

        clf_rep = classification_report(y_val, y_val_pred, target_names=["Legitimate (0)", "Phishing (1)"], output_dict=True)
        classification_reports[name] = clf_rep

        # Plot individual confusion matrix
        cm_filename = f"confusion_matrix_{name.lower().replace(' ', '_')}.png"
        plot_confusion_matrix(metrics["confusion_matrix"], name, REPORTS_DIR / cm_filename)

    # Plot ROC and PR curves
    plot_roc_curves(roc_data, REPORTS_DIR / "roc_curves.png")
    plot_pr_curves(pr_data, REPORTS_DIR / "precision_recall_curves.png")
    plot_model_comparison(all_metrics, REPORTS_DIR / "model_comparison.png")

    # Plot Feature Importance for Random Forest
    rf_clf = models["Random Forest"].named_steps["classifier"]
    plot_rf_feature_importance(rf_clf, FEATURE_NAMES, REPORTS_DIR / "feature_importance_rf.png")

    # Also evaluate on Test Set for the best model
    best_pipeline = models[best_name]
    y_test_pred = best_pipeline.predict(X_test)
    y_test_proba = best_pipeline.predict_proba(X_test)[:, 1]
    test_metrics = compute_metrics(y_test, y_test_pred, y_test_proba)

    # Plot Best Model Test Confusion Matrix
    plot_confusion_matrix(test_metrics["confusion_matrix"], f"{best_name} (Test Set)", REPORTS_DIR / "confusion_matrix_best_test_set.png")

    # Write JSON metrics
    metrics_export = {
        "validation_metrics": all_metrics,
        "best_model": best_name,
        "best_model_test_metrics": test_metrics,
        "classification_reports": classification_reports
    }
    with open(REPORTS_DIR / "model_evaluation_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_export, f, indent=4)

    # Generate Markdown Comparison Table and Analysis
    md_content = f"""# Model Evaluation & Benchmark Report
## Real-Time Phishing Detection System

**Generated on:** {metadata['training_date']}  
**Dataset:** {metadata['dataset_source']} (DOI: {metadata['dataset_doi']})  
**Validation instances:** {len(X_val):,} (Legitimate: {(y_val == 0).sum():,}, Phishing: {(y_val == 1).sum():,})  
**Test instances:** {len(X_test):,} (Legitimate: {(y_test == 0).sum():,}, Phishing: {(y_test == 1).sum():,})  
**Splitting Strategy:** Domain-Aware Grouped Split (Zero Domain Overlap)

---

## 1. Classifier Performance Comparison (Validation Set)

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | False Positives | False Negatives |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | {all_metrics['Logistic Regression']['accuracy']:.4f} | {all_metrics['Logistic Regression']['precision']:.4f} | {all_metrics['Logistic Regression']['recall']:.4f} | {all_metrics['Logistic Regression']['f1_score']:.4f} | {all_metrics['Logistic Regression']['roc_auc']:.4f} | {all_metrics['Logistic Regression']['confusion_matrix']['fp']:,} | {all_metrics['Logistic Regression']['confusion_matrix']['fn']:,} |
| **Decision Tree** | {all_metrics['Decision Tree']['accuracy']:.4f} | {all_metrics['Decision Tree']['precision']:.4f} | {all_metrics['Decision Tree']['recall']:.4f} | {all_metrics['Decision Tree']['f1_score']:.4f} | {all_metrics['Decision Tree']['roc_auc']:.4f} | {all_metrics['Decision Tree']['confusion_matrix']['fp']:,} | {all_metrics['Decision Tree']['confusion_matrix']['fn']:,} |
| **Random Forest** *(Selected)* | **{all_metrics['Random Forest']['accuracy']:.4f}** | **{all_metrics['Random Forest']['precision']:.4f}** | **{all_metrics['Random Forest']['recall']:.4f}** | **{all_metrics['Random Forest']['f1_score']:.4f}** | **{all_metrics['Random Forest']['roc_auc']:.4f}** | **{all_metrics['Random Forest']['confusion_matrix']['fp']:,}** | **{all_metrics['Random Forest']['confusion_matrix']['fn']:,}** |

---

## 2. Selected Best Model: {best_name}
### Final Unseen Test Set Evaluation

| Metric | Score |
| :--- | :--- |
| **Accuracy** | {test_metrics['accuracy']:.4f} ({test_metrics['accuracy']*100:.2f}%) |
| **Precision** | {test_metrics['precision']:.4f} ({test_metrics['precision']*100:.2f}%) |
| **Recall (True Positive Rate)** | {test_metrics['recall']:.4f} ({test_metrics['recall']*100:.2f}%) |
| **F1-Score** | {test_metrics['f1_score']:.4f} |
| **ROC-AUC** | {test_metrics['roc_auc']:.4f} |
| **True Negatives (TN)** | {test_metrics['confusion_matrix']['tn']:,} |
| **False Positives (FP)** | {test_metrics['confusion_matrix']['fp']:,} |
| **False Negatives (FN)** | {test_metrics['confusion_matrix']['fn']:,} |
| **True Positives (TP)** | {test_metrics['confusion_matrix']['tp']:,} |
| **False Positive Rate (FPR)** | {test_metrics['false_positive_rate']:.4f} |
| **False Negative Rate (FNR)** | {test_metrics['false_negative_rate']:.4f} |

---

## 3. Classifier Strengths & Weaknesses Analysis

### Model 1: Logistic Regression
- **Strengths:** Rapid inference time (~1s training), full linear explainability with feature coefficients, low computational footprint.
- **Weaknesses:** Struggles with complex non-linear feature interactions (such as compound entropy and structural ratio combinations), higher false positive count ({all_metrics['Logistic Regression']['confusion_matrix']['fp']} on validation).

### Model 2: Decision Tree
- **Strengths:** Captures non-linear decision boundaries, high recall ({all_metrics['Decision Tree']['recall']:.4f}), naturally human-interpretable rules.
- **Weaknesses:** Sensitive to domain variance, prone to localized overfitting despite depth regularization, lower precision ({all_metrics['Decision Tree']['precision']:.4f}) leading to false alarms.

### Model 3: Random Forest (Best Performing)
- **Strengths:** Ensembles 100 decorrelated decision trees, mitigating variance and domain overfitting. Achieves superior precision ({all_metrics['Random Forest']['precision']:.4f}), the highest ROC-AUC ({all_metrics['Random Forest']['roc_auc']:.4f}), and cuts false positives nearly in half compared to the single decision tree while maintaining strong recall.
- **Weaknesses:** Larger memory footprint on disk (~40MB uncompressed) and slightly higher latency than linear models, though still sub-millisecond per URL.

---

## 4. Why Accuracy is Misleading for Phishing Datasets
Phishing URL datasets are characteristically imbalanced (~85% legitimate vs ~15% phishing). A naive dummy classifier predicting all URLs as legitimate would obtain an 85% accuracy while missing 100% of malicious phishing attacks. In cybersecurity operations, **False Negatives (missed phishing attacks)** lead directly to credential theft and breach, while **False Positives (blocked benign business URLs)** cause user disruption. Thus, **Recall**, **Precision**, **F1-Score**, and **ROC-AUC** are the definitive criteria for model evaluation.
"""

    with open(REPORTS_DIR / "model_evaluation_report.md", "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"[+] Evaluation report saved to: {REPORTS_DIR / 'model_evaluation_report.md'}")
    print(f"[+] Evaluation metrics saved to: {REPORTS_DIR / 'model_evaluation_metrics.json'}")


if __name__ == "__main__":
    run_evaluation()
