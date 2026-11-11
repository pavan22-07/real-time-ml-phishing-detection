# Model Evaluation & Benchmark Report
## Real-Time Phishing Detection System

**Generated on:** 2026-11-10T19:44:59.900028+00:00  
**Dataset:** URL-Phish: A Feature-Engineered Dataset for Phishing Detection (DOI: 10.17632/65z9twcx3r.2)  
**Validation instances:** 18,703 (Legitimate: 14,852, Phishing: 3,851)  
**Test instances:** 16,357 (Legitimate: 14,517, Phishing: 1,840)  
**Splitting Strategy:** Domain-Aware Grouped Split (Zero Domain Overlap)

---

## 1. Classifier Performance Comparison (Validation Set)

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | False Positives | False Negatives |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 0.9301 | 0.7896 | 0.9005 | 0.8414 | 0.9738 | 924 | 383 |
| **Decision Tree** | 0.9511 | 0.8340 | 0.9522 | 0.8892 | 0.9750 | 730 | 184 |
| **Random Forest** *(Selected)* | **0.9581** | **0.8862** | **0.9140** | **0.8999** | **0.9895** | **452** | **331** |

---

## 2. Selected Best Model: Random Forest
### Final Unseen Test Set Evaluation

| Metric | Score |
| :--- | :--- |
| **Accuracy** | 0.9621 (96.21%) |
| **Precision** | 0.8135 (81.35%) |
| **Recall (True Positive Rate)** | 0.8603 (86.03%) |
| **F1-Score** | 0.8362 |
| **ROC-AUC** | 0.9841 |
| **True Negatives (TN)** | 14,154 |
| **False Positives (FP)** | 363 |
| **False Negatives (FN)** | 257 |
| **True Positives (TP)** | 1,583 |
| **False Positive Rate (FPR)** | 0.0250 |
| **False Negative Rate (FNR)** | 0.1397 |

---

## 3. Classifier Strengths & Weaknesses Analysis

### Model 1: Logistic Regression
- **Strengths:** Rapid inference time (~1s training), full linear explainability with feature coefficients, low computational footprint.
- **Weaknesses:** Struggles with complex non-linear feature interactions (such as compound entropy and structural ratio combinations), higher false positive count (924 on validation).

### Model 2: Decision Tree
- **Strengths:** Captures non-linear decision boundaries, high recall (0.9522), naturally human-interpretable rules.
- **Weaknesses:** Sensitive to domain variance, prone to localized overfitting despite depth regularization, lower precision (0.8340) leading to false alarms.

### Model 3: Random Forest (Best Performing)
- **Strengths:** Ensembles 100 decorrelated decision trees, mitigating variance and domain overfitting. Achieves superior precision (0.8862), the highest ROC-AUC (0.9895), and cuts false positives nearly in half compared to the single decision tree while maintaining strong recall.
- **Weaknesses:** Larger memory footprint on disk (~40MB uncompressed) and slightly higher latency than linear models, though still sub-millisecond per URL.

---

## 4. Why Accuracy is Misleading for Phishing Datasets
Phishing URL datasets are characteristically imbalanced (~85% legitimate vs ~15% phishing). A naive dummy classifier predicting all URLs as legitimate would obtain an 85% accuracy while missing 100% of malicious phishing attacks. In cybersecurity operations, **False Negatives (missed phishing attacks)** lead directly to credential theft and breach, while **False Positives (blocked benign business URLs)** cause user disruption. Thus, **Recall**, **Precision**, **F1-Score**, and **ROC-AUC** are the definitive criteria for model evaluation.
