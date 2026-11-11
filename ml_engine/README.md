# `ml_engine` — Machine Learning Phishing URL Detection Module

Independent, static-analysis Machine Learning engine for the **Real-Time ML-Based Phishing Detection & Prevention System**.

Designed to run alongside (without modifying) `security_engine/` and expose a clean inference contract for the Django backend.

---

## 1. Architecture Overview

```
ml_engine/
├── config.py               # Paths, dataset provenance, random seed (42), model hyperparameters
├── dataset_loader.py       # Automated Mendeley Data download & SHA-256 verification
├── data_cleaning.py        # Null/duplicate removal, label normalization -> data/ml_dataset.csv
├── feature_extraction.py   # 33 static URL lexical, domain, security & entropy features (offline)
├── preprocessing.py        # Domain-aware GroupShuffleSplit (zero domain leakage) & sklearn pipelines
├── train.py                # Trains Logistic Regression, Decision Tree, Random Forest; selects best on Val
├── evaluate.py             # Generates confusion matrices, ROC/PR curves, feature importance & reports
├── model_manager.py        # Joblib serialization, feature schema & metadata management
├── predict.py              # Real-time `predict_url(url)` inference interface (no ALLOW/WARN/BLOCK)
├── pipeline.py             # `MLInferencePipeline` integration wrapper for Django & dual-engine scoring
├── models/
│   ├── best_model.joblib   # Trained Random Forest pipeline (v1.0.0)
│   ├── model_metadata.json # Training provenance, hyperparameters & metrics
│   └── feature_schema.json # Ordered 33-feature contract
└── tests/                  # Unittest suite (dataset, features, preprocessing, training, prediction, pipeline)
```

---

## 2. Dataset & Model Summary

- **Dataset:** *URL-Phish: A Feature-Engineered Dataset for Phishing Detection* (Mendeley Data, Version 2, DOI: `10.17632/65z9twcx3r.2`, Licence: `CC BY 4.0`).
- **Raw File:** `data/raw/url_phish_mendeley_v2.csv` (original filename `Dataset.csv`, `116,600` rows, `15,149,338` bytes).
- **Cleaned Dataset:** `data/ml_dataset.csv` (`115,231` unique URLs: `98,641` legitimate [85.6%], `16,590` phishing [14.4%]).
- **Domain-Aware Splits:** `80,171` Train / `18,703` Validation / `16,357` Test (`0` registered-domain overlap across splits).
- **Selected Model:** **Random Forest** (`n_estimators=100`, `max_depth=15`, `min_samples_split=10`, `min_samples_leaf=3`, `class_weight="balanced"`, `random_state=42`).
  - **Validation:** Accuracy `0.9581` | Precision `0.8862` | Recall `0.9140` | F1 `0.8999` | ROC-AUC `0.9895`
  - **Final Test:** Accuracy `0.9621` | Precision `0.8135` | Recall `0.8603` | F1 `0.8362` | ROC-AUC `0.9841`

---

## 3. Windows PowerShell Execution Commands

Run all commands from the repository root (`pishing-project/`):

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Download & verify raw dataset (requires internet on first run)
python -m ml_engine.dataset_loader

# 3. Clean dataset & normalize binary labels (0=LEGITIMATE, 1=PHISHING)
python -m ml_engine.data_cleaning

# 4. Extract 33 static features & create domain-aware train/val/test splits
python -m ml_engine.preprocessing

# 5. Train Logistic Regression, Decision Tree, and Random Forest; save best model
python -m ml_engine.train

# 6. Generate full evaluation charts & comparison reports in data/reports/
python -m ml_engine.evaluate

# 7. Run single-URL real-time prediction from CLI
python -m ml_engine.predict "https://www.wikipedia.org/"

# 8. Run ML automated test suite
python -m unittest discover -s ml_engine/tests -p "test_*.py" -v

# 9. Run existing cybersecurity tests offline (requires TLDEXTRACT_CACHE)
$env:TLDEXTRACT_CACHE="data/.tld_cache"
python security_engine/security_validation_test.py
```

---

## 4. Real-Time Prediction Usage (Django / Python)

```python
from ml_engine.predict import predict_url

result = predict_url("https://example.com")
```

**Success Response:**
```json
{
    "url": "https://example.com",
    "prediction": "LEGITIMATE",
    "label": 0,
    "phishing_probability": 0.0467,
    "legitimate_probability": 0.9533,
    "model_name": "Random Forest",
    "model_version": "1.0.0",
    "status": "SUCCESS"
}
```

**Error Response (Empty/Invalid Input or Missing Model):**
```json
{
    "url": "",
    "prediction": "ERROR",
    "label": null,
    "phishing_probability": null,
    "legitimate_probability": null,
    "model_name": null,
    "model_version": null,
    "status": "ERROR",
    "error_message": "Input URL cannot be empty or whitespace."
}
```

> **Note:** `predict_url()` intentionally never outputs `ALLOW`, `WARN`, or `BLOCK`. Final policy decisions belong in the separate Django combined-decision layer integrating `security_engine` and `ml_engine`.

For full methodology, feature definitions, investigation reports, and integration contracts, see [`ML_DOCUMENTATION.md`](../ML_DOCUMENTATION.md).
