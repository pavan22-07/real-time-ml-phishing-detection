# Machine Learning Module Documentation
## Real-Time ML-Based Phishing Detection & Prevention System

**Module:** `ml_engine` (v1.0.0)  
**Author / Subsystem:** Machine Learning & Data Science Module  
**Repository:** `pishing-project` (`https://github.com/pavan22-07/real-time-ml-phishing-detection`)  

---

## 1. ML System Architecture

The Machine Learning engine (`ml_engine/`) operates as an independent static-URL analysis service alongside the deterministic `security_engine/`. Neither engine imports or mutates the other's internal state.

```
                        User Submits URL
                               |
                               v
                         Django Backend
                               |
            +------------------+------------------+
            |                                     |
            v                                     v
   Cybersecurity Engine (`security_engine`)    ML Engine (`ml_engine`)
   - URL Analyzer, Rule Engine, Risk Scoring   - Static 33-Feature Extraction
   - Brand / IDN / Threat Intel / Redirects    - Trained Random Forest Pipeline
   - Outputs: Security Findings & Risk Score   - Outputs: Label & Phish Probability
            |                                     |
            +------------------+------------------+
                               |
                               v
                 Combined Decision Layer (Django)
                               |
                               v
                      ALLOW / WARN / BLOCK
```

### Design Principles
- **Single Feature Extraction Path:** [`ml_engine/feature_extraction.py`](ml_engine/feature_extraction.py) is used identically during dataset preparation, training, validation, testing, and real-time inference.
- **Zero Target/Precomputed Leakage:** Precomputed numeric columns from the raw dataset are discarded during cleaning; all 33 features are recomputed directly from raw URL strings.
- **Static Analysis Only:** No submitted URL is fetched, resolved via DNS, or executed during ML feature extraction or inference.
- **Strict Separation of Concerns:** `predict_url()` outputs classification labels and probabilities only; `ALLOW` / `WARN` / `BLOCK` policy thresholds remain isolated from the ML predictor.

---

## 2. Dataset Provenance, Download & Preservation

### 2.1 Dataset Source & Licence
- **Dataset Title:** *URL-Phish: A Feature-Engineered Dataset for Phishing Detection*
- **Authors:** Linh Dam Minh, Hung Tran Cong (Posts and Telecommunications Institute of Technology)
- **Version:** `2`
- **Official DOI:** `10.17632/65z9twcx3r.2`
- **Mendeley Dataset ID:** `65z9twcx3r`
- **File ID:** `0e9c55e4-9adb-43f5-8403-1bbd143ebdb6`
- **Original Filename (HTTP `Content-Disposition`):** `Dataset.csv`
- **Download URL:** `https://data.mendeley.com/public-files/datasets/65z9twcx3r/files/0e9c55e4-9adb-43f5-8403-1bbd143ebdb6/file_downloaded`
- **Licence:** Creative Commons Attribution 4.0 International (`CC BY 4.0`)

> **Discovery Note:** The URL referenced in the initial specification (`https://data.mendeley.com/datasets/8x6k8j7z6z/2`) returned `HTTP 200` with an internal API state of `404` (`"No snapshot for dataset_id: 8x6k8j7z6z, version: 2 found"`). Investigation via Mendeley Data's public catalog located the authentic *URL-Phish* v2 dataset under DOI `10.17632/65z9twcx3r.2`.

### 2.2 Automated Download & Integrity Preservation
Implemented in [`ml_engine/dataset_loader.py`](ml_engine/dataset_loader.py):
- Downloads the unmodified original CSV into `data/raw/url_phish_mendeley_v2.csv`.
- Computes and records cryptographic provenance in `data/raw/dataset_metadata.json`:
  - **File Size:** `15,149,338` bytes (~14.45 MiB)
  - **SHA-256:** `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1`
  - **Raw Shape:** `116,600` rows × `26` columns
  - **Raw Class Counts:** `100,000` Legitimate (`0`, `85.76%`), `16,600` Phishing (`1`, `14.24%`)
- The raw file is never altered in place.

---

## 3. Data Cleaning & Class Distribution

Implemented in [`ml_engine/data_cleaning.py`](ml_engine/data_cleaning.py) and logged to `data/reports/data_cleaning_report.json`:

### Cleaning Rules Applied
1. Validate existence of `url` and `label` columns.
2. Drop rows with missing `url` or `label` (`0` found).
3. Strip whitespace and remove empty URL strings (`0` found).
4. Normalize labels strictly to integer binary `{0, 1}` where `0 = LEGITIMATE` and `1 = PHISHING` (`0` invalid or unexpected labels).
5. Verify no conflicting labels exist for identical URLs (`0` conflicts).
6. Deduplicate exact URL strings keeping first occurrence (`1,369` duplicate URLs removed).
7. Discard all 24 precomputed raw dataset columns so no raw dataset metadata or precomputed artifacts leak into modeling.

### Cleaned Dataset Statistics (`data/ml_dataset.csv` & `data/processed/cleaned_dataset.csv`)
- **Total Records:** `115,231`
- **Columns:** `['url', 'label']`
- **Legitimate (`0`):** `98,641` (`85.60%`)
- **Phishing (`1`):** `16,590` (`14.40%`)
- **Imbalance Ratio:** `5.95 : 1` (Legitimate : Phishing)

*(The existing `data/cybersecurity_test_urls.csv` and `data/legitimate_regression_urls.csv` remain completely untouched.)*

---

## 4. Feature Engineering (33 Static URL Features)

Implemented in [`ml_engine/feature_extraction.py`](ml_engine/feature_extraction.py) (`extract_features_from_url()`), using Python's `urllib.parse`, `ipaddress`, `re`, `math`, `collections.Counter`, and offline `tldextract`.

### A. URL Structural Features (15 features)
| # | Feature Name | Type | Calculation |
| :- | :--- | :--- | :--- |
| 1 | `url_len` | `int` | Total character length of trimmed URL string |
| 2 | `hostname_len` | `int` | Character length of parsed lowercase hostname |
| 3 | `path_len` | `int` | Character length of URL path component |
| 4 | `query_len` | `int` | Character length of URL query string |
| 5 | `dot_cnt` | `int` | Total count of `.` characters in URL |
| 6 | `hyphen_cnt` | `int` | Total count of `-` characters in URL |
| 7 | `digit_cnt` | `int` | Total count of ASCII/Unicode numeric digits in URL |
| 8 | `special_cnt` | `int` | Count of characters that are neither alphanumeric nor `/` or `:` |
| 9 | `digit_ratio` | `float` | `digit_cnt / url_len` (rounded to 4 decimals; `0.0` if empty) |
| 10 | `alpha_ratio` | `float` | Count of alphabetic characters divided by `url_len` |
| 11 | `special_ratio` | `float` | `special_cnt / url_len` |
| 12 | `uppercase_ratio` | `float` | Count of uppercase characters divided by `url_len` |
| 13 | `query_param_cnt` | `int` | Number of parsed query parameters (`urllib.parse.parse_qs`) |
| 14 | `separator_cnt` | `int` | Total occurrences of `/`, `?`, `=`, `&`, `#` in URL |
| 15 | `url_component_cnt` | `int` | `(1 if scheme) + (1 if hostname) + count(non-empty path segments) + (1 if query)` |

### B. Domain & Protocol Features (8 features)
| # | Feature Name | Type | Calculation |
| :- | :--- | :--- | :--- |
| 16 | `subdom_cnt` | `int` | Number of non-empty dot-separated subdomain labels (`tldextract`) |
| 17 | `dom_len` | `int` | Character length of extracted domain name (excluding TLD/subdomains) |
| 18 | `is_ip` | `int` | `1` if hostname is a valid IPv4 or IPv6 address (`ipaddress.ip_address`), else `0` |
| 19 | `is_https` | `int` | `1` if URL scheme is `https`, else `0` |
| 20 | `is_suspicious_tld` | `int` | `1` if TLD matches 24 high-abuse TLDs (`xyz`, `top`, `buzz`, `tk`, `ml`, `ga`, `cf`, `gq`, etc.), else `0` |
| 21 | `has_hyphen_in_dom` | `int` | `1` if `-` appears in registered domain label, else `0` |
| 22 | `digit_ratio_dom` | `float` | Numeric digit count in domain divided by `dom_len` |
| 23 | `entropy_dom` | `float` | Shannon entropy (base 2) of the extracted domain string |

### C. Security Indicators (9 features)
| # | Feature Name | Type | Calculation |
| :- | :--- | :--- | :--- |
| 24 | `has_credentials` | `int` | `1` if `parsed.username` or `parsed.password` is present, else `0` |
| 25 | `has_at` | `int` | `1` if `@` symbol appears anywhere in URL, else `0` |
| 26 | `url_encoding_cnt` | `int` | Count of valid `%[0-9a-fA-F]{2}` hex percent-encoded sequences |
| 27 | `has_nested_encoding` | `int` | `1` if `%25[0-9a-fA-F]{2}` (double-encoding) is present, else `0` |
| 28 | `has_malformed_encoding` | `int` | `1` if total `%` count exceeds valid `%XX` sequences, else `0` |
| 29 | `suspicious_keyword_cnt` | `int` | Count of matches from 28 phishing keywords (`login`, `verify`, `secure`, `account`, `update`, `banking`, `password`, etc.) |
| 30 | `is_shortened` | `int` | `1` if registered domain or hostname is in 18 known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.), else `0` |
| 31 | `excessive_subdoms` | `int` | `1` if `subdom_cnt >= 3`, else `0` |
| 32 | `has_punycode` | `int` | `1` if `xn--` appears in hostname, else `0` |

### D. Overall Statistical Feature (1 feature)
| # | Feature Name | Type | Calculation |
| :- | :--- | :--- | :--- |
| 33 | `overall_entropy` | `float` | Shannon entropy $-\sum p(c)\log_2 p(c)$ over the entire URL string |

---

## 5. Preprocessing, Domain-Aware Splitting & Leakage Prevention

Implemented in [`ml_engine/preprocessing.py`](ml_engine/preprocessing.py):

### Domain-Aware Grouped Splitting
To prevent the classifiers from memorizing specific hostnames/domains seen during training, splitting uses `sklearn.model_selection.GroupShuffleSplit` grouped by `registered_domain` (`top_domain_under_public_suffix` from `tldextract`, `random_state=42`):

| Split | Records | % of Dataset | Legitimate (`0`) | Phishing (`1`) | Phishing Ratio | Unique Registered Domains |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Train** (`train.csv`) | `80,171` | `69.57%` | `69,272` | `10,899` | `13.59%` | `63,601` |
| **Validation** (`val.csv`) | `18,703` | `16.23%` | `14,852` | `3,851` | `20.59%` | `13,629` |
| **Test** (`test.csv`) | `16,357` | `14.19%` | `14,517` | `1,840` | `11.25%` | `13,629` |

- **Leakage Verification (`data/reports/data_split_report.json`):**
  - Train ∩ Validation domain overlap: **`0`**
  - Train ∩ Test domain overlap: **`0`**
  - Validation ∩ Test domain overlap: **`0`**
- **Limitation of Grouped Splitting:** Because `GroupShuffleSplit` splits by domain groups rather than individual rows, splits deviate slightly from exact 70/15/15 row ratios and class proportions (`20.59%` phishing in Val vs `11.25%` in Test) whenever certain domains (e.g., hosting platforms or multi-URL domains) carry many URLs of a single class.

### Preprocessing Pipelines
- **Logistic Regression:** `SimpleImputer(strategy="median")` → `StandardScaler()` → `LogisticRegression` (fitted strictly on `train.csv` inside the `Pipeline`).
- **Decision Tree & Random Forest:** `SimpleImputer(strategy="median")` → classifier (tree models are scale-invariant).
- No SMOTE or oversampling is applied before splitting. Imbalance is addressed inside each model via `class_weight="balanced"`.

---

## 6. Trained Models & Hyperparameters

Configured in [`ml_engine/config.py`](ml_engine/config.py) with `RANDOM_SEED = 42` and trained in [`ml_engine/train.py`](ml_engine/train.py):

1. **Logistic Regression:**
   - `C=1.0`, `max_iter=1000`, `class_weight="balanced"`, `solver="lbfgs"`, `random_state=42`
   - Standardized numerical features via `StandardScaler` inside `Pipeline`.
2. **Decision Tree:**
   - `max_depth=10`, `min_samples_split=10`, `min_samples_leaf=5`, `class_weight="balanced"`, `random_state=42`
   - Depth and leaf constraints limit overfitting on training domains.
3. **Random Forest:**
   - `n_estimators=100`, `max_depth=15`, `min_samples_split=10`, `min_samples_leaf=3`, `class_weight="balanced"`, `random_state=42`, `n_jobs=-1`

---

## 7. Evaluation Metrics, Model Comparison & Selection

### 7.1 Training, Validation & Test Results
All metrics below were measured directly on the 80,171 / 18,703 / 16,357 domain-aware splits. Model selection used **Validation metrics only**; `test.csv` remained unseen during training and selection (LR and DT test metrics were measured post-hoc for audit completeness).

| Model | Split | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Confusion Matrix (TN / FP / FN / TP) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Logistic Regression** | Train | 0.9475 | 0.7430 | 0.9381 | 0.8292 | 0.9839 | 65,735 / 3,537 / 675 / 10,224 |
| **Logistic Regression** | Val | 0.9301 | 0.7896 | 0.9005 | 0.8414 | 0.9738 | 13,928 / 924 / 383 / 3,468 |
| **Logistic Regression** | Test | 0.9288 | 0.6422 | 0.8283 | 0.7235 | 0.9677 | 13,668 / 849 / 316 / 1,524 |
| **Decision Tree** | Train | 0.9664 | 0.8228 | 0.9595 | 0.8859 | 0.9935 | 67,020 / 2,252 / 441 / 10,458 |
| **Decision Tree** | Val | 0.9511 | 0.8340 | 0.9522 | 0.8892 | 0.9750 | 14,122 / 730 / 184 / 3,667 |
| **Decision Tree** | Test | 0.9419 | 0.7133 | 0.8087 | 0.7580 | 0.8722 | 13,919 / 598 / 352 / 1,488 |
| **Random Forest** | Train | 0.9829 | 0.9079 | 0.9727 | 0.9392 | 0.9979 | 68,197 / 1,075 / 298 / 10,601 |
| **Random Forest** *(Selected)* | **Val** | **0.9581** | **0.8862** | **0.9140** | **0.8999** | **0.9895** | 14,400 / 452 / 331 / 3,520 |
| **Random Forest** *(Selected)* | **Test** | **0.9621** | **0.8135** | **0.8603** | **0.8362** | **0.9841** | 14,154 / 363 / 257 / 1,583 |

### 7.2 Selected Best Model & Rationale
- **Selected Model:** **Random Forest (`1.0.0`)**
- **Selection Rationale:** Random Forest achieved the highest validation **F1-score (`0.8999`)**, highest validation **Precision (`0.8862`)**, and highest validation **ROC-AUC (`0.9895`)** while preserving strong **Recall (`0.9140`)**. Although the single Decision Tree achieved slightly higher validation recall (`0.9522`), it produced `730` validation false positives (vs `452` for Random Forest) and dropped sharply on unseen test domains (`0.9750` Val AUC → `0.8722` Test AUC; `0.9522` Val Recall → `0.8087` Test Recall). Random Forest generalized best across unseen domains (`0.9841` Test ROC-AUC, `0.8603` Test Recall, `0.0250` FPR, `0.1397` FNR).

### 7.3 False Positives, False Negatives & Why Accuracy Is Misleading
- Because `85.6%` of the dataset is legitimate, a constant predictor returning `0` achieves `85.6%` accuracy with `0%` phishing detection. Therefore, **Recall**, **Precision**, **F1-Score**, and **ROC-AUC** are used instead of accuracy.
- **False Negatives (`257` on Test, `13.97%` FNR):** Missed phishing URLs expose end users to credential harvesting or malware; this is why ML scores should be combined with deterministic cybersecurity rules and threat intelligence.
- **False Positives (`363` on Test, `2.50%` FPR):** Flagging legitimate URLs disrupts normal browsing; Random Forest cut validation false positives by `38%` vs Decision Tree and `51%` vs Logistic Regression.
- All generated plots (`confusion_matrix_*.png`, `roc_curves.png`, `precision_recall_curves.png`, `model_comparison.png`, `feature_importance_rf.png`) and reports are saved under `data/reports/`.

---

## 8. Investigation: High-Risk URL False Negative Case Study

During audit testing, the synthetic high-risk URL:
```
http://secure-login.bank-update.account-verification.xyz/login.php?user=admin&token=123
```
received from the selected Random Forest model:
- `phishing_probability = 0.4285`
- `legitimate_probability = 0.5715`
- `prediction = "LEGITIMATE"` (`label = 0` at default `0.50` threshold)

### Root-Cause Findings
1. **Extracted Features & Metadata:**
   - `registered_domain = "account-verification.xyz"`, `url_len = 87`, `hostname_len = 49`, `dom_len = 20`, `subdom_cnt = 2`, `hyphen_cnt = 3`, `digit_cnt = 3`, `is_https = 0`, `is_suspicious_tld = 1`, `suspicious_keyword_cnt = 6`, `overall_entropy = 4.7227`.
2. **Dataset HTTP/HTTPS Skew (`is_https` = #1 RF Feature, importance `0.1413`):**
   - In `train.csv` (`URL-Phish` v2), **90.75% of phishing URLs use `https://`**, whereas **only 35.00% of benign URLs use `https://`** (benign URLs came from older institutional/ROR `.edu`/`.gov`/`.org` links).
   - Because `is_https` has the highest Gini importance (`0.1413`), `is_https = 0` routes samples into benign-weighted tree branches:
     - `is_https == 0 & subdom_cnt >= 2`: `2,163` benign vs `28` phishing in training (`98.7%` benign)
     - `is_https == 0 & has_hyphen_in_dom == 1`: `4,559` benign vs `523` phishing (`89.7%` benign)
3. **Rarity of Multi-Keyword + `.xyz` Patterns in Training:**
   - `is_suspicious_tld == 1` (`335` phishing vs `5` benign) and `suspicious_keyword_cnt >= 4` (`4` phishing vs `0` benign) are overwhelmingly phishing, but represent `<0.5%` of training rows, giving them low split frequency (`0.0046` and `0.0180` Gini importance).
4. **Tree Vote Polarization:**
   - Across the 100 trees, **51/100 trees** predicted individual probabilities `>= 0.50`, but tree leaf probabilities were polarized (`std = 0.4014`, `min = 0.0`, `max = 1.0`), pulling the mean probability down to `0.4285`.
   - For comparison on the same URL: **Logistic Regression** predicted `1.0000` (`PHISHING`), while **Decision Tree** predicted `0.0000` (`LEGITIMATE`).

### Validation-Only Experiments & Retention Decision
Two controlled experiments were evaluated strictly on `train.csv` + `val.csv` (`test.csv` untouched):

| Configuration | Val Accuracy | Val Precision | Val Recall | Val F1 | Val ROC-AUC | Val FP / FN | Probe URL `P(phish)` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline RF (33 features, retained)** | **0.9581** | **0.8862** | **0.9140** | **0.8999** | **0.9895** | **452 / 331** | `0.4285` |
| Exp A: Drop `is_https` (32 features) | 0.9526 | 0.8720 | 0.9024 | 0.8869 | 0.9860 | 510 / 376 | `0.6753` |
| Exp B: Deeper RF (`max_depth=25`, `leaf=1`, `n=200`) | 0.9627 | 0.8905 | 0.9338 | 0.9116 | 0.9917 | 442 / 255 | `0.5040` |

- **Why Baseline RF (`v1.0.0`) Is Retained:** Dropping `is_https` degrades in-distribution validation F1 (`0.8999 → 0.8869`) and increases both false positives (`+58`) and false negatives (`+45`). Increasing `max_depth=25, min_samples_leaf=1` barely moves the probe (`0.5040`) while risking overfitting to training noise and increasing artifact size.
- **How Dual-Engine Architecture Resolves It:** When evaluated independently by `security_engine` (`scan_static_url`), this exact URL receives **`WARN`** (`SUSPICIOUS_KEYWORDS` with `HIGH` severity for `['login', 'secure', 'account', 'update', 'bank']` in the hostname), while `ml_engine` reports a borderline `0.4285` phishing probability. In the combined Django decision layer, moderate ML suspicion (`0.4285`) + `HIGH`-severity cybersecurity rule findings naturally escalate risk without distorting ML probabilities.

---

## 9. Model Artifacts & Real-Time Prediction Contract

### Saved Artifacts (`ml_engine/models/`)
- `best_model.joblib` (`4,046,796` bytes): Full sklearn `Pipeline` (`SimpleImputer` + `RandomForestClassifier`).
- `model_metadata.json` (`4,544` bytes): Model name, version, training timestamp, dataset DOI, hyperparameters, random seed (`42`), validation/test metrics, and selection rationale.
- `feature_schema.json` (`898` bytes): Exact ordered list of the `33` features.

Managed via [`ml_engine/model_manager.py`](ml_engine/model_manager.py) (`save_model_artifact()`, `load_model_artifact()`).

### Integration Contract (`predict_url` & `MLInferencePipeline`)
- **Primary Function:** `ml_engine.predict.predict_url(url: str) -> Dict[str, Any]`
- **Class Interface:** `ml_engine.pipeline.MLInferencePipeline` (`predict()`, `predict_batch()`, `get_metadata()`, `format_combined_response()`)

**Success Output Schema:**
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
- `label`: `0` (`LEGITIMATE`) or `1` (`PHISHING`).
- `phishing_probability` & `legitimate_probability`: floats in `[0.0, 1.0]` summing to `1.0` (4-decimal rounding).
- **Error Handling:** Empty strings, `None`, non-strings, missing model artifacts (`FileNotFoundError`), or inference exceptions return `"status": "ERROR"`, `"prediction": "ERROR"`, `None` label/probabilities, and an `"error_message"` string. Unavailable models are **never** silently classified as legitimate.

### Django Backend Usage Example
```python
from ml_engine.pipeline import ml_pipeline

def scan_url_view(url: str):
    ml_result = ml_pipeline.predict(url)
    # Call cybersecurity components independently (see Section 10 regarding security_engine.py)
    # Combine ml_result["phishing_probability"] with cybersecurity risk_score/findings
    # in Django's policy layer to emit ALLOW / WARN / BLOCK.
    return ml_result
```

---

## 10. Cybersecurity Engine Findings & Offline Dependency Handling

### 10.1 Pre-Existing Import Issue in `security_engine/security_engine.py`
- **Finding:** [`security_engine/security_engine.py`](security_engine/security_engine.py) line 7 executes `from decision_engine import generate_security_report`, and line 28 calls `generate_security_report(url, features, findings)`. However, [`security_engine/decision_engine.py`](security_engine/decision_engine.py) only defines `determine_decision(risk_assessment, features)`. Importing `security_engine` as a wrapper therefore raises `ImportError: cannot import name 'generate_security_report'`.
- **Root Cause:** As shown in [`security_engine/security_validation_test.py`](security_engine/security_validation_test.py) (`scan_static_url`), the working pipeline calls `run_security_rules(features)` → `assess_risk(findings)` → `determine_decision(assessment, features)` directly; `security_engine.py` references an older or unimplemented helper name.
- **Proposed Correction (Not Applied — Awaiting Team Approval):** Keep `security_engine/` untouched per repository rules. When the cybersecurity team is ready to patch `security_engine/security_engine.py`, replace `generate_security_report` with `assess_risk` + `determine_decision`:
  ```python
  assessment = assess_risk(findings)
  decision = determine_decision(assessment, features)
  ```

### 10.2 Offline Dependency Handling
- **`ml_engine` (100% Offline Inference & Training):** `ml_engine/feature_extraction.py` configures `tldextract.TLDExtract(cache_dir=str(TLD_CACHE_DIR), fallback_to_snapshot=True, suffix_list_urls=None)` so zero network calls occur during feature extraction, training, or prediction. Network access is only required if re-downloading the raw dataset from Mendeley Data via `python -m ml_engine.dataset_loader`.
- **`security_engine` (Requires `TLDEXTRACT_CACHE` Offline):** `security_engine/url_analyzer.py` calls default `tldextract.extract(hostname)`, which attempts to lock Python's `site-packages/tldextract/.suffix_cache` and fetch the Public Suffix List if uncached. When running `security_engine` offline, set:
  ```powershell
  $env:TLDEXTRACT_CACHE="data/.tld_cache"
  ```
  Additionally, `security_engine/redirect_analyzer.py` and `security_engine/update_threat_feeds.py` perform live HTTP requests by design, while `security_engine/threat_intel.py` reads the local `data/threat_feeds/openphish.txt` file offline.

---

## 11. Known Limitations & Repository Hygiene

1. **Static URL Analysis Only:** `ml_engine` inspects lexical, structural, domain, and entropy properties of the URL string. It does not inspect webpage HTML/DOM content, TLS certificates, WHOIS domain age, DNS records, or live redirect chains.
2. **Dataset Collection Bias:** *URL-Phish* exhibits an HTTP/HTTPS bias (`90.75%` of phishing URLs use HTTPS vs `35.00%` of benign URLs), reducing sensitivity on synthetic `http://` phishing URLs unless paired with `security_engine` rules or retrained on a balanced modern HTTPS benign corpus.
3. **Class Imbalance (`5.95 : 1`):** Handled via `class_weight="balanced"`, without synthetic oversampling.
4. **Shortened URLs & Zero-Day Content:** Shortened URLs (`bit.ly`, etc.) reveal limited lexical signal statically; expanding redirects requires live network checks in `security_engine/redirect_analyzer.py`.
5. **`.gitignore` Policy:** Large raw datasets (`data/raw/`), generated feature splits (`data/processed/`), local PSL cache (`data/.tld_cache/`), and `*.lock` files are excluded via `.gitignore` so the repository remains lightweight while keeping reproducible pipeline scripts and `requirements.txt` tracked.
