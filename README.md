# Real-Time ML-Based Phishing Detection & Prevention System

A hybrid, defense-in-depth cybersecurity and machine learning platform for real-time phishing URL detection and automated threat prevention.

Repository: `https://github.com/pavan22-07/real-time-ml-phishing-detection`  
Active Branch: `ml-module-development`

---

## 1. System Architecture

The platform operates as a dual-engine architecture coordinated by a unified decision layer. The deterministic **Cybersecurity Engine** and the statistical **Machine Learning Engine** evaluate submitted URLs independently without shared mutable state or mutual dependencies.

```
                                  Target URL
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        Cybersecurity Engine                     Machine Learning Engine
         (`security_engine`)                         (`ml_engine`)
    ┌──────────────────────────────┐       ┌──────────────────────────────┐
    │ - Lexical & Structure Rules  │       │ - 33 Static URL Features     │
    │ - IDN Homograph & Punycode   │       │ - Offline TLD Extraction     │
    │ - Brand Impersonation        │       │ - Random Forest Classifier   │
    │ - Local Threat Intel Feed    │       │ - Strict `classes_` Mapping  │
    │ - SSRF-Safe Redirect Analysis│       │ - Raw Phishing Probability   │
    │ - Risk Score (0 - 100)       │       └──────────────┬───────────────┘
    └──────────────┬───────────────┘                      │
                   │                                      │
                   ▼                                      ▼
        Cybersecurity Result                       ML Prediction
        (Verdict, Score, Signals)             (Probability, Class, Status)
                   │                                      │
                   └──────────────────┬───────────────────┘
                                      │
                                      ▼
                        Unified Engine Adapter Layer
                            (`unified_engine`)
                      - Input validation & isolation
                      - Scale & contract normalization
                      - Fault containment (no cross-engine crashes)
                                      │
                                      ▼
                        Combined Decision Policy Layer
                                (`policy.py`)
                      - Evaluates authoritative rules
                      - Enforces fail-safe escalation
                                      │
                                      ▼
                   Final Verdict: ALLOW / WARN / BLOCK / ERROR
```

---

## 2. Component Responsibilities

### 2.1 Cybersecurity Engine (`security_engine/`)
- **`url_analyzer.py`**: Static lexical, structural, and encoding parser. Evaluates URL credentials (`user:pass@host`), IP-in-hostname, character distributions, nested/malformed percent-encoding, and IDN homoglyphs. Uses a locally cached, offline-configured `tldextract` extractor (`data/.tld_cache/`) to eliminate external PSL queries.
- **`rule_engine.py`**: Evaluates 11 deterministic security rules (IP hostname, credentials, suspicious keywords, excessive subdomains, length, domain similarity, brand impersonation, IDN homographs, redirect behavior, threat intelligence).
- **`risk_scoring.py`**: Calculates confidence-weighted risk scores (`0 - 100`) grouped by evidence categories (`url_structure`, `brand_identity`, `redirect_behavior`, `threat_reputation`) with category caps to prevent score distortion from correlated findings.
- **`decision_engine.py`**: Maps cybersecurity findings and scores to `ALLOW`, `WARN`, or `BLOCK`. Enforces that critical/high-severity findings or IP-based hosts cannot result in `ALLOW`.
- **`threat_intel.py`**: Local OpenPhish threat intelligence feed parser. Performs exact URL and subdomain/hostname matching. Validates feed file integrity against metadata SHA-256 checksums and detects `FRESH`, `STALE` (> 24 hours), `UNAVAILABLE`, and `MALFORMED` states.
- **`redirect_analyzer.py`**: SSRF-hardened HTTP/HTTPS redirect tracer. Pins connections directly to pre-validated public IPs to prevent DNS rebinding and TOCTOU vulnerabilities, while preserving TLS SNI and Host headers.

### 2.2 Machine Learning Engine (`ml_engine/`)
- **`feature_extraction.py`**: Extracts 33 engineered numeric and boolean URL features without network access.
- **`model_manager.py`**: Verifies and loads the serialized scikit-learn pipeline artifact (`best_model.joblib`), metadata, and feature schema.
- **`predict.py`**: Performs real-time inference. Dynamically maps probability columns using `estimator.classes_` to eliminate class-ordering assumptions, validates probability values (`sum ≈ 1.0`), and preserves `is_calibrated=False`.
- **`pipeline.py` & `train.py`**: Training pipeline using domain-aware cross-validation and evaluation across Logistic Regression, Decision Tree, and Random Forest models.

### 2.3 Unified Engine (`unified_engine/`)
- **`contracts.py`**: Defines typed `EngineResult` contracts ensuring strict scale separation (`cybersecurity_risk_score` in `0 - 100` vs `ml_raw_phishing_probability` in `0.0 - 1.0`).
- **`adapters.py`**: Wraps both engines with boundary input validation and exception isolation so a crash in one engine cannot crash the other.
- **`policy.py`**: Authoritative policy combining both engines into final operational decisions.
- **`detector.py`**: Top-level API entry point (`scan_url(url, inspect_redirects=False)`).

---

## 3. Unified Decision Policy

The combined decision layer enforces strict fail-safe rules:

| Condition | Final Decision | Degraded Mode | Rationale |
|:---|:---:|:---:|:---|
| Cybersecurity returns `BLOCK` (`MALICIOUS`) | **`BLOCK`** | Preserved | Authoritative threat; never downgraded by ML benign prediction or ML failure. |
| Both engines fail / return `ERROR` | **`ERROR`** | `True` | Complete inspection failure; fail-closed. |
| Either engine flags `SUSPICIOUS` | **`WARN`** | Preserved | Suspicious indicators detected; escalated for review. |
| ML flags `MALICIOUS` / `PHISHING` alone | **`WARN`** | Preserved | ML statistical prediction alone never triggers auto-BLOCK. |
| One engine fails or returns incomplete verification | **`WARN`** | `True` | Degraded inspection; fail-safe escalation prevents unverified access. |
| Both engines healthy and report `BENIGN` | **`ALLOW`** | `False` | Clean static analysis and ML probability confirmation. |

---

## 4. Redirect Inspection and SSRF Protection

`security_engine/redirect_analyzer.py` provides defense against Server-Side Request Forgery (SSRF) and DNS Rebinding:

1. **Pre-Flight Destination Resolution**: All destination IPs are resolved via `socket.getaddrinfo` prior to any connection attempt.
2. **Strict IP Filtering**: Rejects loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, reserved, unspecified, and IPv4-mapped IPv6 non-public addresses (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`).
3. **Cloud Metadata Protection**: Explicitly blocks cloud metadata IPs and hostnames (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, `metadata.google.internal`).
4. **Anti-TOCTOU Connection Pinning**: Mounts `SSRFPinnedAdapter` to ensure the HTTP client connects directly to the validated IP address. This prevents a secondary DNS resolution that could rebind to an internal address.
5. **TLS Host & SNI Preservation**: Passes the original hostname to TLS `server_hostname` and HTTP `Host` headers so certificate validation and virtual hosting function correctly.
6. **Hop-by-Hop Revalidation**: Each redirect hop is validated independently. Redirects to private destinations or metadata endpoints abort immediately.
7. **Safe Constraints**: Maximum 10 redirects, explicit timeouts `(connect=3s, read=5s)`, streaming headers without downloading full bodies, and `trust_env=False` to prevent inheriting untrusted proxy settings.

> **Operational Note:** Redirect inspection requires network access and is disabled by default (`inspect_redirects=False`) for static scans.

---

## 5. Environment & Installation

### Prerequisites
- Python: `3.10` to `3.13`
- PowerShell (Windows) or Bash (Linux/macOS)

### Clean Environment Installation (PowerShell)

```powershell
# 1. Clone repository and checkout development branch
git clone https://github.com/pavan22-07/real-time-ml-phishing-detection.git
cd real-time-ml-phishing-detection
git checkout ml-module-development

# 2. Create clean virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install pinned dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 4. Verify installation
python -c "import sklearn, pandas, numpy, joblib, tldextract, requests, pytest; print('All dependencies imported successfully!')"
```

### Dependency Specifications (`requirements.txt`)
- `scikit-learn==1.9.1`: Matches the serialized model artifact.
- `pandas>=2.2.0,<4.0.0`: Data cleaning and DataFrame processing.
- `numpy>=2.0.0,<3.0.0`: Array and numerical computing.
- `joblib>=1.3.0,<=1.6.0`: Model pipeline serialization.
- `tldextract>=5.1.0,<=5.4.0`: Public suffix extraction with offline local cache.
- `requests>=2.31.0,<=2.34.2`: Safe HTTP communication.
- `urllib3>=2.0.0,<3.0.0`: Low-level socket and connection pool handling.
- `matplotlib>=3.7.0,<=3.10.8`: Evaluation charts and confusion matrices.
- `pytest>=7.4.0,<=9.2.0`: Test runner and assertions.

---

## 6. Threat Feed Operations

The OpenPhish community feed provides local indicators of compromise:

```powershell
# Update threat feed with SHA-256 verification and atomic file swap
python -m security_engine.update_threat_feeds
```

- Feed data: `data/threat_feeds/openphish.txt`
- Metadata: `data/threat_feeds/openphish_metadata.json`
- Feeds older than 24 hours are marked `STALE`, which preserves fail-safe escalation to `WARN` rather than treating stale feeds as proof of legitimacy.

---

## 7. Model Training & Evaluation

The production model is a **Random Forest Classifier** trained on the *URL-Phish* dataset (DOI: `10.17632/65z9twcx3r.2`):

- **Train Records:** 80,171 (70%)
- **Validation Records:** 18,703 (15%)
- **Holdout Test Records:** 16,357 (15%)
- **Domain-Aware Splitting:** Registered domains do not leak across splits.

### Measured Evaluation Metrics (Holdout Test Set)

| Metric | Measured Value |
|:---|:---:|
| **Accuracy** | **96.21%** |
| **Precision** | **81.35%** |
| **Recall** | **86.03%** |
| **F1-Score** | **83.62%** |
| **ROC-AUC** | **98.41%** |
| **True Negatives (TN)** | 14,154 |
| **False Positives (FP)** | 363 |
| **False Negatives (FN)** | 257 |
| **True Positives (TP)** | 1,583 |

---

## 8. Backend REST API Architecture (`backend/`)

The backend wraps the Unified Engine in a production-ready Django REST Framework API with PostgreSQL persistence and JWT authentication.

```
                           React / Client Application
                                      │
                                      ▼
                        [ HTTPS / CORS Middleware ]
                                      │
                                      ▼
                           Django REST Framework
                      ┌───────────────────────────────┐
                      │  - Scoped Rate Throttling     │
                      │  - SimpleJWT Authentication   │
                      │  - Serializer Validation      │
                      │  - Safe Exception Handler     │
                      └──────────────┬────────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
          Accounts Module                           Scans Module
        (`backend/accounts/`)                   (`backend/scans/`)
     ┌────────────────────────┐              ┌────────────────────────┐
     │ - User Registration    │              │ - URL Validation       │
     │ - JWT Token Issuance   │              │ - Scan Service Layer   │
     │ - Profile Management   │              │ - Scan History (UUID)  │
     │ - Password Hashing     │              │ - Dashboard Stats      │
     └────────────────────────┘              └───────────┬────────────┘
                                                         │
                                                         ▼
                                                Unified Engine API
                                           (`unified_engine.detector`)
                                            scan_url(url, inspect=False)
                                                         │
                                                         ▼
                                                PostgreSQL Database
                                           (`ScanHistory` / `auth_user`)
```

### 8.1 Backend Endpoints Summary

| Method | Endpoint | Auth Required | Description |
|:---|:---|:---:|:---|
| `POST` | `/api/v1/auth/register/` | No | User registration with password validation; issues JWT token pair. |
| `POST` | `/api/v1/auth/login/` | No | Authenticate credentials; issues JWT token pair. Throttled (`15/min`). |
| `POST` | `/api/v1/auth/token/refresh/` | No | Refresh an expired access token using a valid refresh token. |
| `GET` | `/api/v1/auth/profile/` | **Yes (JWT)** | Retrieve the authenticated user's profile. |
| `POST` | `/api/v1/scans/` | **Yes (JWT)** | Submit URL for static unified phishing detection. Throttled (`60/min`). |
| `GET` | `/api/v1/scans/` | **Yes (JWT)** | Paginated history of user's own scans (newest first). |
| `GET` | `/api/v1/scans/<id>/` | **Yes (JWT)** | Retrieve detailed scan record by UUID (isolated by user; 404 for others). |
| `GET` | `/api/v1/dashboard/stats/` | **Yes (JWT)** | Aggregated scan metrics (totals, decisions, recent count, latest timestamp). |

---

## 9. Backend Setup & Startup Instructions

### 9.1 Environment Configuration (`.env`)

Copy the template `.env.example` to `.env` in the repository root and configure PostgreSQL credentials:

```ini
# Django Security Settings
SECRET_KEY=your-production-secret-key-here
DEBUG=False
ALLOWED_HOSTS=127.0.0.1,localhost

# PostgreSQL Database Configuration
DB_NAME=phishing_detection_db
DB_USER=postgres
DB_PASSWORD=your_secure_db_password
DB_HOST=localhost
DB_PORT=5432

# CORS Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

> **Testing Fallback:** When `DB_NAME` is empty or unset, Django automatically falls back to an isolated SQLite database (`backend/db.sqlite3`), facilitating rapid local testing without a live PostgreSQL service.

### 9.2 Database Migrations

Apply the database schema migrations to PostgreSQL:

```powershell
python backend/manage.py migrate
```

### 9.3 Development Server Startup

Launch the Django development server:

```powershell
python backend/manage.py runserver 127.0.0.1:8000
```

The API will be accessible at `http://127.0.0.1:8000/api/v1/`.

---

## 10. API Documentation & Examples

### 10.1 Authentication (`/api/v1/auth/`)

#### 1. User Registration (`POST /api/v1/auth/register/`)

**Request:**
```json
POST /api/v1/auth/register/
Content-Type: application/json

{
    "username": "analyst1",
    "email": "analyst1@example.com",
    "password": "SecurePassword123!",
    "password_confirm": "SecurePassword123!"
}
```

**Response (`201 Created`):**
```json
{
    "message": "User registered successfully.",
    "user": {
        "id": 1,
        "username": "analyst1",
        "email": "analyst1@example.com",
        "first_name": "",
        "last_name": "",
        "date_joined": "2026-11-17T17:35:00.000000Z",
        "last_login": null,
        "is_staff": false
    },
    "tokens": {
        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
}
```

#### 2. User Login (`POST /api/v1/auth/login/`)

**Request:**
```json
POST /api/v1/auth/login/
Content-Type: application/json

{
    "username": "analyst1",
    "password": "SecurePassword123!"
}
```

**Response (`200 OK`):**
```json
{
    "message": "Authentication successful.",
    "user": {
        "id": 1,
        "username": "analyst1",
        "email": "analyst1@example.com",
        "first_name": "",
        "last_name": "",
        "date_joined": "2026-11-17T17:35:00.000000Z",
        "last_login": "2026-11-17T17:36:00.000000Z",
        "is_staff": false
    },
    "tokens": {
        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
}
```

#### 3. Token Refresh (`POST /api/v1/auth/token/refresh/`)

**Request:**
```json
POST /api/v1/auth/token/refresh/
Content-Type: application/json

{
    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (`200 OK`):**
```json
{
    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 10.2 URL Scanning (`/api/v1/scans/`)

All scan endpoints require the `Authorization` header:
```text
Authorization: Bearer <access_token>
```

#### 1. Submit Scan (`POST /api/v1/scans/`)

**Request:**
```json
POST /api/v1/scans/
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
    "url": "https://example.com"
}
```

**Response (`201 Created`):**
```json
{
    "id": "e2f1837a-42c2-4cf4-9c3f-c96ec7f86f6d",
    "url": "https://example.com",
    "final_decision": "ALLOW",
    "degraded_mode": false,
    "cybersecurity": {
        "status": "OK",
        "verdict": "BENIGN",
        "risk_score": 0
    },
    "machine_learning": {
        "status": "OK",
        "prediction": "LEGITIMATE",
        "raw_phishing_probability": 0.0768,
        "is_calibrated": false
    },
    "reasons": [
        "Clean static analysis and ML probability confirmation."
    ],
    "warnings": [],
    "timestamp": "2026-11-17T17:40:00.000000Z"
}
```

#### 2. Scan History (`GET /api/v1/scans/`)

**Request:**
```text
GET /api/v1/scans/?page=1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (`200 OK`):**
```json
{
    "count": 42,
    "next": "http://127.0.0.1:8000/api/v1/scans/?page=2",
    "previous": null,
    "results": [
        {
            "id": "e2f1837a-42c2-4cf4-9c3f-c96ec7f86f6d",
            "url": "https://example.com",
            "final_decision": "ALLOW",
            "degraded_mode": false,
            "cybersecurity": {
                "status": "OK",
                "verdict": "BENIGN",
                "risk_score": 0
            },
            "machine_learning": {
                "status": "OK",
                "prediction": "LEGITIMATE",
                "raw_phishing_probability": 0.0768,
                "is_calibrated": false
            },
            "reasons": ["Clean static analysis and ML probability confirmation."],
            "warnings": [],
            "timestamp": "2026-11-17T17:40:00.000000Z"
        }
    ]
}
```

#### 3. Single Scan Record (`GET /api/v1/scans/<id>/`)

**Request:**
```text
GET /api/v1/scans/e2f1837a-42c2-4cf4-9c3f-c96ec7f86f6d/
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (`200 OK`):**
Returns the detailed `ScanResponseSerializer` record. Non-existent UUIDs or records owned by other users return `404 Not Found`.

---

### 10.3 Dashboard Statistics (`/api/v1/dashboard/stats/`)

**Request:**
```text
GET /api/v1/dashboard/stats/
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (`200 OK`):**
```json
{
    "total_scans": 25,
    "total_allow": 18,
    "total_warn": 4,
    "total_block": 3,
    "total_error": 0,
    "recent_scans_count": 7,
    "latest_scan_timestamp": "2026-11-17T17:40:00.000000Z"
}
```

---

## 11. Automated Testing

All tests run completely offline without external network dependencies.

```powershell
# 1. Run all tests via pytest (Full Suite: 219 tests)
python -m pytest -q

# 2. Run Django REST API test suite separately (28 tests)
python backend/manage.py test accounts scans -v 2

# 3. Run Cybersecurity Engine tests (108 tests)
pytest security_engine

# 4. Run Machine Learning Engine tests (47 tests)
pytest ml_engine/tests

# 5. Run Unified Engine tests (36 tests)
pytest unified_engine/tests
```

### Measured Test Suite Summary

| Test Suite | Path | Tests Collected | Passed | Failed | Skipped | Subtests |
|:---|:---|:---:|:---:|:---:|:---:|:---:|
| **Cybersecurity Engine** | `security_engine/` | 108 | 108 | 0 | 0 | 48 |
| **Machine Learning Engine** | `ml_engine/tests/` | 47 | 47 | 0 | 0 | 0 |
| **Unified Engine** | `unified_engine/tests/` | 36 | 36 | 0 | 0 | 10 |
| **Django REST API** | `backend/accounts/` & `backend/scans/` | 28 | 28 | 0 | 0 | 0 |
| **Full Combined Regression** | All Modules (`pytest -q`) | **219** | **219** | **0** | **0** | **58** |

---

## 12. End-to-End Validation Examples

```python
from unified_engine.detector import scan_url

# Example 1: Legitimate domain with fresh feed
result = scan_url("https://www.wikipedia.org/")
# final_decision: "ALLOW" (or "WARN" if local threat feed is STALE)
# risk_score: 0.0, raw_phishing_probability: 0.0467

# Example 2: Brand impersonation phishing URL
result = scan_url("https://paypal.com.evil-site.com/login")
# final_decision: "WARN"
# risk_score: 23.0, raw_phishing_probability: 0.7315

# Example 3: IP-based login URL
result = scan_url("http://192.0.2.10/login")
# final_decision: "WARN"
# risk_score: 13.0, raw_phishing_probability: 0.6550

# Example 4: Known threat intelligence indicator
result = scan_url("http://351312.cc/")
# final_decision: "BLOCK"
# Confirmed threat match overrides ML benign prediction
```

---

## 10. Known Limitations

1. **Airgapped Threat Feeds:** The threat intelligence feed must be updated periodically (`python -m security_engine.update_threat_feeds`). In environments without scheduled updates, feeds older than 24 hours transition to `STALE`, causing benign URLs to escalate to `WARN` (fail-safe by design).
2. **Uncalibrated ML Probabilities:** ML probabilities are raw Random Forest tree-vote fractions (`is_calibrated=False`). They provide relative statistical ranking rather than true posterior probabilities.
3. **Live Redirects in Sandbox/Airgap:** Redirect analysis requires outbound network connectivity and is disabled by default (`inspect_redirects=False`). When enabled, non-public IPs are safely rejected.
