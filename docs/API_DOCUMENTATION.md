# Backend API Reference

Base URL for local development: `http://127.0.0.1:8000`

Protected endpoints use a JWT access token:

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

## Authentication

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/auth/register/` | Register a user and issue tokens. |
| POST | `/api/v1/auth/login/` | Authenticate and issue tokens. |
| POST | `/api/v1/auth/token/refresh/` | Refresh an access token. |
| GET | `/api/v1/auth/profile/` | Retrieve the authenticated user's profile. |

Use the request fields defined by `backend/accounts/serializers.py`; those serializers are the source of truth if this document and implementation differ.

## Scans

### Submit a URL

`POST /api/v1/scans/` (authenticated; returns `201 Created`)

Request:

```json
{
  "url": "https://example.com/"
}
```

The API validates a non-empty URL string (maximum 2048 characters), runs the unified detection pipeline and stores a scan-history record.

Response shape:

```json
{
  "id": "scan-uuid",
  "url": "https://example.com/",
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
    "raw_phishing_probability": 0.12,
    "is_calibrated": false
  },
  "reasons": [],
  "warnings": [],
  "timestamp": "2026-01-01T00:00:00Z"
}
```

The values above illustrate the response structure only; they are not a promised prediction for the example URL. ML probability is uncalibrated.

### Scan history

`GET /api/v1/scans/` returns the authenticated user's paginated scan history, newest first.

### Retrieve one scan

`GET /api/v1/scans/{id}/` retrieves a scan by UUID. Records belonging to another user are not exposed.

## Dashboard

`GET /api/v1/dashboard/stats/` returns totals for ALLOW, WARN, BLOCK and ERROR decisions, recent scan count and latest scan timestamp.

## Decision values

| Value | Meaning |
|---|---|
| `ALLOW` | Both engines are healthy and benign under the combined policy. |
| `WARN` | Suspicious indicators or incomplete/degraded verification require caution. |
| `BLOCK` | Authoritative cybersecurity engine block. |
| `ERROR` | Both engines failed according to combined-policy error handling. |

See `backend/scans/serializers.py`, `backend/scans/views.py` and `unified_engine/policy.py` for the live contract and behavior.
