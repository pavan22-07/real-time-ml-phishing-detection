# SecureLens Architecture

## Runtime request flow

```text
React frontend
    |
    | POST /api/v1/scans/ (JWT)
    v
Django REST Framework
    |
    v
backend/scans/services.py
    |
    v
unified_engine.detector.scan_url()
    |
    +-------------------------------+
    |                               |
    v                               v
Cybersecurity adapter           ML adapter
security_engine                 ml_engine
    |                               |
    +---------------+---------------+
                    |
                    v
        unified_engine/policy.py
                    |
                    v
          ALLOW / WARN / BLOCK / ERROR
                    |
                    v
       Django ScanHistory persistence
                    |
                    v
          Serialized API response
```

## Component ownership

| Component | Responsibility |
|---|---|
| `frontend/` | User interface and API client; displays API results rather than reimplementing policy. |
| `backend/accounts/` | Registration, authentication and profile endpoints. |
| `backend/scans/` | Request validation, orchestration, persistence, history and dashboard statistics. |
| `security_engine/` | Deterministic URL analysis, security rules, threat-intelligence checks, risk scoring and security verdict. |
| `ml_engine/` | Static feature extraction and trained-model inference. |
| `unified_engine/adapters.py` | Independent engine invocation, fault isolation and normalization to `EngineResult`. |
| `unified_engine/policy.py` | Authoritative combined decision precedence. |
| `unified_engine/detector.py` | Orchestrates validation, adapters and combined policy. |

## Decision ownership and invariants

- Security rules and risk scoring belong to `security_engine`; the ML predictor does not mutate them.
- ML returns a class prediction and an uncalibrated probability. It does not own ALLOW/WARN/BLOCK policy.
- A cybersecurity `MALICIOUS` verdict backed by a raw `BLOCK` decision is authoritative.
- ML-only suspicion can escalate to `WARN`, never automatic `BLOCK`.
- Engine errors, degraded inspection and unknown verdicts must not silently become `ALLOW`.
- Redirect inspection is disabled by default.

## Persistence

`backend/scans/models.py` stores the final decision, cybersecurity verdict and risk score, ML prediction and raw probability, degraded-mode flag, per-engine statuses, reasons, warnings, errors and complete result. Scan history is scoped to the authenticated user by the API views.

## Local development ports

The Vite frontend uses port `3000` and proxies `/api` to Django at `127.0.0.1:8000` in the provided configuration. Start Django from `backend/` with:

```powershell
python manage.py runserver 127.0.0.1:8000
```

Do not use `--noreload` during active development if you expect Django's autoreloader to pick up changes.
