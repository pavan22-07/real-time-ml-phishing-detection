# Testing and Regression Guide

Run commands from the repository root unless noted.

## Full suite

```powershell
python -m pytest -q
```

## Focused suites

```powershell
python -m pytest security_engine
python -m pytest ml_engine/tests
python -m pytest unified_engine/tests
python backend/manage.py test accounts scans -v 2
```

Use the current command output as the authoritative test count. Historical test totals in old screenshots or notes should not be copied into documentation without rerunning the suite.

## High-value regression scenarios

| Category | Example input | Expected property |
|---|---|---|
| Legitimate | `https://www.wikipedia.org/` | No fabricated threat finding; combined ALLOW only when both engines are healthy and benign. |
| Generic credential wording | `https://example.test/login` | Generic login term alone must not trigger the protected-brand compound BLOCK condition. |
| Protected brand + strong credential context | `https://paypal.com.example.test/login/password-reset` | High-confidence brand impersonation plus strong credential context should trigger cybersecurity BLOCK. |
| Legitimate protected brand domain | `https://www.paypal.com/login` | The genuine protected brand domain must not be mistaken for a subdomain impersonation. |
| ML-only phishing prediction | Controlled ML suspicious result with benign cybersecurity result | Combined policy returns WARN, not BLOCK. |
| ML unavailable + security BLOCK | Security BLOCK and ML error | Final decision remains BLOCK. |
| Security inspection degraded | Security engine degraded/unknown | Must not silently ALLOW. |

The `.test` examples are reserved test inputs and should be submitted only to the local scanner, not opened in a browser.

## Security invariants to preserve

- ML alone never triggers automatic BLOCK.
- A confirmed cybersecurity BLOCK cannot be downgraded by ML.
- Stale, unavailable or malformed threat-intelligence data must not be treated as evidence of safety.
- Redirect inspection stays disabled by default.
- SSRF protections, TLS verification, connection pinning and proxy bypass protections must not be weakened.
- Raw ML probability must remain explicitly uncalibrated unless a calibration process is implemented and validated.

## Before committing

```powershell
git status --short
git diff --check
python -m pytest -q
```

Review generated artifacts and secrets before staging. Documentation-only edits should not modify engine code or model artifacts.
