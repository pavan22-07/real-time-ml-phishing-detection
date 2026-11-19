# Cybersecurity Engine

## Scope

`security_engine/` performs deterministic static URL analysis and returns structured features, findings, a risk assessment and a security decision. The unified engine consumes this result through `unified_engine/adapters.py`.

## Detection coverage

Implemented rules include URL structure and lexical indicators, IP-address hosts, suspicious keywords, excessive subdomains, suspicious ports and file extensions, encoding, domain similarity, protected-brand impersonation, brand-plus-credential context, IDN homographs, redirects (when explicitly enabled), and local threat-intelligence matches. The exact active rule inventory is defined in `security_engine/rule_engine.py`; consult that file when updating this list.

## Risk scoring

`security_engine/risk_scoring.py` calculates a confidence-weighted score on a 0–100 scale. Findings are grouped into evidence categories with group caps to reduce over-counting correlated indicators. A risk score is not the same as the ML phishing probability.

## Decision behavior

`security_engine/decision_engine.py` determines the cybersecurity decision from findings and features. High-confidence protected-brand impersonation combined with strong credential/payment context is a compound attack condition. The unified adapter maps:
- `ALLOW` → `BENIGN`
- `WARN` → `SUSPICIOUS`
- `BLOCK` → `MALICIOUS`

The combined policy preserves an authoritative cybersecurity `BLOCK`. ML does not downgrade it.

## Threat intelligence

The local feed is read by `security_engine/threat_intel.py`. Feed freshness, availability and malformed data are inspection-state concerns; a missing or stale feed is not proof of legitimacy. Follow the feed updater's own instructions before replacing feed files.

## Redirect and SSRF safety

Redirect inspection is disabled by default. When explicitly enabled, the redirect analyzer applies destination validation and connection-safety controls. Do not bypass its IP validation, TLS verification, connection pinning, proxy isolation or per-hop checks.

## Testing

Run:

```powershell
python -m pytest security_engine
python -m pytest unified_engine/tests
```

Add regression tests when changing a rule, score, threshold, evidence grouping or decision precedence. Include positive, negative and boundary cases, and verify the unified policy still preserves security BLOCK.
