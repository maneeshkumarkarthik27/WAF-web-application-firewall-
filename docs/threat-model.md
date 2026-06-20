# Threat Model

## Assets

- Protected web application.
- Session cookies and credentials.
- Application data in transit.
- Security telemetry and offender history.

## Threats Covered

- SQL injection.
- Cross-site scripting.
- Command injection.
- Directory traversal.
- Malicious scanners and basic bot traffic.
- Brute-force and burst traffic.

## Trust Boundaries

- Internet to WAF.
- WAF to protected application.
- WAF to local database.

## Assumptions

- The WAF is deployed in front of one or more internal applications.
- Upstream applications are not directly exposed to the Internet.
- Blocking hooks will be replaced with OS-level enforcement in hardened environments.

## Residual Risk

- Regex rules can produce false positives and false negatives.
- Encrypted payloads and multi-stage attacks may evade static signatures.
- A future behavioral or ML layer is required for stronger anomaly detection.
