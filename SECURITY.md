# Security Policy

## Supported Versions

Albator is under active development. Security fixes are provided for:

| Version | Supported |
|---------|-----------|
| `main` branch (latest) | Yes |
| Tagged releases from the last 6 months | Best effort |
| Older snapshots / forks | No |

## Reporting a Vulnerability

Please do **not** open public GitHub issues for suspected security vulnerabilities.

Use one of these channels:

1. **Preferred:** GitHub private vulnerability reporting (Security Advisories)
2. Open a draft advisory in this repository if you have access
3. If private reporting is unavailable, open an issue with minimal details and request a private channel

When reporting, include:

- affected component or file path
- exact reproduction steps
- impact (what an attacker can do)
- environment details (macOS version, shell, Python version)
- proof-of-concept (if safe to share)

## Response Process

- Initial acknowledgment target: **within 72 hours**
- Triage target: **within 7 days**
- Patch target: depends on severity and complexity

Severity guide:

- **Critical/High:** prioritized immediate triage and patching
- **Medium:** patched in next planned maintenance window
- **Low:** best-effort fix or hardening guidance

## Disclosure Policy

- Please allow time for investigation and remediation before public disclosure.
- Coordinated disclosure is preferred.
- We will credit reporters unless anonymity is requested.

## Scope Notes

This project includes scripts that can modify local system security settings. Reports are most actionable when they identify:

- command injection or privilege escalation paths
- insecure default configurations
- unsafe file handling / backup handling
- broken or bypassable preflight/safety checks

Out of scope by default:

- purely local misconfiguration with no security impact
- issues requiring physical access with no meaningful escalation

## Operational Safety

For safe testing:

- use `--dry-run` where available
- run preflight first: `python3 albator_cli.py preflight --json`
- avoid mutating tests on production systems
