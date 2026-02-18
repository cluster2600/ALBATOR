# Core vs Optional Components

This file defines what is production-core in this repository and what is optional/experimental.

## Core (maintained, expected to work in this checkout)

- `albator_cli.py`
- `preflight.py`
- `main.py`
- `rule_handler.py`
- `utils.py`
- Shell hardening scripts:
  - `privacy.sh`
  - `firewall.sh`
  - `encryption.sh`
  - `app_security.sh`
  - `cve_fetch.sh`
  - `apple_updates.sh`
  - `reporting.sh`
- Rule/config data:
  - `rules/*.yaml`
  - `includes/*.yaml`
  - `config/albator.yaml`
  - `config/profiles/macos_26_3.yaml`
  - `VERSION.yaml`
- Tests/validation:
  - `tests/test_core_behaviors.py`
  - `tests/test_framework.py`
  - `tests/test_security.sh`
  - `.github/workflows/core-tests.yml`

## Optional (best-effort, may have reduced functionality)

- `albator_enhanced.py`
  - Runs core script orchestration even when optional backend modules are missing.
  - Advanced features (fleet/compliance/plugins/batch/rollback manager integration) require the missing `lib/*` stack.
- `web/app.py`
  - Starts with a fallback backend when `lib/*` modules are unavailable.
  - Profile APIs work from `config/albator.yaml`; advanced rollback/config manager features remain limited without `lib/*`.

## Swift Subproject (`albator-swift/`)

- Treated as optional and independent from the Python/shell core.
- Source files are tracked; generated build artifacts and zip outputs are intentionally ignored.

## Operational Guidance

- For reliable production use, prefer the core path:
  - `python3 albator_cli.py preflight --json`
  - `python3 albator_cli.py <subcommand>`
- Use optional components only if you explicitly need them and understand their dependency gaps.

## Core-Only Release Profile

- Profile file: `config/profiles/core_only.yaml`
- Purpose: publish/support a minimal deterministic release boundary.
- Recommendation: use this profile as the baseline for CI, packaging, and production hardening runs.
