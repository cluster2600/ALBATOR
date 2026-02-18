# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- Added `SECURITY.md` with vulnerability disclosure policy and supported versions.
- Added refreshed architecture diagram in `README.md`.
- Added consolidated `doctor` diagnostics command to `albator_cli.py`.
- Added `config/profiles/core_only.yaml` for minimal supported release scope.
- Added CI optional-health smoke checks for enhanced/web paths.
- Added `IMPLEMENTATION_NOTES_2026-02-18.md` documenting all current improvements.
- Added `rollback_apply.py` to execute rollback metadata files.
- Added mocked script smoke harness under `tests/mocks/bin/` and `tests/test_scripts_smoke_mocked.sh`.
- Added `DEPRECATIONS.md` with migration guidance.
- Added release artifact workflow with checksum generation and optional cosign signing.

### Changed
- Rewrote `README.md` to align documentation with the current repository scope and command behavior.
- Pruned redundant markdown files and updated script/documentation references.
- Updated `tests/test_framework.py` to separate non-mutating default checks from privileged/mutating modes.
- Updated `albator.sh` to use configurable minimum macOS policy from `config/albator.yaml`.
- Updated shell script runtime behavior with structured logging support and explicit status signaling.
- Added unified `--json-output` support across CLI commands, including shell-script wrappers and doctor output.
- Updated hardening scripts to use configured macOS baseline messaging and dry-run plan artifact recording.
- Hardened web API session settings and added token/localhost API access controls.

### Fixed
- Fixed CLI passthrough behavior so wrapped script flags are forwarded correctly.
- Improved CLI error diagnostics to include captured subprocess output.
- Fixed `tests/test_framework.py` import-path resilience for local runs.
- Fixed `privacy.sh` backup-path handling for absolute preference domains.
- Fixed `apple_updates.sh --offline` behavior to degrade gracefully when cache is absent (with optional strict mode).
- Fixed test/version policy wiring in `tests/test_security.sh` via configurable `MIN_MACOS_VERSION`.
- Added and enforced minimum macOS preflight policy (`26.3`) with background security update checks.
- Hardened `web/app.py` status probes to avoid interactive `sudo` and surface elevation hints.
- Removed `eval` usage from script/test command execution paths.

## [v3.0.1] - 2026-02-18

### Added
- Added preflight command and automatic preflight gating for mutating operations.
- Added CI checks for lint/static checks and core behavior tests.
- Added macOS 26.3 profile pack and version-aware baseline filtering support.

### Fixed
- Hardened fix execution safety and expanded behavior tests.

## [v0.9] - 2025-05-28

### Added
- Initial broad project release combining Bash hardening scripts and Python tooling.
- Early unified CLI and advanced feature scaffolding.

---

For security-specific reporting and handling guidelines, see `SECURITY.md`.
