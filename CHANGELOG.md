# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- Added `SECURITY.md` with vulnerability disclosure policy and supported versions.
- Added refreshed architecture diagram in `README.md`.

### Changed
- Rewrote `README.md` to align documentation with the current repository scope and command behavior.
- Pruned redundant markdown files and updated script/documentation references.

### Fixed
- Fixed CLI passthrough behavior so wrapped script flags are forwarded correctly.
- Improved CLI error diagnostics to include captured subprocess output.
- Fixed `tests/test_framework.py` import-path resilience for local runs.
- Fixed `privacy.sh` backup-path handling for absolute preference domains.
- Fixed `apple_updates.sh --offline` behavior to degrade gracefully when cache is absent (with optional strict mode).
- Fixed test/version policy wiring in `tests/test_security.sh` via configurable `MIN_MACOS_VERSION`.
- Added and enforced minimum macOS preflight policy (`26.3`) with background security update checks.

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
