# Changelog

All notable changes to this project are documented in this file.

## [3.4.0] — 2026-03-20

### Added
- **Swift CLI overhaul**: subcommands (`scan`, `json`, `monitor`, `report`, `logs`, `version`), coloured output, risk score bar, actionable recommendations.
- **macOS Tahoe hardening probes**: BSI auto-patching, screen lock (sysadminctl), USB Restricted Mode, Safari Advanced Fingerprinting Protection, FileVault recovery key escrow, Lockdown Mode, hardware generation (Intel EOL warning).
- **GUI — Tahoe Hardening view**: dedicated sidebar section with detailed cards, remediation commands, and deprecated API reference table.
- **GUI — Vulnerability Scanner**: CVE checks against macOS version, listening port scan, unsigned/ad-hoc app detection, Intel-only binary detection, config-based vulnerability assessment.
- **GUI — Compliance Checker**: live audit against CIS Level 1, CIS Level 2, and DISA STIG profiles. Runs 61–73 YAML rule check commands with pass/fail/error status, severity badges, compliance percentage bar, and expandable rows with NIST 800-53/STIG/CCI references.
- **GUI — Network Scanner**: interface enumeration, listening TCP ports, ARP table, DNS servers, default gateway, Wi-Fi info, public IP detection.
- **GUI — Reports**: full security report generation, quick snapshot export, saved report management with Finder integration.
- **Codesigning and notarisation pipeline**: hardened runtime entitlements, Developer ID codesigning in CI, Apple notarytool integration via repo secrets.

### Fixed
- Fixed CI `core-tests` job missing PyYAML and pytest dependencies.
- Fixed screen lock probe using deprecated `com.apple.screensaver` domain — now uses `sysadminctl -screenLock status` for macOS Tahoe.
- Fixed shell probes hanging on commands requiring root — added timeouts and stdin nulling.
- Fixed `shellOutput` not capturing stderr (broke sysadminctl, which writes to stderr).
- Fixed FileVault recovery key probe reporting false warning when running without root.
- Allowed mocked script smoke harness to continue-on-error in CI (macOS-only scripts on Ubuntu).

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
- Added `albator-swift/Tests/AlbatorTests/SystemSecurityProbeTests.swift` for Swift baseline/probe validation.
- Added `albator-swift/build_release_binaries.sh` for deterministic macOS binary packaging with checksums.

### Changed
- Rewrote `README.md` to align documentation with the current repository scope and command behavior.
- Pruned redundant markdown files and updated script/documentation references.
- Updated `tests/test_framework.py` to separate non-mutating default checks from privileged/mutating modes.
- Updated `albator.sh` to use configurable minimum macOS policy from `config/albator.yaml`.
- Updated shell script runtime behavior with structured logging support and explicit status signaling.
- Added unified `--json-output` support across CLI commands, including shell-script wrappers and doctor output.
- Updated hardening scripts to use configured macOS baseline messaging and dry-run plan artifact recording.
- Hardened web API session settings and added token/localhost API access controls.
- Updated validation framework and shell test behavior to be environment-aware (sudo-gated checks skip/defer instead of hard-fail).
- Updated mutating validation mode to deterministic script args (`--dry-run` / `--offline`) and non-mutating safety.
- Refactored `albator-swift` package into shared `AlbatorCore` with split CLI/GUI targets.
- Updated `albator-swift` build/demo/report scripts and README to match real SwiftPM artifacts.
- Upgraded `albator-swift` dashboard/report pipeline to include macOS 26.3 baseline + security-data status checks.
- Expanded release pipeline (`.github/workflows/release-artifacts.yml`) to publish GitHub Releases with macOS arm64 Swift binaries and source archive checksums.
- Updated root and Swift README files with end-to-end tag-based binary publishing instructions.

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
- Fixed `tests/test_security.sh` early exit caused by arithmetic + `set -e`.
- Fixed `cve_fetch.sh` dry-run/offline summary parsing failures under `set -euo pipefail`.
- Fixed brittle FileVault/Safari validation matchers for modern macOS command output variants.
- Fixed `albator-swift` `swift build` failure caused by missing test target path.
- Fixed `albator-swift` CLI report crash by disabling notification center usage in non-bundled CLI context.
- Fixed `albator-swift` placeholder/random security state by implementing real system probes.

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
