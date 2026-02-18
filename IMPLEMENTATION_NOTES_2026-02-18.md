# Albator Implementation Notes (2026-02-18)

This document captures all implemented improvements from the current hardening/documentation pass.

## 1. Policy Alignment

- `albator.sh` no longer hardcodes a fixed major-version gate.
- It now reads:
  - `preflight.min_macos_version`
  - `preflight.enforce_min_version`
  from `config/albator.yaml`.
- Environment overrides are supported:
  - `MIN_MACOS_VERSION`
  - `ENFORCE_MIN_VERSION`

## 2. Unified Diagnostics (`doctor`)

Added `albator_cli.py doctor` to run consolidated checks:
- config schema validation
- preflight summary
- required dependency presence
- script existence + executable checks
- min macOS policy verification

## 3. Config Schema Validation

`albator_cli.py` now validates expected configuration structure before command execution.

Required top-level keys:
- `profiles` (mapping)
- `preflight` (mapping)
- `dependencies` (mapping)

Required nested keys:
- `preflight.min_macos_version` (string)
- `preflight.enforce_min_version` (boolean)
- `dependencies.required` (list of strings)

## 4. Test Framework Mode Split

`tests/test_framework.py` now separates test modes:
- default: non-mutating, low-privilege tests
- `--include-privileged`: privileged read-only verification
- `--include-mutating`: script execution tests that may modify state
- `--include-scripts`: deprecated alias for `--include-mutating`

## 5. Web Safety Changes

`web/app.py` now:
- uses non-interactive probes for component status checks
- reports `requires_elevation` hints in component status payloads
- supports fallback backend mode when optional `lib/*` modules are unavailable
- supports plain Flask mode if `flask_socketio` is not installed

## 6. Enhanced CLI Fallback Behavior

`albator_enhanced.py` now degrades gracefully when optional `lib/*` modules are missing:
- fallback logger is used
- unavailable advanced managers are set to `None`
- script orchestration remains functional

## 7. Shell Runtime Behavior

Shared runtime helpers were added in `utils.sh`:
- structured logging mode (`ALBATOR_LOG_FORMAT=json`)
- script state initialization
- rollback metadata file lifecycle
- change/no-op tracking
- unified status exit helper

Integrated scripts:
- `privacy.sh`
- `firewall.sh`
- `encryption.sh`
- `app_security.sh`

## 8. Exit Code Semantics

For integrated core hardening scripts:
- `0`: success (changes applied or dry-run success path)
- `10`: already compliant / no-op
- `1`: error

## 9. Rollback Metadata

Integrated scripts now generate per-run metadata under:
- `/tmp/albator_state/*_rollback_YYYYmmdd_HHMMSS.json`

Metadata includes:
- script name
- start/finish timestamps
- status
- recorded changes (when available)

## 10. CI Enhancements

`.github/workflows/core-tests.yml` now includes `optional-health` job:
- installs runtime deps from `requirements.txt`
- runs `python albator_enhanced.py --help`
- runs web import smoke test

## 11. Release Boundary Documentation

Added:
- `config/profiles/core_only.yaml`
- updates in `CORE_VS_OPTIONAL.md`

Purpose:
- define deterministic supported baseline for packaging/CI/production use.

## 12. Recommended Operator Commands

```bash
python3 albator_cli.py doctor
python3 albator_cli.py preflight --json
python3 -m unittest tests/test_core_behaviors.py -v
python3 tests/test_framework.py --output /tmp/albator_test_report.json
python3 tests/test_framework.py --include-privileged --output /tmp/albator_privileged_report.json
python3 tests/test_framework.py --include-mutating --output /tmp/albator_mutating_report.json
```

## 13. Additional Hardening And Operability Updates

- Added global `--json-output` to `albator_cli.py` for machine-readable command payloads.
- Added `rollback_apply.py` for replaying rollback metadata in reverse order.
- Added dry-run plan metadata generation (`*_plan_*.json`) in `utils.sh`.
- Removed `eval` execution path from `privacy.sh` and `tests/test_security.sh`.
- Added mocked integration harness:
  - `tests/mocks/bin/*`
  - `tests/test_scripts_smoke_mocked.sh`
- Extended CI with shell syntax smoke and mocked script smoke execution.
- Added release workflow `.github/workflows/release-artifacts.yml` with checksum and optional cosign signing.
- Hardened `web/app.py` API security:
  - token auth via `ALBATOR_API_TOKEN` + `X-Albator-Token`
  - localhost restriction fallback when token is unset
  - stricter session cookie settings
- Added `DEPRECATIONS.md` and deprecation warning output for legacy/alias command paths.

## 14. Validation Reliability Fixes (Issues #13-#17)

- `tests/test_framework.py` now:
  - gates privileged checks on non-interactive sudo availability
  - marks unsupported privileged checks as skipped (reported, not failed)
  - supports robust matcher variants for FileVault and Safari security output
  - runs mutating validation scripts with deterministic args (`--dry-run` / `--offline`)
- Core scripts `privacy.sh`, `firewall.sh`, `encryption.sh`, `app_security.sh` now support dry-run validation without mandatory sudo when `ALBATOR_TEST_ALLOW_DRYRUN_NO_SUDO=true`.
- `tests/test_security.sh` counter arithmetic was corrected to avoid premature exit under `set -e`.
- `cve_fetch.sh` parsing and summary generation paths were hardened for `set -euo pipefail`.

## 15. Albator Swift Remediation (Issues #18-#22)

- Fixed Swift package validity and test wiring:
  - repaired target layout and added real Swift tests under `albator-swift/Tests/AlbatorTests`.
- Implemented real host security probing in Swift:
  - firewall, FileVault, Gatekeeper, SIP, macOS version baseline, and security data update settings.
- Added macOS 26.3-focused feature parity in Swift dashboard/CLI/report output:
  - baseline compliance
  - `ConfigDataInstall` / `CriticalUpdateInstall` status
- Refactored `albator-swift` into shared `AlbatorCore` + split executable products:
  - `Albator-Swift` (CLI)
  - `Albator-SwiftGUI` (GUI)
- Updated Swift scripts/docs to match actual outputs and removed stale `.app` assumptions.
- Hardened notification behavior for CLI context to avoid non-bundled crash during report generation.

Validation run results (post-fix):
- `cd albator-swift && swift build --configuration release` ✅
- `cd albator-swift && swift test` ✅
- `cd albator-swift && ./build_swift_app.sh` ✅
- `cd albator-swift && ./simple_cli_demo.sh` ✅
- `cd albator-swift && ./demo_cli.sh` ✅
- `cd albator-swift && ./test_reporting.sh` ✅

## 16. GitHub Binary Release Publishing

- Added deterministic Swift release packaging script:
  - `albator-swift/build_release_binaries.sh`
- Expanded `.github/workflows/release-artifacts.yml` to:
  - build `Albator-Swift` + `Albator-SwiftGUI` on `macos-13` (`x86_64`) and `macos-14` (`arm64`)
  - package binaries as architecture-specific `.tar.gz` bundles
  - generate SHA-256 checksums for each package
  - upload source archive + checksum
  - publish all release files to the GitHub Release tied to the pushed `v*` tag
- Updated:
  - `README.md` with release publishing summary
  - `albator-swift/README.md` with exact tag workflow and local dry-run packaging commands
