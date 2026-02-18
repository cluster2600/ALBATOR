# Albator Implementation Notes (2026-02-18)

This document captures all implemented improvements from the current hardening/documentation pass.

## 1. Policy Alignment

- `albator.sh` no longer hardcodes a macOS 15.x gate.
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
