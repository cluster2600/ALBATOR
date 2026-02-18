# Albator Validation And Testing Guide

## Scope
This document describes how to validate Albator safely on macOS 26.3 and what each test covers.

## Issue Mapping (2026-02-18 Validation Pass)
- #7: CLI subcommands now forward script flags (implemented).
- #8: `tests/test_framework.py` no longer hard-fails on missing `lib/logger` import; logging fallback added.
- #9: `tests/test_security.sh` now checks against configurable minimum macOS version (`MIN_MACOS_VERSION`, default `26.3`).
- #10: CLI wrapper error diagnostics now include both stderr and stdout.
- #11: `apple_updates.sh --offline` now degrades gracefully without cache (strict mode optional via `STRICT_OFFLINE=true`).
- #12: `privacy.sh` backup path now sanitizes domain/key components.
- #13: `tests/test_framework.py --include-privileged` now skips privileged checks when non-interactive sudo is unavailable.
- #14: FileVault/Safari matcher logic in `tests/test_framework.py` now handles modern macOS output variants.
- #15: `tests/test_framework.py --include-mutating` now runs deterministic script validation (`--dry-run` / `--offline`).
- #16: `tests/test_security.sh` no longer exits early due arithmetic + `set -e` interaction.
- #17: `cve_fetch.sh` parsing/summary paths hardened for `set -euo pipefail` in dry-run/offline validation.

## Safe Validation Commands

### 1. Core Python behavior tests
```bash
python3 -m unittest tests/test_core_behaviors.py -v
```
Coverage includes:
- benchmark resolution
- rule path fail-fast behavior
- version-aware rule filtering
- preflight policy checks
- CLI preflight auto-gate behavior
- CLI wrapper diagnostics behavior
- legacy CLI integration with fixture project

### 2. Preflight validation
```bash
python3 albator_cli.py preflight --json
python3 albator_cli.py doctor
python3 albator_cli.py --json-output doctor
python3 albator_cli.py preflight --require-sudo
python3 albator_cli.py preflight --require-rules
```
Checks include:
- Python/runtime/tools
- macOS minimum version policy
- rules/config presence
- background security improvements settings
- macOS 26.3 output signatures
- config schema validation and script permission checks (`doctor`)

### 3. Unified CLI wrapper passthrough
```bash
python3 albator_cli.py cve_fetch --dry-run
python3 albator_cli.py apple_updates --offline --verbose
```
Expected:
- flags are forwarded to underlying scripts
- wrapper reports stdout/stderr context on failures

### 4. Script-level non-destructive tests
```bash
bash privacy.sh --dry-run
bash firewall.sh --dry-run
bash encryption.sh --dry-run
bash app_security.sh --dry-run
bash tests/test_security.sh --dry-run --verbose
```
Notes:
- some scripts require sudo even in validation mode
- use preflight output to understand environment gating

### 5. Python framework report generation
```bash
python3 tests/test_framework.py --output /tmp/albator_test_report.json --verbose
python3 tests/test_framework.py --include-privileged --output /tmp/albator_privileged_report.json
python3 tests/test_framework.py --include-mutating --output /tmp/albator_mutating_report.json
bash tests/test_scripts_smoke_mocked.sh
```
Expected:
- framework starts without `logger` import failure
- report includes preflight summary
- failing checks are reported explicitly
- mutating script execution tests run only when explicitly requested
- mocked smoke harness validates script dry-run behavior without requiring host macOS internals
- privileged checks are marked skipped (not failed) when non-interactive sudo is unavailable
- mutating mode uses deterministic script args to avoid host mutation and flaky network requirements

### 6. Enhanced and web optional health checks
```bash
python3 albator_enhanced.py --help
python3 -c "import web.app as w; print(w.OPTIONAL_BACKEND_AVAILABLE, w.SOCKETIO_AVAILABLE)"
```
Expected:
- enhanced CLI still starts even when optional `lib/*` modules are missing
- web module imports with fallback backend mode when optional modules are absent

## Configuration Knobs Used In Validation

### `config/albator.yaml`
```yaml
preflight:
  min_macos_version: "26.3"
  enforce_min_version: true
```

### Environment variables
- `MIN_MACOS_VERSION`: minimum version for `tests/test_security.sh` (default: `26.3`)
- `STRICT_OFFLINE`: when `true`, `apple_updates.sh --offline` exits if cache is missing
- `ALBATOR_LOG_FORMAT`: set to `json` for structured script logs
- `ALBATOR_API_TOKEN`: when set, required as `X-Albator-Token` for `/api/*` endpoints
- `ALBATOR_COOKIE_SECURE`: set `true` to enforce secure-only session cookie in web mode
- `ALBATOR_TEST_ALLOW_DRYRUN_NO_SUDO`: allows dry-run test execution of privileged scripts in validation harness

## Interpretation Guidance
- A failing mutating command without sudo is expected when preflight enforces privilege checks.
- `apple_updates.sh --offline` without cache now degrades gracefully by default and still produces summary output.
- `tests/test_framework.py` may report operational failures (e.g., sudo-gated checks) even when framework integrity is healthy.
