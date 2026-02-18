# Sprint 1 — Security Hardening Summary

## Overview

Sprint 1 focused on fixing broken scripts, adding dependency checks, and establishing CI infrastructure for the ALBATOR macOS security hardening toolkit.

## Changes Delivered

### Script Fixes
- Fixed executable permissions on all `.sh` files (including `tests/test_security.sh`)
- Resolved `shellcheck` SC2155 warnings in `log()` function (separate declare and assign)

### Dependency Guards
Added `check_dependencies()` guard function to the following core scripts:
- `app_security.sh` — guards `spctl`, `codesign`
- `encryption.sh` — guards `fdesetup`, `diskutil`
- `privacy.sh` — guards `tccutil`, `plutil`
- `reporting.sh` — guards `system_profiler`, `csrutil`

Each guard checks that required binaries exist before attempting to use them, preventing cryptic failures on systems with non-standard configurations.

### CI Pipeline
Added `.github/workflows/core-tests.yml`:
- Runs `shellcheck -S error` on all `.sh` files (static analysis)
- Runs `bash -n` syntax check on all `.sh` files
- Triggers on every push and pull request to `main`

### Compatibility
- macOS 26.x (Tahoe) compatibility verified for all probes and hardening commands
- Albator Swift module updated for actor-isolation changes introduced in Xcode 26 / Swift 6.1

### Documentation
- Comprehensive improvement documentation in `docs/2026-02-18-improvements.md`
- Doctor diagnostics subsystem added (`--doctor` flag)
- Fallback modes defined for non-critical hardening steps

## Hardening Improvements (10 total)

1. Executable bit fixed on all shell scripts
2. Dependency guard: `app_security.sh`
3. Dependency guard: `encryption.sh`
4. Dependency guard: `privacy.sh`
5. Dependency guard: `reporting.sh`
6. SC2155 shellcheck fix in `log()` (all scripts)
7. CI pipeline: shellcheck -S error
8. CI pipeline: bash -n syntax validation
9. macOS 26.x compatibility pass
10. GitHub Releases workflow for binary distribution

## Issues Closed

- **Issue #2**: _vibe coded & broken?_ — RESOLVED
  - All scripts now have proper permissions
  - All scripts pass static analysis (`shellcheck -S error`)
  - Dependency guards prevent failures on systems missing required binaries

## Testing

All 14 `.sh` files pass both checks:

```bash
find . -name '*.sh' -exec bash -n {} \;                 # syntax check
shellcheck -S error $(find . -name '*.sh')              # static analysis
```

CI runs these checks automatically on every push.
