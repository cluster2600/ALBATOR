# Albator Swift

Native Swift implementation scaffold for Albator security monitoring on macOS.

## Current State

This subproject now provides:
- `Albator-Swift` (CLI executable)
- `Albator-SwiftGUI` (SwiftUI GUI executable)
- `AlbatorCore` (shared model/service/view logic)
- `AlbatorTests` (unit tests)

## macOS 26.3-Oriented Features

- Baseline compliance check against configurable minimum version (`ALBATOR_MIN_MACOS_VERSION`, default `26.3`)
- Background security data settings checks:
  - `ConfigDataInstall`
  - `CriticalUpdateInstall`
- Real host probes for:
  - Firewall
  - FileVault
  - Gatekeeper
  - SIP
- Security report generation in JSON format

## Build

```bash
cd albator-swift
./build_swift_app.sh
```

Artifacts:
- `.build/release/Albator-Swift`
- `.build/release/Albator-SwiftGUI`
- `dist/` + zip package

## GitHub Binary Release

This repository publishes macOS binary archives on Git tags like `v3.0.2`.

Produced artifacts:
- `albator-swift-vX.Y.Z-macos-arm64.tar.gz`
- checksum files (`.sha256`) for each archive
- source archive (`albator-vX.Y.Z.tar.gz`) + checksum

Create a release:

```bash
git tag v3.0.2
git push origin v3.0.2
```

GitHub Actions workflow `.github/workflows/release-artifacts.yml` will:
- build Swift binaries on `macos-14` (arm64)
- package binaries with build metadata
- generate SHA-256 checksums
- create/update the GitHub Release for that tag and upload files

Local dry run of release packaging:

```bash
cd albator-swift
./build_release_binaries.sh v3.0.2 ./release
ls -1 ./release
```

## Test

```bash
swift test
./simple_cli_demo.sh
./test_reporting.sh
```

## CLI Usage

```bash
.build/release/Albator-Swift --help
.build/release/Albator-Swift --json
.build/release/Albator-Swift --report
```

## GUI Usage

```bash
.build/release/Albator-SwiftGUI
```

Note: GUI target runs as an executable target; this repo does not currently produce a signed `.app` bundle.

## Project Layout

- `Package.swift`: target/product definitions
- `Sources/AlbatorCLI/main.swift`: CLI entrypoint
- `Sources/AlbatorGUI/AlbatorApp.swift`: GUI entrypoint
- `Sources/Albator/Services/SystemSecurityProbe.swift`: real security probes
- `Tests/AlbatorTests/`: Swift tests

## Scope Notes

This is still an early-stage native implementation. It now performs real system probes and report generation, but deeper remediation/workflow parity with shell/Python Albator remains future work.
