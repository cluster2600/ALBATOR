# Albator

![Albator](albator.png)

A comprehensive macOS security hardening toolkit for **macOS 26 Tahoe**. Combines native Swift binaries (CLI + GUI), shell-based hardening scripts, Python compliance tooling, and 73 YAML security rules mapped to CIS Benchmarks and DISA STIG.

[![Core Tests](https://github.com/cluster2600/ALBATOR/actions/workflows/core-tests.yml/badge.svg)](https://github.com/cluster2600/ALBATOR/actions/workflows/core-tests.yml)
[![Release](https://github.com/cluster2600/ALBATOR/actions/workflows/release-artifacts.yml/badge.svg)](https://github.com/cluster2600/ALBATOR/releases/latest)

## Features

### Swift CLI (`albator-swift`)

Native arm64 binary — no Python or dependencies required.

```
albator-swift scan        # Full security audit with risk scoring
albator-swift scan -v     # Verbose with raw probe output
albator-swift json        # Machine-readable JSON for automation
albator-swift monitor     # Continuous polling (Ctrl+C to stop)
albator-swift report      # Generate JSON report to ~/Documents
albator-swift logs        # View recent log entries
```

**Core security checks:** Firewall, FileVault, Gatekeeper, SIP, baseline version, security data updates.

**Tahoe hardening checks:** Background Security Improvements (BSI), screen lock (sysadminctl), USB Restricted Mode, Safari Advanced Fingerprinting Protection, FileVault recovery key escrow, Lockdown Mode, hardware generation (Intel EOL detection).

**Extended checks:** Remote login, Bluetooth sharing, auto updates, AirDrop.

### Swift GUI (`Albator-SwiftGUI`)

Full SwiftUI application with six functional sections:

| Section | Description |
|---|---|
| **Dashboard** | Real-time security status cards (core + Tahoe), risk score with breakdown, recent activity, quick actions |
| **Tahoe Hardening** | Detailed Tahoe probe cards with descriptions, remediation commands, deprecated API reference table |
| **Vulnerability Scanner** | CVE checks against macOS version, listening port scan, unsigned app detection, config-based vulnerability assessment |
| **Compliance Checker** | Live audit against CIS Level 1, CIS Level 2, or DISA STIG profiles — runs 61–73 rule check commands with pass/fail status |
| **Network Scanner** | Interface enumeration, listening TCP ports, ARP table, DNS servers, Wi-Fi info, public IP |
| **Reports** | Generate and manage security reports, export snapshots, browse saved reports |

### Python CLI (`albator_cli.py`)

Full-featured Python CLI with subcommands for scanning, fixing, reporting, and compliance:

```bash
python3 albator_cli.py scan --profile cis_level1    # Compliance scan
python3 albator_cli.py fix --dry-run                 # Preview remediations
python3 albator_cli.py report --format json          # Generate report
python3 albator_cli.py baseline --save               # Save compliance baseline
python3 albator_cli.py preflight --json              # Environment checks
python3 albator_cli.py doctor                        # Consolidated diagnostics
```

### Shell Hardening Scripts

Core hardening scripts with dry-run support, structured logging, and rollback tracking:

- `privacy.sh` — Telemetry, Siri analytics, Safari suggestions, remote services
- `firewall.sh` — Application firewall, stealth mode, logging
- `encryption.sh` — FileVault, recovery keys, secure tokens
- `app_security.sh` — Gatekeeper, SIP, code signing, quarantine, Lockdown Mode

### 73 YAML Security Rules

Each rule includes a `check` command, `fix` command, severity, and compliance mappings:

```yaml
# Example: rules/os_firewall_enable.yaml
title: "Enable Firewall"
id: "os_firewall_enable"
severity: "medium"
check: "/usr/libexec/PlistBuddy -c 'Print :globalstate' /Library/Preferences/com.apple.alf.plist | grep -q '1'"
fix: "sudo /usr/libexec/PlistBuddy -c 'Set :globalstate 1' /Library/Preferences/com.apple.alf.plist"
references:
  800-53r5: ["SC-7"]
  disa_stig: ["V-259755"]
```

**Compliance profiles:**

| Profile | Controls | Use case |
|---|---|---|
| `cis_level1` | 61 | Most organisations — practical hardening |
| `cis_level2` | 73 | High-security environments |
| `stig` | 72 | DoD / federal compliance |

## Installation

### Download release binary (recommended)

```bash
# Download the latest release
curl -sL https://github.com/cluster2600/ALBATOR/releases/latest/download/albator-swift-v3.4.0-macos-arm64.tar.gz | tar xz
cd albator-swift-v3.4.0-macos-arm64

# Remove quarantine attribute
xattr -d com.apple.quarantine Albator-Swift Albator-SwiftGUI 2>/dev/null

# Install CLI
sudo cp Albator-Swift /usr/local/bin/albator-swift

# Launch GUI
open Albator-SwiftGUI
```

### Build from source

```bash
git clone https://github.com/cluster2600/ALBATOR.git
cd ALBATOR/albator-swift

# Build CLI
swift build --configuration release --product Albator-Swift
cp .build/release/Albator-Swift /usr/local/bin/albator-swift

# Build GUI
swift build --configuration release --product Albator-SwiftGUI
open .build/release/Albator-SwiftGUI
```

### Python tools

```bash
pip3 install -r requirements.txt
python3 albator_cli.py --help
```

## macOS Compatibility

| macOS | Support | Notes |
|---|---|---|
| **26.x Tahoe** | Primary target | Full Tahoe hardening probes, 26.4 validated |
| 15.x Sequoia | Supported | Core scripts and probes work |
| 14.x Sonoma | Best-effort | Some output signatures may differ |
| 13.x and older | Not supported | Use at your own risk |

> Albator detects Intel vs Apple Silicon and warns that **macOS 26 Tahoe is the last release supporting Intel Macs**.

## macOS Tahoe Security Probes

Albator includes checks specific to macOS 26 Tahoe:

| Probe | What it checks | API |
|---|---|---|
| BSI Auto-Patch | Background Security Improvements auto-install | `com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates` |
| Screen Lock | Password required on wake | `sysadminctl -screenLock status` (replaces deprecated `com.apple.screensaver`) |
| USB Restricted Mode | Block USB at lock screen (extends to Recovery in Tahoe) | `com.apple.security USBRestrictedMode` |
| Safari Anti-FP | Advanced Fingerprinting Protection for all browsing | `com.apple.Safari EnableEnhancedPrivacyInRegularBrowsing` |
| FV Recovery Key | FileVault recovery key escrowed | `fdesetup haspersonalrecoverykey` |
| Lockdown Mode | Apple extreme protection mode | `.GlobalPreferences LDMGlobalEnabled` |
| Hardware Gen | Intel EOL detection | `sysctl hw.optional.arm64` |

## Releases

Automated via GitHub Actions. Push a `v*` tag to build and publish:

```bash
git tag -a v3.4.1 -m "Release v3.4.1"
git push origin v3.4.1
```

Each release includes:
- `albator-swift-vX.Y.Z-macos-arm64.tar.gz` — codesigned CLI + GUI binaries
- `albator-vX.Y.Z.tar.gz` — source archive
- SHA-256 checksums for all artifacts

The pipeline supports **Apple notarisation** when Developer ID credentials are configured as repo secrets. See the [release workflow](.github/workflows/release-artifacts.yml) for details.

## Testing

```bash
# Swift tests
cd albator-swift && swift test

# Python core tests (396 tests)
python3 -m pytest tests/test_core_behaviors.py -v

# Shell syntax check
find . -name '*.sh' -not -path './.git/*' -exec bash -n {} \;

# Mocked script smoke test
bash tests/test_scripts_smoke_mocked.sh
```

## Configuration

| File | Purpose |
|---|---|
| `config/albator.yaml` | Runtime config, min macOS version policy |
| `config/profiles/cis_level1.yaml` | CIS Benchmark Level 1 rule set |
| `config/profiles/cis_level2.yaml` | CIS Benchmark Level 2 rule set |
| `config/profiles/stig.yaml` | DISA STIG rule set |
| `config/profiles/core_only.yaml` | Minimal supported scope |
| `rules/*.yaml` | Individual security rules (73 total) |

## Architecture

```
albator/
  albator-swift/           # Native Swift CLI + GUI
    Sources/
      AlbatorCLI/          # CLI binary (scan, json, monitor, report, logs)
      AlbatorGUI/          # SwiftUI application
      Albator/             # Shared core (probes, engine, views, services)
    Tests/                 # Swift unit tests
    entitlements/          # Hardened runtime entitlements
  rules/                   # 73 YAML security rules
  config/profiles/         # CIS L1, CIS L2, STIG profiles
  albator_cli.py           # Python unified CLI
  scan.py, fix.py, ...     # Python compliance modules
  privacy.sh, firewall.sh  # Shell hardening scripts
  tests/                   # Python + shell test suites
  .github/workflows/       # CI (tests + release artifacts)
```

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — Version history
- [SECURITY.md](SECURITY.md) — Vulnerability disclosure policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution guidelines
- [VALIDATION_AND_TESTING.md](VALIDATION_AND_TESTING.md) — Test matrix
- [CORE_VS_OPTIONAL.md](CORE_VS_OPTIONAL.md) — Component scope
- [DEPRECATIONS.md](DEPRECATIONS.md) — Deprecated APIs and migration

## Contributing

Open an issue or pull request with a reproducible test case and expected behaviour.

## License

MIT License.
