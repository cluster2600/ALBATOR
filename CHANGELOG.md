# Changelog

## [Unreleased]

### eureka
- Added an "Architecture Overview" section with a mermaid flowchart to README.md.
- The flowchart visually represents the main bash scripts and the legacy Python tool components and their interactions.
- Documented the user interaction modes and key files involved in the Python tool.
- Updated privacy.sh to include macOS 15.5 privacy enhancements:
  - Disabled new telemetry service placeholder.
  - Disabled SMB network sharing service.
  - Added verification for new settings.
- Updated firewall.sh to enable logging and verify firewall status for macOS 15.5.
- Updated encryption.sh to include macOS 15.5 placeholder for secure recovery key handling.
- Updated app_security.sh to add macOS 15.5 Hardened Runtime additional checks placeholder.
- Updated cve_fetch.sh and apple_updates.sh to support macOS 15.5 CVE and security update parsing.
