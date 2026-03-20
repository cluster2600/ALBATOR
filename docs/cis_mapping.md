# CIS macOS Benchmark — ALBATOR Coverage Mapping

This document maps each CIS Apple macOS Benchmark control to the
ALBATOR rule that implements it. Controls marked **IMPLEMENTED** have
working check/fix commands, NIST 800-53 references, and tests.

**Coverage summary (2026-03-20):**

| Level | Implemented | Total | Coverage |
|-------|-------------|-------|----------|
| Level 1 | 55 | 57 | 96.5% |
| Level 2 | 12 | 15 | 80.0% |
| **Combined** | **67** | **72** | **93.1%** |

---

## Section 1 — Install Updates, Patches and Additional Security Software

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 1.1 | Ensure All Apple-Provided Software Is Current | L1 | `os_software_update_auto` | IMPLEMENTED |
| 1.2 | Ensure Auto Update Download Is Enabled | L1 | `os_software_update_download` | IMPLEMENTED |
| 1.3 | Ensure Install of Critical Updates Is Enabled | L1 | `os_software_update_critical_install` | IMPLEMENTED |
| 1.4 | Ensure Install Application Updates from the App Store Is Enabled | L1 | `os_software_update_auto` | IMPLEMENTED (partial — shares rule) |
| 1.5 | Ensure Install Security Responses and System Files Is Enabled | L1 | — | NOT IMPLEMENTED |

## Section 2 — System Preferences

### 2.1 — Bluetooth

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.1.1 | Ensure Bluetooth Is Disabled If No Devices Are Paired | L1 | `os_bluetooth_disable` | IMPLEMENTED |
| 2.1.2 | Ensure Bluetooth Sharing Is Disabled | L1 | `os_bluetooth_sharing_disable` | IMPLEMENTED |

### 2.2 — Date & Time

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.2.1 | Ensure Set Time and Date Automatically Is Enabled | L1 | `os_time_server_configure` | IMPLEMENTED |

### 2.3 — Desktop & Screen Saver / Sharing

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.3.1 | Ensure Screen Saver Corners Are Secure | L2 | `os_screensaver_timeout` | IMPLEMENTED (timeout-based) |
| 2.3.2 | Ensure Screen Sharing Is Disabled | L1 | `os_screen_sharing_disable` | IMPLEMENTED |
| 2.3.3.1 | Ensure File Sharing (AFP) Is Disabled | L1 | `os_file_sharing_smb_disable` | IMPLEMENTED (SMB scope) |
| 2.3.3.2 | Ensure File Sharing (SMB) Is Disabled | L1 | `os_file_sharing_smb_disable` | IMPLEMENTED |
| 2.3.3.3 | Ensure Printer Sharing Is Disabled | L1 | `os_printer_sharing_disable` | IMPLEMENTED |
| 2.3.3.4 | Ensure Remote Login (SSH) Is Disabled | L1 | `os_ssh_disable` | IMPLEMENTED |
| 2.3.3.5 | Ensure Remote Management Is Disabled | L1 | `os_remote_management_disable` | IMPLEMENTED |
| 2.3.3.6 | Ensure Remote Apple Events Is Disabled | L1 | `os_remote_apple_events_disable` | IMPLEMENTED |
| 2.3.3.7 | Ensure Internet Sharing Is Disabled | L1 | `os_internet_sharing_disable` | IMPLEMENTED |
| 2.3.3.8 | Ensure Content Caching Is Disabled | L1 | `os_content_caching_disable` | IMPLEMENTED |
| 2.3.3.9 | Ensure Media Sharing Is Disabled | L1 | `os_media_sharing_disable` | IMPLEMENTED |
| 2.3.3.10 | Ensure Bluetooth Sharing Is Disabled | L1 | `os_bluetooth_sharing_disable` | IMPLEMENTED |
| 2.3.3.11 | Ensure DVD or CD Sharing Is Disabled | L1 | `os_dvd_sharing_disable` | IMPLEMENTED |
| 2.3.3.12 | Ensure AirDrop Is Disabled | L1 | `os_airdrop_disable` | IMPLEMENTED |

### 2.4 — Siri & Spotlight

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.4.1 | Ensure Siri Is Disabled | L1 | `os_siri_disable` | IMPLEMENTED |

### 2.5 — Privacy & Security

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.5.1 | Ensure FileVault Is Enabled | L1 | `os_filevault_enable` | IMPLEMENTED |
| 2.5.2 | Ensure Gatekeeper Is Enabled | L1 | `os_gatekeeper_enable` | IMPLEMENTED |
| 2.5.2.1 | Ensure Sending Diagnostic and Usage Data to Apple Is Disabled | L2 | `os_diagnostic_reports_disable` | IMPLEMENTED |
| 2.5.3 | Ensure Personalized Advertising Is Disabled | L1 | `os_ad_tracking_disable` | IMPLEMENTED |
| 2.5.4 | Ensure Lockdown Mode Is Enabled | L2 | `os_lockdown_enable` | IMPLEMENTED |

### 2.6 — iCloud

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.6.1 | Ensure iCloud Keychain Is Disabled | L2 | `os_icloud_keychain_disable` | IMPLEMENTED |
| 2.6.1.1 | Ensure Location Services Is Enabled | L2 | `os_location_services_enable` | IMPLEMENTED |
| 2.6.2 | Ensure iCloud Drive Is Disabled | L1 | `os_icloud_drive_disable` | IMPLEMENTED |
| 2.6.3 | Ensure iCloud Desktop and Documents Sync Is Disabled | L1 | `os_icloud_documents_desktop_disable` | IMPLEMENTED |
| 2.6.4 | Ensure Find My Mac Is Enabled | L2 | `os_find_my_mac_enable` | IMPLEMENTED |

### 2.7 — Time Machine

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.7.1 | Ensure Time Machine Auto-Backup Is Enabled | L2 | — | NOT IMPLEMENTED |

### 2.8 — Handoff

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.8.1 | Ensure Handoff Is Disabled | L2 | `os_handoff_disable` | IMPLEMENTED |

### 2.9 — Energy / Power

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.9.1 | Ensure Wake for Network Access Is Disabled | L1 | `os_wake_network_access_disable` | IMPLEMENTED |
| 2.9.2 | Ensure Power Nap Is Disabled | L2 | `os_power_nap_disable` | IMPLEMENTED |

### 2.10 — Peripherals

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 2.10.1 | Ensure USB Restricted Mode Is Enabled | L1 | `os_usb_restricted_mode` | IMPLEMENTED |

## Section 3 — Logging and Auditing

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 3.1 | Ensure Security Auditing Is Enabled | L1 | `os_auditd_enable` | IMPLEMENTED |
| 3.2 | Ensure Firewall Stealth Mode Is Enabled | L1 | `os_firewall_stealth_mode` | IMPLEMENTED |
| 3.3 | Ensure Firewall Is Enabled | L1 | `os_firewall_enable` | IMPLEMENTED |
| 3.4 | Ensure Security Auditing Flags Are Configured | L1 | `os_audit_flags_configure` | IMPLEMENTED |
| 3.5 | Ensure Audit Retention Is Configured | L1 | `os_audit_retention_configure` | IMPLEMENTED |
| 3.6 | Ensure Audit Log Folder ACLs Are Configured | L1 | `os_audit_acls_configure` | IMPLEMENTED |
| 3.7 | Ensure Install.log Retention Is 365 Days | L1 | `os_install_log_retention_configure` | IMPLEMENTED |

## Section 4 — Network Configurations

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 4.1 | Ensure Bonjour Advertising Is Disabled | L1 | `os_bonjour_disable` | IMPLEMENTED |
| 4.2 | Ensure HTTP Server (httpd) Is Disabled | L1 | `os_httpd_disable` | IMPLEMENTED |
| 4.3 | Ensure NFS Server Is Disabled | L1 | `os_nfsd_disable` | IMPLEMENTED |
| 4.4 | Ensure Wi-Fi Is Disabled When Not Needed | L1 | `os_wifi_disable` | IMPLEMENTED |
| 4.5 | Ensure AirDrop Is Disabled | L1 | `os_airdrop_disable` | IMPLEMENTED |

## Section 5 — System Access, Authentication and Authorization

### 5.1 — File System Permissions

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 5.1.1 | Ensure Home Folders Are Secured | L1 | `os_home_folder_permissions` | IMPLEMENTED |
| 5.1.2 | Ensure System Integrity Protection Is Enabled | L1 | `os_sip_enable` | IMPLEMENTED |

### 5.2 — Password Policy

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 5.2.1 | Ensure Password Minimum Length Is 15 | L1 | `os_password_min_length` | IMPLEMENTED |
| 5.2.2 | Ensure Complex Passwords Are Required | L1 | `os_password_complexity` | IMPLEMENTED |
| 5.2.3 | Ensure Password History Is 15 Passwords | L1 | `os_password_history` | IMPLEMENTED |
| 5.2.4 | Ensure Maximum Password Age Is 365 Days | L1 | `os_password_max_age` | IMPLEMENTED |
| 5.2.5 | Ensure Account Lockout Threshold Is 5 Attempts | L1 | `os_password_lockout` | IMPLEMENTED |

### 5.3 — Login Window

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 5.3.1 | Ensure Login Window Displays as Name and Password | L1 | `os_login_window_display` | IMPLEMENTED |
| 5.3.2 | Ensure Password Hints Are Disabled | L1 | `os_password_hints_disable` | IMPLEMENTED |
| 5.3.3 | Ensure Guest Account Is Disabled | L1 | `os_guest_account_disable` | IMPLEMENTED |
| 5.3.4 | Ensure Login Window Banner Text Is Set | L1 | `os_login_window_banner` | IMPLEMENTED |

### 5.4 — Account Settings

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 5.4.1 | Ensure Automatic Login Is Disabled | L1 | `os_auto_login_disable` | IMPLEMENTED |
| 5.4.2 | Ensure Root Account Is Disabled | L1 | `os_root_disable` | IMPLEMENTED |
| 5.4.3 | Ensure Fast User Switching Is Disabled | L1 | `os_fast_user_switching_disable` | IMPLEMENTED |

### 5.5 — Screen Lock

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 5.5.1 | Ensure Screensaver Password Is Required Immediately | L1 | `os_screensaver_password` | IMPLEMENTED |
| 5.5.2 | Ensure Require Password After Wake Is Enabled | L1 | `os_require_password_wake` | IMPLEMENTED |
| 5.5.3 | Ensure Screensaver Inactivity Timeout ≤ 20 Minutes | L1 | `os_screensaver_timeout` | IMPLEMENTED |

### 5.6 — Secure Keyboard Entry

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 5.6.1 | Ensure Secure Keyboard Entry Is Enabled in Terminal | L1 | `os_keyboard_secure` | IMPLEMENTED |

## Section 6 — User Accounts and Environment

### 6.1 — Finder

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 6.1.1 | Ensure Show All Filename Extensions Is Enabled | L1 | `os_show_filename_extensions` | IMPLEMENTED |

### 6.2 — Safari

| CIS # | Control | Level | ALBATOR Rule | Status |
|--------|---------|-------|--------------|--------|
| 6.2.1 | Ensure Warn When Visiting a Fraudulent Website Is Enabled | L1 | `os_safari_warn_fraudulent_sites` | IMPLEMENTED |
| 6.2.2 | Ensure Open Safe Downloads Is Disabled | L1 | `os_safari_open_safe_downloads_disable` | IMPLEMENTED |
| 6.2.3 | Ensure Show Full Website URL Is Enabled | L1 | `os_safari_show_full_url` | IMPLEMENTED |
| 6.2.4 | Ensure AutoFill Is Disabled | L1 | `os_safari_auto_fill_disable` | IMPLEMENTED |
| 6.2.5 | Ensure Pop-up Windows Are Blocked | L1 | `os_safari_popups_disable` | IMPLEMENTED |

---

## Gaps — Controls Not Yet Implemented

| CIS # | Control | Level | Priority | Notes |
|--------|---------|-------|----------|-------|
| 1.5 | Install Security Responses and System Files | L1 | Medium | Requires `com.apple.SoftwareUpdate` key `CriticalUpdateInstall` — may overlap with 1.3 |
| 2.7.1 | Time Machine Auto-Backup Is Enabled | L2 | Low | `defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup` |
| — | IPv6 Privacy Extensions | L2 | Low | `sysctl net.inet6.ip6.use_tempaddr` |
| — | Managed Kernel Extensions (kext allowlist) | L2 | Low | MDM-dependent, limited CLI coverage |
| — | Safari JavaScript Restrictions | L2 | Low | Diminishing returns; pop-up blocker covers most risk |

---

## NIST 800-53r5 Control Families Covered

| Family | Controls | Rules |
|--------|----------|-------|
| AC (Access Control) | AC-2, AC-3, AC-4, AC-7, AC-8, AC-11, AC-17, AC-18, AC-20 | 18 |
| AU (Audit) | AU-3, AU-8, AU-9, AU-11, AU-12, AU-14 | 7 |
| CM (Configuration Mgmt) | CM-5, CM-6, CM-7 | 19 |
| IA (Identification/Auth) | IA-2, IA-4, IA-5, IA-6 | 7 |
| MP (Media Protection) | MP-2, MP-4, MP-7 | 3 |
| SC (Sys & Comms) | SC-7, SC-8, SC-10, SC-15, SC-18, SC-23, SC-28, SC-41 | 15 |
| SI (Sys & Info Integrity) | SI-2, SI-3, SI-4, SI-7, SI-12 | 7 |

---

*Generated by ALBATOR Research Program — Experiment 11*
