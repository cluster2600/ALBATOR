"""Albator Report Module — Generate comprehensive compliance reports.

Combines scan results with CIS Benchmark mapping and NIST 800-53 family
coverage to produce auditor-ready compliance reports.  Supports text,
JSON, and CSV output formats.
"""

import csv
import io
import os
from collections import OrderedDict
from datetime import datetime, timezone

from scan import load_rules, load_profile, filter_rules_by_profile, \
    filter_rules_by_severity, run_check


# ---------------------------------------------------------------------------
# CIS section catalogue — maps rule IDs to CIS control metadata
# ---------------------------------------------------------------------------

CIS_CONTROLS = OrderedDict([
    # Section 1 — Install Updates
    ("1.1", {"title": "Ensure All Apple-Provided Software Is Current", "level": 1, "rule": "os_software_update_auto"}),
    ("1.2", {"title": "Ensure Auto Update Download Is Enabled", "level": 1, "rule": "os_software_update_download"}),
    ("1.3", {"title": "Ensure Install of Critical Updates Is Enabled", "level": 1, "rule": "os_software_update_critical_install"}),
    ("1.4", {"title": "Ensure Install Application Updates from the App Store Is Enabled", "level": 1, "rule": "os_software_update_auto"}),
    ("1.5", {"title": "Ensure Install Security Responses and System Files Is Enabled", "level": 1, "rule": "os_security_responses_install"}),
    # Section 2 — System Preferences
    ("2.1.1", {"title": "Ensure Bluetooth Is Disabled If No Devices Are Paired", "level": 1, "rule": "os_bluetooth_disable"}),
    ("2.1.2", {"title": "Ensure Bluetooth Sharing Is Disabled", "level": 1, "rule": "os_bluetooth_sharing_disable"}),
    ("2.2.1", {"title": "Ensure Set Time and Date Automatically Is Enabled", "level": 1, "rule": "os_time_server_configure"}),
    ("2.3.1", {"title": "Ensure Screen Saver Corners Are Secure", "level": 2, "rule": "os_screensaver_timeout"}),
    ("2.3.2", {"title": "Ensure Screen Sharing Is Disabled", "level": 1, "rule": "os_screen_sharing_disable"}),
    ("2.3.3.1", {"title": "Ensure File Sharing (AFP) Is Disabled", "level": 1, "rule": "os_file_sharing_smb_disable"}),
    ("2.3.3.2", {"title": "Ensure File Sharing (SMB) Is Disabled", "level": 1, "rule": "os_file_sharing_smb_disable"}),
    ("2.3.3.3", {"title": "Ensure Printer Sharing Is Disabled", "level": 1, "rule": "os_printer_sharing_disable"}),
    ("2.3.3.4", {"title": "Ensure Remote Login (SSH) Is Disabled", "level": 1, "rule": "os_ssh_disable"}),
    ("2.3.3.5", {"title": "Ensure Remote Management Is Disabled", "level": 1, "rule": "os_remote_management_disable"}),
    ("2.3.3.6", {"title": "Ensure Remote Apple Events Is Disabled", "level": 1, "rule": "os_remote_apple_events_disable"}),
    ("2.3.3.7", {"title": "Ensure Internet Sharing Is Disabled", "level": 1, "rule": "os_internet_sharing_disable"}),
    ("2.3.3.8", {"title": "Ensure Content Caching Is Disabled", "level": 1, "rule": "os_content_caching_disable"}),
    ("2.3.3.9", {"title": "Ensure Media Sharing Is Disabled", "level": 1, "rule": "os_media_sharing_disable"}),
    ("2.3.3.10", {"title": "Ensure Bluetooth Sharing Is Disabled", "level": 1, "rule": "os_bluetooth_sharing_disable"}),
    ("2.3.3.11", {"title": "Ensure DVD or CD Sharing Is Disabled", "level": 1, "rule": "os_dvd_sharing_disable"}),
    ("2.3.3.12", {"title": "Ensure AirDrop Is Disabled", "level": 1, "rule": "os_airdrop_disable"}),
    ("2.4.1", {"title": "Ensure Siri Is Disabled", "level": 1, "rule": "os_siri_disable"}),
    ("2.5.1", {"title": "Ensure FileVault Is Enabled", "level": 1, "rule": "os_filevault_enable"}),
    ("2.5.2", {"title": "Ensure Gatekeeper Is Enabled", "level": 1, "rule": "os_gatekeeper_enable"}),
    ("2.5.2.1", {"title": "Ensure Sending Diagnostic and Usage Data to Apple Is Disabled", "level": 2, "rule": "os_diagnostic_reports_disable"}),
    ("2.5.3", {"title": "Ensure Personalized Advertising Is Disabled", "level": 1, "rule": "os_ad_tracking_disable"}),
    ("2.5.4", {"title": "Ensure Lockdown Mode Is Enabled", "level": 2, "rule": "os_lockdown_enable"}),
    ("2.6.1", {"title": "Ensure iCloud Keychain Is Disabled", "level": 2, "rule": "os_icloud_keychain_disable"}),
    ("2.6.1.1", {"title": "Ensure Location Services Is Enabled", "level": 2, "rule": "os_location_services_enable"}),
    ("2.6.2", {"title": "Ensure iCloud Drive Is Disabled", "level": 1, "rule": "os_icloud_drive_disable"}),
    ("2.6.3", {"title": "Ensure iCloud Desktop and Documents Sync Is Disabled", "level": 1, "rule": "os_icloud_documents_desktop_disable"}),
    ("2.6.4", {"title": "Ensure Find My Mac Is Enabled", "level": 2, "rule": "os_find_my_mac_enable"}),
    ("2.7.1", {"title": "Ensure Time Machine Auto-Backup Is Enabled", "level": 2, "rule": "os_time_machine_auto_backup"}),
    ("2.8.1", {"title": "Ensure Handoff Is Disabled", "level": 2, "rule": "os_handoff_disable"}),
    ("2.9.1", {"title": "Ensure Wake for Network Access Is Disabled", "level": 1, "rule": "os_wake_network_access_disable"}),
    ("2.9.2", {"title": "Ensure Power Nap Is Disabled", "level": 2, "rule": "os_power_nap_disable"}),
    ("2.10.1", {"title": "Ensure USB Restricted Mode Is Enabled", "level": 1, "rule": "os_usb_restricted_mode"}),
    # Section 3 — Logging and Auditing
    ("3.1", {"title": "Ensure Security Auditing Is Enabled", "level": 1, "rule": "os_auditd_enable"}),
    ("3.2", {"title": "Ensure Firewall Stealth Mode Is Enabled", "level": 1, "rule": "os_firewall_stealth_mode"}),
    ("3.3", {"title": "Ensure Firewall Is Enabled", "level": 1, "rule": "os_firewall_enable"}),
    ("3.4", {"title": "Ensure Security Auditing Flags Are Configured", "level": 1, "rule": "os_audit_flags_configure"}),
    ("3.5", {"title": "Ensure Audit Retention Is Configured", "level": 1, "rule": "os_audit_retention_configure"}),
    ("3.6", {"title": "Ensure Audit Log Folder ACLs Are Configured", "level": 1, "rule": "os_audit_acls_configure"}),
    ("3.7", {"title": "Ensure Install.log Retention Is 365 Days", "level": 1, "rule": "os_install_log_retention_configure"}),
    # Section 4 — Network
    ("4.1", {"title": "Ensure Bonjour Advertising Is Disabled", "level": 1, "rule": "os_bonjour_disable"}),
    ("4.2", {"title": "Ensure HTTP Server (httpd) Is Disabled", "level": 1, "rule": "os_httpd_disable"}),
    ("4.3", {"title": "Ensure NFS Server Is Disabled", "level": 1, "rule": "os_nfsd_disable"}),
    ("4.4", {"title": "Ensure Wi-Fi Is Disabled When Not Needed", "level": 1, "rule": "os_wifi_disable"}),
    ("4.5", {"title": "Ensure AirDrop Is Disabled", "level": 1, "rule": "os_airdrop_disable"}),
    ("4.6", {"title": "Ensure IPv6 Privacy Extensions Are Enabled", "level": 2, "rule": "os_ipv6_privacy_extensions"}),
    # Section 5 — System Access, Authentication and Authorization
    ("5.1.1", {"title": "Ensure Home Folders Are Secured", "level": 1, "rule": "os_home_folder_permissions"}),
    ("5.1.2", {"title": "Ensure System Integrity Protection Is Enabled", "level": 1, "rule": "os_sip_enable"}),
    ("5.2.1", {"title": "Ensure Password Minimum Length Is 15", "level": 1, "rule": "os_password_min_length"}),
    ("5.2.2", {"title": "Ensure Complex Passwords Are Required", "level": 1, "rule": "os_password_complexity"}),
    ("5.2.3", {"title": "Ensure Password History Is 15 Passwords", "level": 1, "rule": "os_password_history"}),
    ("5.2.4", {"title": "Ensure Maximum Password Age Is 365 Days", "level": 1, "rule": "os_password_max_age"}),
    ("5.2.5", {"title": "Ensure Account Lockout Threshold Is 5 Attempts", "level": 1, "rule": "os_password_lockout"}),
    ("5.3.1", {"title": "Ensure Login Window Displays as Name and Password", "level": 1, "rule": "os_login_window_display"}),
    ("5.3.2", {"title": "Ensure Password Hints Are Disabled", "level": 1, "rule": "os_password_hints_disable"}),
    ("5.3.3", {"title": "Ensure Guest Account Is Disabled", "level": 1, "rule": "os_guest_account_disable"}),
    ("5.3.4", {"title": "Ensure Login Window Banner Text Is Set", "level": 1, "rule": "os_login_window_banner"}),
    ("5.4.1", {"title": "Ensure Automatic Login Is Disabled", "level": 1, "rule": "os_auto_login_disable"}),
    ("5.4.2", {"title": "Ensure Root Account Is Disabled", "level": 1, "rule": "os_root_disable"}),
    ("5.4.3", {"title": "Ensure Fast User Switching Is Disabled", "level": 1, "rule": "os_fast_user_switching_disable"}),
    ("5.5.1", {"title": "Ensure Screensaver Password Is Required Immediately", "level": 1, "rule": "os_screensaver_password"}),
    ("5.5.2", {"title": "Ensure Require Password After Wake Is Enabled", "level": 1, "rule": "os_require_password_wake"}),
    ("5.5.3", {"title": "Ensure Screensaver Inactivity Timeout ≤ 20 Minutes", "level": 1, "rule": "os_screensaver_timeout"}),
    ("5.6.1", {"title": "Ensure Secure Keyboard Entry Is Enabled in Terminal", "level": 1, "rule": "os_keyboard_secure"}),
    ("5.7.1", {"title": "Ensure Only Approved Kernel Extensions Are Loaded", "level": 2, "rule": "os_managed_kext_policy"}),
    # Section 6 — User Accounts and Environment
    ("6.1.1", {"title": "Ensure Show All Filename Extensions Is Enabled", "level": 1, "rule": "os_show_filename_extensions"}),
    ("6.2.1", {"title": "Ensure Warn When Visiting a Fraudulent Website Is Enabled", "level": 1, "rule": "os_safari_warn_fraudulent_sites"}),
    ("6.2.2", {"title": "Ensure Open Safe Downloads Is Disabled", "level": 1, "rule": "os_safari_open_safe_downloads_disable"}),
    ("6.2.3", {"title": "Ensure Show Full Website URL Is Enabled", "level": 1, "rule": "os_safari_show_full_url"}),
    ("6.2.4", {"title": "Ensure AutoFill Is Disabled", "level": 1, "rule": "os_safari_auto_fill_disable"}),
    ("6.2.5", {"title": "Ensure Pop-up Windows Are Blocked", "level": 1, "rule": "os_safari_popups_disable"}),
    ("6.2.6", {"title": "Ensure Safari JavaScript Restrictions Are Configured", "level": 2, "rule": "os_safari_javascript_restrict"}),
])

# CIS top-level section names
CIS_SECTIONS = OrderedDict([
    ("1", "Install Updates, Patches and Additional Security Software"),
    ("2", "System Preferences"),
    ("3", "Logging and Auditing"),
    ("4", "Network Configurations"),
    ("5", "System Access, Authentication and Authorization"),
    ("6", "User Accounts and Environment"),
])


def _section_for(cis_id):
    """Return the top-level section number for a CIS control ID."""
    return cis_id.split(".")[0]


def _nist_families_from_rules(rules):
    """Extract NIST 800-53r5 family coverage from loaded rules."""
    families = {}  # family_code -> set of controls
    for rule in rules:
        refs = rule.get("references", {})
        for ctrl in refs.get("800-53r5", []):
            family = ctrl.split("-")[0]
            families.setdefault(family, set()).add(ctrl)
    return families


# ---------------------------------------------------------------------------
# Core report generator
# ---------------------------------------------------------------------------

def generate_report(rules_dir, profiles_dir=None, profile_name=None,
                    min_severity=None, dry_run=False, timeout=30):
    """Generate a comprehensive compliance report.

    Returns a dict with:
      - metadata: timestamp, profile, dry_run flag
      - summary: totals for rules, pass/fail, compliance %
      - cis_controls: per-control results keyed by CIS ID
      - sections: per-section aggregated scores
      - nist_families: 800-53 family coverage counts
      - level_summary: L1 vs L2 breakdown
    """
    rules = load_rules(rules_dir)

    if profile_name:
        if not profiles_dir:
            raise ValueError("profiles_dir required when profile_name is set")
        profile_ids = load_profile(profiles_dir, profile_name)
        rules = filter_rules_by_profile(rules, profile_ids)

    if min_severity:
        rules = filter_rules_by_severity(rules, min_severity)

    # Index rules by ID for quick lookup
    rule_by_id = {r["id"]: r for r in rules}

    # Run checks for each CIS control
    cis_results = OrderedDict()
    passed = 0
    failed = 0
    not_applicable = 0

    for cis_id, ctrl in CIS_CONTROLS.items():
        rule_id = ctrl["rule"]
        entry = {
            "cis_id": cis_id,
            "title": ctrl["title"],
            "level": ctrl["level"],
            "rule_id": rule_id,
        }

        rule = rule_by_id.get(rule_id)
        if rule is None:
            entry["status"] = "not_applicable"
            entry["severity"] = "n/a"
            entry["detail"] = "rule not in selected scope"
            not_applicable += 1
        elif dry_run:
            entry["status"] = "dry-run"
            entry["severity"] = rule.get("severity", "unknown")
            entry["check"] = rule.get("check", "")
        else:
            ok, detail = run_check(rule, timeout=timeout)
            entry["severity"] = rule.get("severity", "unknown")
            if ok:
                entry["status"] = "pass"
                passed += 1
            else:
                entry["status"] = "fail"
                entry["detail"] = detail
                failed += 1

        cis_results[cis_id] = entry

    # Avoid double-counting rules that map to multiple CIS controls
    # (already handled by running checks per CIS control — same rule
    #  may pass for both 2.3.3.1 and 2.3.3.2 for example)

    total_evaluated = passed + failed
    compliance_pct = round(100.0 * passed / total_evaluated, 1) if total_evaluated > 0 else 0.0

    # Per-section breakdown
    sections = OrderedDict()
    for sec_num, sec_title in CIS_SECTIONS.items():
        sec_pass = sum(1 for cid, e in cis_results.items()
                       if _section_for(cid) == sec_num and e["status"] == "pass")
        sec_fail = sum(1 for cid, e in cis_results.items()
                       if _section_for(cid) == sec_num and e["status"] == "fail")
        sec_total = sec_pass + sec_fail
        sections[sec_num] = {
            "title": sec_title,
            "passed": sec_pass,
            "failed": sec_fail,
            "total": sec_total,
            "compliance_pct": round(100.0 * sec_pass / sec_total, 1) if sec_total > 0 else 0.0,
        }

    # Level breakdown
    l1_pass = sum(1 for e in cis_results.values() if e["level"] == 1 and e["status"] == "pass")
    l1_fail = sum(1 for e in cis_results.values() if e["level"] == 1 and e["status"] == "fail")
    l2_pass = sum(1 for e in cis_results.values() if e["level"] == 2 and e["status"] == "pass")
    l2_fail = sum(1 for e in cis_results.values() if e["level"] == 2 and e["status"] == "fail")

    level_summary = {
        "level1": {
            "passed": l1_pass, "failed": l1_fail,
            "total": l1_pass + l1_fail,
            "compliance_pct": round(100.0 * l1_pass / (l1_pass + l1_fail), 1) if (l1_pass + l1_fail) > 0 else 0.0,
        },
        "level2": {
            "passed": l2_pass, "failed": l2_fail,
            "total": l2_pass + l2_fail,
            "compliance_pct": round(100.0 * l2_pass / (l2_pass + l2_fail), 1) if (l2_pass + l2_fail) > 0 else 0.0,
        },
    }

    # NIST family coverage
    nist_families = {}
    for fam, ctrls in sorted(_nist_families_from_rules(rules).items()):
        nist_families[fam] = {"controls": sorted(ctrls), "count": len(ctrls)}

    return {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "profile": profile_name,
            "dry_run": dry_run,
            "rules_loaded": len(rules),
        },
        "summary": {
            "cis_controls_total": len(CIS_CONTROLS),
            "evaluated": total_evaluated,
            "passed": passed,
            "failed": failed,
            "not_applicable": not_applicable,
            "compliance_pct": compliance_pct,
        },
        "level_summary": level_summary,
        "sections": sections,
        "cis_controls": cis_results,
        "nist_families": nist_families,
    }


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def format_text_report(report):
    """Format report as human-readable text."""
    lines = []
    meta = report["metadata"]
    summ = report["summary"]

    lines.append("=" * 60)
    lines.append("  ALBATOR CIS macOS Benchmark Compliance Report")
    lines.append("=" * 60)
    lines.append(f"Generated: {meta['timestamp']}")
    if meta["profile"]:
        lines.append(f"Profile:   {meta['profile']}")
    if meta["dry_run"]:
        lines.append("Mode:      DRY-RUN (checks not executed)")
    lines.append(f"Rules:     {meta['rules_loaded']} loaded")
    lines.append("")

    # Overall score
    lines.append(f"Overall Compliance: {summ['compliance_pct']}%  "
                 f"({summ['passed']}/{summ['evaluated']} controls passed)")
    if summ["not_applicable"] > 0:
        lines.append(f"  ({summ['not_applicable']} controls not applicable to selected scope)")
    lines.append("")

    # Level breakdown
    ls = report["level_summary"]
    lines.append("Level Breakdown:")
    lines.append(f"  Level 1: {ls['level1']['compliance_pct']}%  "
                 f"({ls['level1']['passed']}/{ls['level1']['total']})")
    lines.append(f"  Level 2: {ls['level2']['compliance_pct']}%  "
                 f"({ls['level2']['passed']}/{ls['level2']['total']})")
    lines.append("")

    # Per-section
    lines.append("-" * 60)
    lines.append("Section Breakdown:")
    lines.append("-" * 60)
    for sec_num, sec in report["sections"].items():
        if sec["total"] == 0:
            continue
        bar_len = 20
        filled = int(bar_len * sec["compliance_pct"] / 100)
        bar = "#" * filled + "-" * (bar_len - filled)
        lines.append(f"  S{sec_num} {sec['title'][:42]:<42s}")
        lines.append(f"     [{bar}] {sec['compliance_pct']:5.1f}%  "
                     f"({sec['passed']}/{sec['total']})")
    lines.append("")

    # Per-control detail
    lines.append("-" * 60)
    lines.append("Control Details:")
    lines.append("-" * 60)
    current_section = None
    for cis_id, ctrl in report["cis_controls"].items():
        sec = _section_for(cis_id)
        if sec != current_section:
            current_section = sec
            lines.append(f"\n  Section {sec}: {CIS_SECTIONS.get(sec, '')}")

        status = ctrl["status"].upper()
        level_tag = f"L{ctrl['level']}"
        if status == "PASS":
            marker = "PASS"
        elif status == "FAIL":
            marker = "FAIL"
        elif status == "NOT_APPLICABLE":
            marker = "N/A "
        else:
            marker = "DRY "

        lines.append(f"    [{marker}] {cis_id:<10s} [{level_tag}] {ctrl['title']}")
        if ctrl.get("detail"):
            lines.append(f"           -> {ctrl['detail'][:100]}")

    lines.append("")

    # NIST families
    if report["nist_families"]:
        lines.append("-" * 60)
        lines.append("NIST 800-53r5 Family Coverage:")
        lines.append("-" * 60)
        for fam, info in sorted(report["nist_families"].items()):
            lines.append(f"  {fam:<4s} ({info['count']:2d} controls): "
                         f"{', '.join(info['controls'][:8])}"
                         f"{'...' if info['count'] > 8 else ''}")

    lines.append("")
    lines.append("=" * 60)
    lines.append(f"  Score: {summ['compliance_pct']}% — "
                 f"{summ['passed']} passed, {summ['failed']} failed, "
                 f"{summ['not_applicable']} N/A")
    lines.append("=" * 60)
    return "\n".join(lines)


def format_csv_report(report):
    """Format report as CSV (one row per CIS control)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["cis_id", "title", "level", "rule_id", "severity",
                     "status", "detail"])
    for cis_id, ctrl in report["cis_controls"].items():
        writer.writerow([
            cis_id,
            ctrl["title"],
            ctrl["level"],
            ctrl["rule_id"],
            ctrl.get("severity", ""),
            ctrl["status"],
            ctrl.get("detail", ""),
        ])
    return buf.getvalue()
