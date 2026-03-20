"""Albator Scan Module — Audit a system against YAML security rules.

Loads rules from rules/*.yaml, optionally filters by compliance profile,
runs each rule's check command, and reports compliance status.
"""

import glob
import json
import os
import subprocess
import yaml

from odv import load_odv_defaults, get_effective_check_command


def load_rules(rules_dir):
    """Load all YAML rule files from the rules directory."""
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "os_*.yaml"))):
        with open(path) as f:
            data = yaml.safe_load(f)
        if data and "id" in data and "check" in data:
            data["_source"] = path
            rules.append(data)
    return rules


def load_profile(profiles_dir, profile_name):
    """Load a compliance profile and return the list of rule IDs."""
    path = os.path.join(profiles_dir, f"{profile_name}.yaml")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Profile not found: {path}")
    with open(path) as f:
        data = yaml.safe_load(f)
    return data["profile"]["rules"]


def filter_rules_by_profile(rules, profile_rule_ids):
    """Filter rules to only those listed in a profile."""
    id_set = set(profile_rule_ids)
    return [r for r in rules if r["id"] in id_set]


def filter_rules_by_severity(rules, min_severity):
    """Filter rules to those at or above a minimum severity level."""
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold = severity_order.get(min_severity, 0)
    return [r for r in rules if severity_order.get(r.get("severity", "low"), 0) >= threshold]


def run_check(rule, timeout=30, odv_values=None):
    """Run a rule's check command and return (passed, detail).

    Returns (True, stdout) if exit code 0, (False, stderr/stdout) otherwise.
    In case of execution errors (e.g., command not found), returns (False, error_message).
    When odv_values is provided, uses check_odv template if available.
    """
    check_cmd = get_effective_check_command(rule, odv_values)
    if not check_cmd.strip():
        return False, "empty check command"
    try:
        result = subprocess.run(
            ["bash", "-c", check_cmd],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return True, (result.stdout or "").strip()
        return False, (result.stderr or result.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return False, f"check timed out after {timeout}s"
    except OSError as e:
        return False, str(e)


def scan(rules_dir, profiles_dir=None, profile_name=None,
         min_severity=None, dry_run=False, timeout=30, odv_file=None):
    """Run a compliance scan and return structured results.

    Args:
        rules_dir: Path to the rules/ directory.
        profiles_dir: Path to config/profiles/ directory (needed if profile_name set).
        profile_name: Optional profile to filter rules (e.g., 'cis_level1').
        min_severity: Optional minimum severity filter.
        dry_run: If True, list rules without executing checks.
        timeout: Per-check timeout in seconds.
        odv_file: Optional path to ODV overrides YAML file.

    Returns:
        dict with keys: rules_scanned, passed, failed, errors, results, summary.
    """
    rules = load_rules(rules_dir)

    # Load ODV overrides if provided
    odv_values = None
    if odv_file:
        odv_values = load_odv_defaults(odv_file)

    if profile_name:
        if not profiles_dir:
            raise ValueError("profiles_dir required when profile_name is set")
        profile_ids = load_profile(profiles_dir, profile_name)
        rules = filter_rules_by_profile(rules, profile_ids)

    if min_severity:
        rules = filter_rules_by_severity(rules, min_severity)

    results = []
    passed_count = 0
    failed_count = 0
    error_count = 0

    for rule in rules:
        entry = {
            "id": rule["id"],
            "title": rule.get("title", ""),
            "severity": rule.get("severity", "unknown"),
        }
        if dry_run:
            entry["status"] = "dry-run"
            entry["check"] = get_effective_check_command(rule, odv_values)
        else:
            ok, detail = run_check(rule, timeout=timeout, odv_values=odv_values)
            if ok:
                entry["status"] = "pass"
                passed_count += 1
            else:
                entry["status"] = "fail"
                entry["detail"] = detail
                failed_count += 1

        results.append(entry)

    total = len(rules)
    if dry_run:
        passed_count = 0
        failed_count = 0

    return {
        "rules_scanned": total,
        "passed": passed_count,
        "failed": failed_count,
        "errors": error_count,
        "dry_run": dry_run,
        "profile": profile_name,
        "results": results,
        "summary": {
            "total": total,
            "passed": passed_count,
            "failed": failed_count,
            "compliance_pct": round(100.0 * passed_count / total, 1) if total > 0 else 0.0,
        },
    }


def format_scan_report(scan_result):
    """Format scan results as a human-readable report."""
    lines = []
    lines.append("Albator Compliance Scan Report")
    lines.append("=" * 40)
    if scan_result.get("profile"):
        lines.append(f"Profile: {scan_result['profile']}")
    if scan_result.get("dry_run"):
        lines.append("Mode: DRY-RUN (checks not executed)")
    lines.append(f"Rules scanned: {scan_result['rules_scanned']}")
    lines.append("")

    for r in scan_result["results"]:
        status = r["status"].upper()
        severity = r["severity"].upper()
        lines.append(f"[{status}] [{severity}] {r['id']}: {r['title']}")
        if r.get("detail"):
            lines.append(f"        {r['detail'][:120]}")
        if r.get("check"):
            lines.append(f"        check: {r['check'][:120]}")

    lines.append("")
    lines.append("-" * 40)
    s = scan_result["summary"]
    lines.append(f"Total: {s['total']}  Passed: {s['passed']}  Failed: {s['failed']}  Compliance: {s['compliance_pct']}%")
    return "\n".join(lines)
