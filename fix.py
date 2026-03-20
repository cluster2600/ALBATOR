"""Albator Fix Module — Remediate non-compliant rules by running fix commands.

Complements the scan module: scan identifies gaps, fix remediates them.
Runs each rule's check command first; if non-compliant, runs the fix command.
Supports profile/severity filtering, dry-run, and JSON output.
"""

import os
import subprocess
import time

from scan import load_rules, load_profile, filter_rules_by_profile, filter_rules_by_severity, run_check
from odv import load_odv_defaults, get_effective_fix_command
from exemptions import load_exemptions, get_exempt_ids, filter_rules_with_exemptions
from dependencies import load_dependency_graph, topological_sort


def run_fix(rule, timeout=60, odv_values=None):
    """Run a rule's fix command and return (success, detail).

    Returns (True, stdout) if exit code 0, (False, error) otherwise.
    When odv_values is provided, uses fix_odv template if available.
    """
    fix_cmd = get_effective_fix_command(rule, odv_values)
    if not fix_cmd.strip():
        return False, "no fix command defined"
    try:
        result = subprocess.run(
            ["bash", "-c", fix_cmd],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return True, (result.stdout or "").strip()
        return False, (result.stderr or result.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return False, f"fix timed out after {timeout}s"
    except OSError as e:
        return False, str(e)


def fix(rules_dir, profiles_dir=None, profile_name=None,
        min_severity=None, dry_run=False, check_timeout=30, fix_timeout=60,
        odv_file=None, exempt_file=None, dep_file=None):
    """Run compliance checks and fix non-compliant rules.

    Args:
        rules_dir: Path to the rules/ directory.
        profiles_dir: Path to config/profiles/ directory (needed if profile_name set).
        profile_name: Optional profile to filter rules (e.g., 'cis_level1').
        min_severity: Optional minimum severity filter.
        dry_run: If True, identify non-compliant rules without applying fixes.
        check_timeout: Per-check timeout in seconds.
        fix_timeout: Per-fix timeout in seconds.
        odv_file: Optional path to ODV overrides YAML file.
        dep_file: Optional path to rule_dependencies.yaml for ordering.

    Returns:
        dict with keys: rules_checked, already_compliant, fixed, fix_failed,
                        skipped, dry_run, profile, results, summary,
                        dependency_warnings.
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

    # Handle exemptions
    exemptions = None
    exempted_rules = []
    if exempt_file:
        exemptions = load_exemptions(exempt_file)
        exempt_ids = get_exempt_ids(exemptions)
        rules, exempted_rules = filter_rules_with_exemptions(rules, exempt_ids)

    # Sort rules by dependency order so prerequisites are fixed first
    dep_graph = load_dependency_graph(dep_file)
    dep_warnings = []
    if dep_graph:
        rules, dep_warnings = topological_sort(rules, dep_graph)

    results = []
    already_compliant = 0
    fixed_count = 0
    fix_failed_count = 0
    skipped_count = 0
    exempt_count = len(exempted_rules)

    for rule in rules:
        entry = {
            "id": rule["id"],
            "title": rule.get("title", ""),
            "severity": rule.get("severity", "unknown"),
        }

        # Step 1: check current compliance
        check_ok, check_detail = run_check(rule, timeout=check_timeout, odv_values=odv_values)

        if check_ok:
            entry["status"] = "compliant"
            already_compliant += 1
            results.append(entry)
            continue

        # Non-compliant — decide whether to fix
        fix_cmd = get_effective_fix_command(rule, odv_values)
        if not fix_cmd.strip():
            entry["status"] = "skipped"
            entry["detail"] = "no fix command defined"
            skipped_count += 1
            results.append(entry)
            continue

        if dry_run:
            entry["status"] = "would-fix"
            entry["fix"] = fix_cmd
            entry["check_detail"] = check_detail
            results.append(entry)
            continue

        # Step 2: run fix
        fix_ok, fix_detail = run_fix(rule, timeout=fix_timeout, odv_values=odv_values)
        if fix_ok:
            # Step 3: verify fix worked
            verify_ok, verify_detail = run_check(rule, timeout=check_timeout, odv_values=odv_values)
            if verify_ok:
                entry["status"] = "fixed"
                fixed_count += 1
            else:
                entry["status"] = "fix-unverified"
                entry["detail"] = f"fix ran OK but check still fails: {verify_detail}"
                fix_failed_count += 1
        else:
            entry["status"] = "fix-failed"
            entry["detail"] = fix_detail
            fix_failed_count += 1

        results.append(entry)

    # Add exempted rules to results
    for rule in exempted_rules:
        ex_info = None
        if exemptions:
            ex_info = next((e for e in exemptions if e["rule_id"] == rule["id"]), None)
        entry = {
            "id": rule["id"],
            "title": rule.get("title", ""),
            "severity": rule.get("severity", "unknown"),
            "status": "exempt",
        }
        if ex_info:
            entry["exempt_reason"] = ex_info["reason"]
            entry["exempt_approved_by"] = ex_info["approved_by"]
        results.append(entry)

    total = len(rules)
    non_compliant = total - already_compliant
    would_fix = sum(1 for r in results if r["status"] == "would-fix")

    return {
        "rules_checked": total,
        "already_compliant": already_compliant,
        "fixed": fixed_count,
        "fix_failed": fix_failed_count,
        "skipped": skipped_count,
        "exempt": exempt_count,
        "dry_run": dry_run,
        "profile": profile_name,
        "results": results,
        "dependency_warnings": dep_warnings,
        "summary": {
            "total": total,
            "already_compliant": already_compliant,
            "non_compliant": non_compliant,
            "fixed": fixed_count,
            "fix_failed": fix_failed_count,
            "skipped": skipped_count,
            "would_fix": would_fix,
            "exempt": exempt_count,
        },
    }


def format_fix_report(fix_result):
    """Format fix results as a human-readable report."""
    lines = []
    lines.append("Albator Remediation Report")
    lines.append("=" * 40)
    if fix_result.get("profile"):
        lines.append(f"Profile: {fix_result['profile']}")
    if fix_result.get("dry_run"):
        lines.append("Mode: DRY-RUN (fixes not applied)")
    lines.append(f"Rules checked: {fix_result['rules_checked']}")
    lines.append("")

    for r in fix_result["results"]:
        status = r["status"].upper()
        severity = r["severity"].upper()
        lines.append(f"[{status}] [{severity}] {r['id']}: {r['title']}")
        if r.get("detail"):
            lines.append(f"        {r['detail'][:120]}")
        if r.get("fix"):
            lines.append(f"        fix: {r['fix'][:120]}")

    for w in fix_result.get("dependency_warnings", []):
        lines.append(f"  WARNING: {w}")

    lines.append("")
    lines.append("-" * 40)
    s = fix_result["summary"]
    parts = [
        f"Total: {s['total']}",
        f"Compliant: {s['already_compliant']}",
    ]
    if fix_result["dry_run"]:
        parts.append(f"Would fix: {s['would_fix']}")
    else:
        parts.append(f"Fixed: {s['fixed']}")
        parts.append(f"Failed: {s['fix_failed']}")
    parts.append(f"Skipped: {s['skipped']}")
    if s.get("exempt", 0) > 0:
        parts.append(f"Exempt: {s['exempt']}")
    lines.append("  ".join(parts))
    return "\n".join(lines)
