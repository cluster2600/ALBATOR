"""Albator Baseline Module — Compliance drift detection via scan snapshots.

Save scan results as timestamped baselines, then compare two baselines
to detect compliance drift: new failures, resolved issues, severity
changes, and rule additions/removals.
"""

import datetime
import glob
import json
import os


def save_baseline(scan_result, baselines_dir, label=None):
    """Save a scan result as a timestamped baseline JSON file.

    Args:
        scan_result: dict returned by scan().
        baselines_dir: Directory to store baseline files.
        label: Optional human-readable label (e.g., 'pre-deploy').

    Returns:
        str: Path to the saved baseline file.
    """
    os.makedirs(baselines_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    suffix = f"_{label}" if label else ""
    filename = f"baseline_{timestamp}{suffix}.json"
    path = os.path.join(baselines_dir, filename)

    baseline = {
        "version": 1,
        "timestamp": datetime.datetime.now().isoformat(),
        "label": label or "",
        "scan": scan_result,
    }
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)
    return path


def load_baseline(path):
    """Load a baseline JSON file.

    Args:
        path: Path to the baseline JSON file.

    Returns:
        dict: The baseline data.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not valid baseline JSON.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Baseline file not found: {path}")
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict) or "scan" not in data:
        raise ValueError(f"Invalid baseline format: missing 'scan' key in {path}")
    return data


def list_baselines(baselines_dir):
    """List available baseline files, newest first.

    Args:
        baselines_dir: Directory containing baseline files.

    Returns:
        dict with keys: baselines_dir, count, baselines (list of metadata dicts).
    """
    if not os.path.isdir(baselines_dir):
        return {"baselines_dir": baselines_dir, "count": 0, "baselines": []}

    files = sorted(
        glob.glob(os.path.join(baselines_dir, "baseline_*.json")),
        reverse=True,
    )
    baselines = []
    for path in files:
        try:
            data = load_baseline(path)
            scan = data.get("scan", {})
            summary = scan.get("summary", {})
            baselines.append({
                "path": path,
                "filename": os.path.basename(path),
                "timestamp": data.get("timestamp", ""),
                "label": data.get("label", ""),
                "rules_scanned": scan.get("rules_scanned", 0),
                "passed": summary.get("passed", 0),
                "failed": summary.get("failed", 0),
                "compliance_pct": summary.get("compliance_pct", 0.0),
            })
        except (ValueError, json.JSONDecodeError):
            baselines.append({
                "path": path,
                "filename": os.path.basename(path),
                "error": "invalid baseline format",
            })
    return {"baselines_dir": baselines_dir, "count": len(baselines), "baselines": baselines}


def compare_baselines(old_baseline, new_baseline):
    """Compare two baselines and return a drift report.

    Args:
        old_baseline: dict loaded via load_baseline() (the reference).
        new_baseline: dict loaded via load_baseline() (the current state).

    Returns:
        dict with keys: old_meta, new_meta, summary, new_failures,
        resolved, regressions, new_rules, removed_rules, unchanged.
    """
    old_scan = old_baseline.get("scan", {})
    new_scan = new_baseline.get("scan", {})

    old_results = {r["id"]: r for r in old_scan.get("results", [])}
    new_results = {r["id"]: r for r in new_scan.get("results", [])}

    old_ids = set(old_results.keys())
    new_ids = set(new_results.keys())

    common_ids = old_ids & new_ids
    added_ids = new_ids - old_ids
    removed_ids = old_ids - new_ids

    new_failures = []
    resolved = []
    regressions = []
    unchanged = []

    for rid in sorted(common_ids):
        old_r = old_results[rid]
        new_r = new_results[rid]
        old_status = old_r.get("status", "unknown")
        new_status = new_r.get("status", "unknown")

        if old_status == new_status:
            unchanged.append({"id": rid, "status": new_status})
        elif old_status == "pass" and new_status == "fail":
            regressions.append({
                "id": rid,
                "title": new_r.get("title", ""),
                "severity": new_r.get("severity", "unknown"),
                "old_status": old_status,
                "new_status": new_status,
                "detail": new_r.get("detail", ""),
            })
        elif old_status == "fail" and new_status == "pass":
            resolved.append({
                "id": rid,
                "title": new_r.get("title", ""),
                "severity": new_r.get("severity", "unknown"),
                "old_status": old_status,
                "new_status": new_status,
            })
        else:
            # Any other status transition (e.g., exempt ↔ pass/fail)
            regressions.append({
                "id": rid,
                "title": new_r.get("title", ""),
                "severity": new_r.get("severity", "unknown"),
                "old_status": old_status,
                "new_status": new_status,
                "detail": new_r.get("detail", ""),
            })

    new_rules = []
    for rid in sorted(added_ids):
        r = new_results[rid]
        entry = {
            "id": rid,
            "title": r.get("title", ""),
            "severity": r.get("severity", "unknown"),
            "status": r.get("status", "unknown"),
        }
        if r.get("status") == "fail":
            new_failures.append(entry)
        new_rules.append(entry)

    removed_rules = []
    for rid in sorted(removed_ids):
        r = old_results[rid]
        removed_rules.append({
            "id": rid,
            "title": r.get("title", ""),
            "severity": r.get("severity", "unknown"),
            "status": r.get("status", "unknown"),
        })

    old_summary = old_scan.get("summary", {})
    new_summary = new_scan.get("summary", {})
    compliance_delta = (
        new_summary.get("compliance_pct", 0.0) - old_summary.get("compliance_pct", 0.0)
    )

    has_drift = bool(regressions or resolved or new_rules or removed_rules or new_failures)

    return {
        "old_meta": {
            "timestamp": old_baseline.get("timestamp", ""),
            "label": old_baseline.get("label", ""),
        },
        "new_meta": {
            "timestamp": new_baseline.get("timestamp", ""),
            "label": new_baseline.get("label", ""),
        },
        "summary": {
            "has_drift": has_drift,
            "regressions": len(regressions),
            "resolved": len(resolved),
            "new_failures": len(new_failures),
            "new_rules": len(new_rules),
            "removed_rules": len(removed_rules),
            "unchanged": len(unchanged),
            "old_compliance_pct": old_summary.get("compliance_pct", 0.0),
            "new_compliance_pct": new_summary.get("compliance_pct", 0.0),
            "compliance_delta": round(compliance_delta, 1),
        },
        "regressions": regressions,
        "resolved": resolved,
        "new_failures": new_failures,
        "new_rules": new_rules,
        "removed_rules": removed_rules,
        "unchanged": unchanged,
    }


def format_diff_report(diff):
    """Format a drift comparison as a human-readable report."""
    lines = []
    lines.append("Albator Compliance Drift Report")
    lines.append("=" * 45)
    lines.append(f"Old baseline: {diff['old_meta'].get('label', '')} ({diff['old_meta'].get('timestamp', 'unknown')})")
    lines.append(f"New baseline: {diff['new_meta'].get('label', '')} ({diff['new_meta'].get('timestamp', 'unknown')})")
    lines.append("")

    s = diff["summary"]
    direction = "IMPROVED" if s["compliance_delta"] > 0 else "DEGRADED" if s["compliance_delta"] < 0 else "UNCHANGED"
    lines.append(f"Compliance: {s['old_compliance_pct']}% -> {s['new_compliance_pct']}% ({direction}, delta {s['compliance_delta']:+.1f}%)")
    lines.append(f"Drift detected: {'YES' if s['has_drift'] else 'NO'}")
    lines.append("")

    if diff["regressions"]:
        lines.append(f"REGRESSIONS ({len(diff['regressions'])}):")
        for r in diff["regressions"]:
            lines.append(f"  [!] {r['id']}: {r['title']} ({r['old_status']} -> {r['new_status']})")
        lines.append("")

    if diff["resolved"]:
        lines.append(f"RESOLVED ({len(diff['resolved'])}):")
        for r in diff["resolved"]:
            lines.append(f"  [+] {r['id']}: {r['title']} ({r['old_status']} -> {r['new_status']})")
        lines.append("")

    if diff["new_rules"]:
        lines.append(f"NEW RULES ({len(diff['new_rules'])}):")
        for r in diff["new_rules"]:
            lines.append(f"  [*] {r['id']}: {r['title']} (status: {r['status']})")
        lines.append("")

    if diff["removed_rules"]:
        lines.append(f"REMOVED RULES ({len(diff['removed_rules'])}):")
        for r in diff["removed_rules"]:
            lines.append(f"  [-] {r['id']}: {r['title']}")
        lines.append("")

    if not s["has_drift"]:
        lines.append("No compliance drift detected.")
        lines.append("")

    lines.append("-" * 45)
    lines.append(f"Regressions: {s['regressions']}  Resolved: {s['resolved']}  New rules: {s['new_rules']}  Removed: {s['removed_rules']}  Unchanged: {s['unchanged']}")
    return "\n".join(lines)


def format_baseline_list(result):
    """Format baseline list as a human-readable report."""
    lines = []
    lines.append("Albator Compliance Baselines")
    lines.append("=" * 45)
    lines.append(f"Directory: {result['baselines_dir']}")
    lines.append(f"Baselines found: {result['count']}")
    lines.append("")

    if result["count"] == 0:
        lines.append("No baselines saved yet. Run: albator baseline --save")
    else:
        for b in result["baselines"]:
            if "error" in b:
                lines.append(f"  {b['filename']}: {b['error']}")
            else:
                label = f" [{b['label']}]" if b.get("label") else ""
                lines.append(f"  {b['filename']}{label}")
                lines.append(f"    {b['timestamp']}  rules={b['rules_scanned']}  "
                             f"pass={b['passed']}  fail={b['failed']}  "
                             f"compliance={b['compliance_pct']}%")
        lines.append("")
    return "\n".join(lines)
