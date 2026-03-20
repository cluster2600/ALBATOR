"""Albator Rollback Module — List, inspect, and apply rollback metadata.

Complements scan and fix: scan identifies gaps, fix remediates them,
rollback reverses changes when needed. Reads JSON metadata files
produced by hardening scripts (privacy.sh, firewall.sh, etc.) and
applies rollback commands in LIFO order.
"""

import glob
import json
import os
import subprocess


def find_metadata_files(state_dir):
    """Return rollback metadata file paths sorted newest-first."""
    if not os.path.isdir(state_dir):
        return []
    pattern = os.path.join(state_dir, "*_rollback_*.json")
    files = sorted(glob.glob(pattern), reverse=True)
    return files


def load_metadata(path):
    """Load and validate a rollback metadata JSON file."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Metadata file not found: {path}")
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid metadata format in {path}: expected object")
    return data


def list_rollbacks(state_dir):
    """List available rollback metadata files with summary info.

    Returns:
        dict with keys: state_dir, files (list of file summaries), count.
    """
    files = find_metadata_files(state_dir)
    summaries = []
    for path in files:
        try:
            data = load_metadata(path)
            summaries.append({
                "path": path,
                "script": data.get("script", "unknown"),
                "status": data.get("status", "unknown"),
                "changes": len(data.get("changes", [])),
            })
        except (json.JSONDecodeError, ValueError):
            summaries.append({
                "path": path,
                "script": "unknown",
                "status": "parse-error",
                "changes": 0,
            })
    return {
        "state_dir": state_dir,
        "files": summaries,
        "count": len(summaries),
    }


def apply_rollback(metadata_path, dry_run=False, timeout=30):
    """Apply rollback from a metadata file in LIFO order.

    Args:
        metadata_path: Path to a rollback metadata JSON file.
        dry_run: If True, show what would be rolled back without executing.
        timeout: Per-command timeout in seconds.

    Returns:
        dict with keys: metadata_file, script, dry_run, total_changes,
                        applied, failed, skipped, results, status.
    """
    data = load_metadata(metadata_path)
    script_name = data.get("script", "unknown")
    changes = data.get("changes", [])

    results = []
    applied = 0
    failed = 0
    skipped = 0

    # Process in reverse (LIFO) order
    for change in reversed(changes):
        component = change.get("component", "")
        detail = change.get("detail", "")
        rollback_cmd = change.get("rollback_command", "")

        # Fallback: if component looks like domain/key, use defaults delete
        if not rollback_cmd and "/" in component:
            domain, key = component.split("/", 1)
            rollback_cmd = f"defaults delete {domain} {key}"

        entry = {
            "component": component,
            "detail": detail,
            "rollback_command": rollback_cmd,
        }

        if not rollback_cmd:
            entry["status"] = "skipped"
            entry["reason"] = "no rollback command"
            skipped += 1
            results.append(entry)
            continue

        if dry_run:
            entry["status"] = "would-rollback"
            applied += 1
            results.append(entry)
            continue

        # Execute rollback command
        try:
            proc = subprocess.run(
                ["bash", "-c", rollback_cmd],
                capture_output=True, text=True, timeout=timeout
            )
            if proc.returncode == 0:
                entry["status"] = "rolled-back"
                applied += 1
            else:
                entry["status"] = "failed"
                entry["error"] = (proc.stderr or proc.stdout or "").strip()
                failed += 1
        except subprocess.TimeoutExpired:
            entry["status"] = "failed"
            entry["error"] = f"timed out after {timeout}s"
            failed += 1
        except OSError as e:
            entry["status"] = "failed"
            entry["error"] = str(e)
            failed += 1

        results.append(entry)

    status = "ok" if failed == 0 else "failed"
    if dry_run:
        status = "dry-run"

    return {
        "metadata_file": metadata_path,
        "script": script_name,
        "dry_run": dry_run,
        "total_changes": len(changes),
        "applied": applied,
        "failed": failed,
        "skipped": skipped,
        "results": results,
        "status": status,
    }


def format_rollback_list(list_result):
    """Format rollback list as a human-readable report."""
    lines = []
    lines.append("Albator Rollback Metadata")
    lines.append("=" * 40)
    lines.append(f"State directory: {list_result['state_dir']}")
    lines.append(f"Files found: {list_result['count']}")
    lines.append("")

    for f in list_result["files"]:
        lines.append(f"  {f['path']}")
        lines.append(f"    script={f['script']}  status={f['status']}  changes={f['changes']}")

    if list_result["count"] == 0:
        lines.append("  (no rollback metadata files found)")

    return "\n".join(lines)


def format_rollback_report(rollback_result):
    """Format rollback results as a human-readable report."""
    lines = []
    lines.append("Albator Rollback Report")
    lines.append("=" * 40)
    lines.append(f"Script: {rollback_result['script']}")
    lines.append(f"Metadata: {rollback_result['metadata_file']}")
    if rollback_result["dry_run"]:
        lines.append("Mode: DRY-RUN (commands not executed)")
    lines.append(f"Total changes: {rollback_result['total_changes']}")
    lines.append("")

    for r in rollback_result["results"]:
        status = r["status"].upper()
        lines.append(f"[{status}] {r['component']}: {r['detail']}")
        if r.get("rollback_command"):
            lines.append(f"        cmd: {r['rollback_command'][:120]}")
        if r.get("error"):
            lines.append(f"        error: {r['error'][:120]}")
        if r.get("reason"):
            lines.append(f"        reason: {r['reason']}")

    lines.append("")
    lines.append("-" * 40)
    lines.append(
        f"Applied: {rollback_result['applied']}  "
        f"Failed: {rollback_result['failed']}  "
        f"Skipped: {rollback_result['skipped']}"
    )
    return "\n".join(lines)
