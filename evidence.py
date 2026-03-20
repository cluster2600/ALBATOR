"""Albator Evidence Module — Audit evidence collection for compliance artifacts.

Captures detailed per-rule evidence during scans: command output, exit codes,
timestamps, and system metadata. Produces auditor-ready evidence packages
for SOC 2, FedRAMP, ISO 27001, and similar compliance frameworks.
"""

import datetime
import hashlib
import json
import os
import platform
import subprocess


def collect_system_metadata():
    """Collect system metadata for evidence context.

    Returns:
        dict with hostname, platform, kernel, timestamp, and user.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    user = os.environ.get("USER", os.environ.get("LOGNAME", "unknown"))

    # Try to get macOS version; falls back gracefully on non-macOS
    macos_version = "unknown"
    try:
        result = subprocess.run(
            ["sw_vers", "-productVersion"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            macos_version = result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass

    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "macos_version": macos_version,
        "kernel": platform.release(),
        "collected_by": user,
        "collected_at": now.isoformat(),
        "collected_at_epoch": int(now.timestamp()),
    }


def collect_rule_evidence(rule, timeout=30, odv_values=None):
    """Run a rule's check command and capture full evidence.

    Args:
        rule: dict with at least 'id', 'check', and optionally 'title', 'severity'.
        timeout: Per-check timeout in seconds.
        odv_values: Optional ODV overrides dict.

    Returns:
        dict with rule metadata, command, stdout, stderr, exit_code,
        duration_ms, and compliance status.
    """
    # Import here to avoid circular dependency
    from odv import get_effective_check_command

    check_cmd = get_effective_check_command(rule, odv_values)
    start = datetime.datetime.now(datetime.timezone.utc)

    evidence = {
        "rule_id": rule["id"],
        "rule_title": rule.get("title", ""),
        "severity": rule.get("severity", "unknown"),
        "check_command": check_cmd,
        "references": rule.get("references", {}),
    }

    if not check_cmd.strip():
        evidence.update({
            "compliant": False,
            "stdout": "",
            "stderr": "empty check command",
            "exit_code": -1,
            "duration_ms": 0,
            "error": "empty check command",
            "timestamp": start.isoformat(),
        })
        return evidence

    try:
        result = subprocess.run(
            ["bash", "-c", check_cmd],
            capture_output=True, text=True, timeout=timeout
        )
        end = datetime.datetime.now(datetime.timezone.utc)
        duration_ms = int((end - start).total_seconds() * 1000)

        evidence.update({
            "compliant": result.returncode == 0,
            "stdout": (result.stdout or "").strip(),
            "stderr": (result.stderr or "").strip(),
            "exit_code": result.returncode,
            "duration_ms": duration_ms,
            "timestamp": start.isoformat(),
        })
    except subprocess.TimeoutExpired:
        end = datetime.datetime.now(datetime.timezone.utc)
        duration_ms = int((end - start).total_seconds() * 1000)
        evidence.update({
            "compliant": False,
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "duration_ms": duration_ms,
            "error": f"check timed out after {timeout}s",
            "timestamp": start.isoformat(),
        })
    except OSError as e:
        end = datetime.datetime.now(datetime.timezone.utc)
        duration_ms = int((end - start).total_seconds() * 1000)
        evidence.update({
            "compliant": False,
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "duration_ms": duration_ms,
            "error": str(e),
            "timestamp": start.isoformat(),
        })

    return evidence


def save_evidence(evidence_list, evidence_dir, system_metadata=None, label=None):
    """Save evidence artifacts to a directory.

    Creates:
    - One JSON file per rule: evidence_{rule_id}.json
    - A manifest file: evidence_manifest.json with index and checksums

    Args:
        evidence_list: List of evidence dicts from collect_rule_evidence().
        evidence_dir: Directory to write evidence files.
        system_metadata: Optional dict from collect_system_metadata().
        label: Optional label for the evidence collection run.

    Returns:
        str: Path to the manifest file.
    """
    os.makedirs(evidence_dir, exist_ok=True)

    if system_metadata is None:
        system_metadata = collect_system_metadata()

    artifacts = []
    compliant_count = 0
    non_compliant_count = 0

    for ev in evidence_list:
        rule_id = ev["rule_id"]
        filename = f"evidence_{rule_id}.json"
        filepath = os.path.join(evidence_dir, filename)

        artifact = {
            "version": 1,
            "system": system_metadata,
            "evidence": ev,
        }

        content = json.dumps(artifact, indent=2, sort_keys=True)
        with open(filepath, "w") as f:
            f.write(content)

        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

        if ev.get("compliant"):
            compliant_count += 1
        else:
            non_compliant_count += 1

        artifacts.append({
            "rule_id": rule_id,
            "file": filename,
            "sha256": checksum,
            "compliant": ev.get("compliant", False),
            "severity": ev.get("severity", "unknown"),
        })

    manifest = {
        "version": 1,
        "label": label or "",
        "system": system_metadata,
        "collected_at": system_metadata.get("collected_at", ""),
        "summary": {
            "total": len(artifacts),
            "compliant": compliant_count,
            "non_compliant": non_compliant_count,
            "compliance_pct": round(
                100.0 * compliant_count / len(artifacts), 1
            ) if artifacts else 0.0,
        },
        "artifacts": artifacts,
    }

    manifest_path = os.path.join(evidence_dir, "evidence_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    return manifest_path


def format_evidence_summary(manifest):
    """Format an evidence manifest as a human-readable summary.

    Args:
        manifest: dict loaded from evidence_manifest.json.

    Returns:
        str: Formatted text summary.
    """
    lines = []
    lines.append("Albator Evidence Collection Summary")
    lines.append("=" * 40)
    if manifest.get("label"):
        lines.append(f"Label: {manifest['label']}")
    lines.append(f"Collected: {manifest.get('collected_at', 'unknown')}")

    sys_info = manifest.get("system", {})
    lines.append(f"Host: {sys_info.get('hostname', 'unknown')}")
    lines.append(f"Platform: {sys_info.get('platform', 'unknown')}")
    lines.append(f"Collected by: {sys_info.get('collected_by', 'unknown')}")
    lines.append("")

    s = manifest.get("summary", {})
    lines.append(f"Total rules: {s.get('total', 0)}")
    lines.append(f"Compliant: {s.get('compliant', 0)}")
    lines.append(f"Non-compliant: {s.get('non_compliant', 0)}")
    lines.append(f"Compliance: {s.get('compliance_pct', 0)}%")
    lines.append("")

    non_compliant = [a for a in manifest.get("artifacts", []) if not a.get("compliant")]
    if non_compliant:
        lines.append("Non-compliant rules:")
        for a in non_compliant:
            lines.append(f"  [{a['severity'].upper()}] {a['rule_id']}")
    else:
        lines.append("All rules compliant.")

    lines.append("")
    lines.append(f"Evidence directory: {len(manifest.get('artifacts', []))} artifact files")
    lines.append("Each artifact includes: command, stdout, stderr, exit code, timestamp, SHA-256 checksum")
    return "\n".join(lines)
