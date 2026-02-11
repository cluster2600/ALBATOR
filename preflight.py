import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import List, Optional


STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"


@dataclass
class PreflightCheck:
    name: str
    status: str
    message: str
    required: bool = True


def _run_quick(cmd: List[str]) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.returncode == 0
    except Exception:
        return False


def _check_python_version() -> PreflightCheck:
    current = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 8):
        return PreflightCheck("python_version", STATUS_PASS, f"Python {current}", True)
    return PreflightCheck("python_version", STATUS_FAIL, f"Python {current} < 3.8", True)


def _check_macos_target() -> PreflightCheck:
    system = platform.system()
    if system == "Darwin":
        version = platform.mac_ver()[0] or "unknown"
        return PreflightCheck("os_target", STATUS_PASS, f"macOS detected ({version})", True)
    return PreflightCheck("os_target", STATUS_WARN, f"Non-macOS environment detected ({system})", False)


def _run_capture(cmd: List[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output.strip()
    except Exception as e:
        return False, str(e)


def _check_tool(tool: str, required: bool) -> PreflightCheck:
    path = shutil.which(tool)
    if path:
        return PreflightCheck(f"tool_{tool}", STATUS_PASS, f"{tool} found at {path}", required)
    status = STATUS_FAIL if required else STATUS_WARN
    msg = f"{tool} not found in PATH"
    return PreflightCheck(f"tool_{tool}", status, msg, required)


def _check_sudo_or_root(require_sudo: bool) -> PreflightCheck:
    if not require_sudo:
        return PreflightCheck("sudo_or_root", STATUS_PASS, "Not required for this operation", False)

    if os.name != "posix":
        return PreflightCheck("sudo_or_root", STATUS_WARN, "Cannot validate sudo/root on non-POSIX host", False)

    if os.geteuid() == 0:
        return PreflightCheck("sudo_or_root", STATUS_PASS, "Running as root", True)

    if _run_quick(["sudo", "-n", "true"]):
        return PreflightCheck("sudo_or_root", STATUS_PASS, "sudo available without prompt", True)

    return PreflightCheck(
        "sudo_or_root",
        STATUS_FAIL,
        "No root privileges and non-interactive sudo unavailable",
        True,
    )


def _check_config_file(root_dir: str) -> PreflightCheck:
    candidates = [os.path.join(root_dir, "config.yaml"), os.path.join(root_dir, "config", "albator.yaml")]
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            return PreflightCheck("config_file", STATUS_PASS, f"Readable config found: {path}", False)
    return PreflightCheck("config_file", STATUS_WARN, "No readable config file found (using defaults)", False)


def _check_rule_dirs(root_dir: str, require_rules: bool) -> PreflightCheck:
    rules_dir = os.path.join(root_dir, "rules")
    custom_rules_dir = os.path.join(root_dir, "custom", "rules")
    found = False

    for candidate in (rules_dir, custom_rules_dir):
        if os.path.isdir(candidate):
            for _base, _dirs, files in os.walk(candidate):
                if any(file.endswith(".yaml") for file in files):
                    found = True
                    break
        if found:
            break

    if found:
        return PreflightCheck("rule_files", STATUS_PASS, "Rule YAML files detected", require_rules)

    status = STATUS_FAIL if require_rules else STATUS_WARN
    msg = f"No rule YAML files under {rules_dir} or {custom_rules_dir}"
    return PreflightCheck("rule_files", status, msg, require_rules)


def _check_macos_26_3_profile(root_dir: str) -> PreflightCheck:
    profile_path = os.path.join(root_dir, "config", "profiles", "macos_26_3.yaml")
    if os.path.isfile(profile_path) and os.access(profile_path, os.R_OK):
        return PreflightCheck("macos_26_3_profile", STATUS_PASS, f"Profile present: {profile_path}", False)
    return PreflightCheck("macos_26_3_profile", STATUS_WARN, "macOS 26.3 profile pack not found", False)


def _check_macos_26_3_signatures() -> List[PreflightCheck]:
    checks: List[PreflightCheck] = []
    if platform.system() != "Darwin":
        return checks

    version = platform.mac_ver()[0] or ""
    if not version.startswith("26.3"):
        checks.append(
            PreflightCheck("macos_26_3_mode", STATUS_WARN, f"26.3-specific checks skipped on {version or 'unknown'}", False)
        )
        return checks

    ok_fw, fw_output = _run_capture(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    if ok_fw and ("enabled" in fw_output.lower() or "disabled" in fw_output.lower()):
        checks.append(
            PreflightCheck("macos_26_3_firewall_signature", STATUS_PASS, "Firewall status output signature looks compatible", False)
        )
    else:
        checks.append(
            PreflightCheck("macos_26_3_firewall_signature", STATUS_WARN, f"Unexpected firewall status output: {fw_output}", False)
        )

    ok_spctl, spctl_output = _run_capture(["spctl", "--status"])
    if ok_spctl and "assessment" in spctl_output.lower():
        checks.append(
            PreflightCheck("macos_26_3_gatekeeper_signature", STATUS_PASS, "Gatekeeper output signature looks compatible", False)
        )
    else:
        checks.append(
            PreflightCheck("macos_26_3_gatekeeper_signature", STATUS_WARN, f"Unexpected Gatekeeper output: {spctl_output}", False)
        )

    return checks


def run_preflight(root_dir: Optional[str] = None, require_sudo: bool = False, require_rules: bool = False) -> dict:
    """Run preflight checks and return structured summary."""
    resolved_root = os.path.abspath(root_dir or os.environ.get("ROOT_DIR") or os.getcwd())

    checks = [
        _check_python_version(),
        _check_macos_target(),
        _check_tool("curl", required=True),
        _check_tool("jq", required=True),
        _check_tool("pup", required=False),
        _check_sudo_or_root(require_sudo=require_sudo),
        _check_config_file(root_dir=resolved_root),
        _check_rule_dirs(root_dir=resolved_root, require_rules=require_rules),
        _check_macos_26_3_profile(root_dir=resolved_root),
    ]
    checks.extend(_check_macos_26_3_signatures())

    failed_required = [c for c in checks if c.status == STATUS_FAIL and c.required]
    warning_count = len([c for c in checks if c.status == STATUS_WARN])

    return {
        "root_dir": resolved_root,
        "require_sudo": require_sudo,
        "require_rules": require_rules,
        "checks": [asdict(c) for c in checks],
        "passed": len(failed_required) == 0,
        "failed_required_count": len(failed_required),
        "warning_count": warning_count,
    }


def format_preflight_report(summary: dict) -> str:
    """Format a readable preflight report."""
    lines = [
        "Albator preflight report",
        f"Root directory: {summary['root_dir']}",
    ]
    for check in summary["checks"]:
        lines.append(f"[{check['status']}] {check['name']}: {check['message']}")
    lines.append(
        f"Result: {'PASS' if summary['passed'] else 'FAIL'} "
        f"(required failures: {summary['failed_required_count']}, warnings: {summary['warning_count']})"
    )
    return "\n".join(lines)


def preflight_to_json(summary: dict) -> str:
    return json.dumps(summary, indent=2)
