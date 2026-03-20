import argparse
import contextlib
import io
import json
import subprocess
import sys
import yaml
import os

from main import BaselineGenerator
from preflight import format_preflight_report, preflight_to_json, run_preflight
from rule_handler import collect_rules
from fix import fix, format_fix_report
from rollback import (
    apply_rollback, find_metadata_files, list_rollbacks,
    format_rollback_list, format_rollback_report,
)
from report import generate_report, format_text_report, format_csv_report
from scan import scan, format_scan_report
from baseline import (
    save_baseline, load_baseline, list_baselines, compare_baselines,
    format_diff_report, format_baseline_list,
)
from utils import parse_authors

CONFIG_PATHS = ("config.yaml", os.path.join("config", "albator.yaml"))

def load_config(path: str = None):
    candidates = [path] if path else list(CONFIG_PATHS)
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            with open(candidate, 'r') as f:
                return yaml.safe_load(f) or {}
    print("Configuration file not found. Using defaults.")
    return {}


def _validate_config_schema(config: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(config, dict):
        return ["configuration root must be a mapping"]

    required_top = {
        "profiles": dict,
        "preflight": dict,
        "dependencies": dict,
    }
    for key, expected_type in required_top.items():
        value = config.get(key)
        if value is None:
            errors.append(f"missing required top-level key: {key}")
        elif not isinstance(value, expected_type):
            errors.append(f"key '{key}' must be a {expected_type.__name__}")

    preflight_cfg = config.get("preflight", {})
    if isinstance(preflight_cfg, dict):
        min_v = preflight_cfg.get("min_macos_version")
        enforce = preflight_cfg.get("enforce_min_version")
        if min_v is None:
            errors.append("missing required key: preflight.min_macos_version")
        elif not isinstance(min_v, str):
            errors.append("preflight.min_macos_version must be a string")
        if enforce is None:
            errors.append("missing required key: preflight.enforce_min_version")
        elif not isinstance(enforce, bool):
            errors.append("preflight.enforce_min_version must be a boolean")

    deps_cfg = config.get("dependencies", {})
    if isinstance(deps_cfg, dict):
        required = deps_cfg.get("required")
        if required is None:
            errors.append("missing required key: dependencies.required")
        elif not isinstance(required, list) or not all(isinstance(x, str) for x in required):
            errors.append("dependencies.required must be a list of strings")
    return errors


def _version_tuple(version: str):
    try:
        return tuple(int(part) for part in str(version).split("."))
    except Exception:
        return ()

def _preflight_policy(config: dict) -> dict:
    preflight_cfg = config.get("preflight", {}) if isinstance(config, dict) else {}
    return {
        "min_macos_version": preflight_cfg.get("min_macos_version", "26.3"),
        "enforce_min_version": bool(preflight_cfg.get("enforce_min_version", True)),
    }

def _print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def run_bash_script(script_name, args=None, json_output: bool = False):
    cmd = ["bash", script_name]
    if args:
        cmd.extend(args)
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        if json_output:
            _print_json({
                "command": "script",
                "script": script_name,
                "args": args or [],
                "success": True,
                "returncode": result.returncode,
                "stdout": (result.stdout or "").strip(),
                "stderr": (result.stderr or "").strip(),
            })
        else:
            print(result.stdout)
        return 0
    except subprocess.CalledProcessError as e:
        stdout = (e.stdout or "").strip()
        stderr = (e.stderr or "").strip()
        details = "\n".join(part for part in [stderr, stdout] if part) or "(no output)"
        if json_output:
            _print_json({
                "command": "script",
                "script": script_name,
                "args": args or [],
                "success": False,
                "returncode": e.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "error": details,
            })
            return e.returncode
        print(f"Error running {script_name}:\n{details}", file=sys.stderr)
        sys.exit(e.returncode)

def run_legacy_command(args: argparse.Namespace) -> None:
    """Execute legacy Python tool actions."""
    legacy_args = argparse.Namespace(
        controls=False,
        keyword=args.keyword,
        list_tags=False,
        tailor=False,
        root_dir=None,
        interactive=False,
        gui=False
    )
    generator = BaselineGenerator(args=legacy_args)
    try:
        generator.setup_directories()
        all_rules = collect_rules(generator.root_dir)
        mscp_data = generator.load_yaml_file(os.path.join(generator.includes_dir, 'mscp-data.yaml'))
        version_data = generator.load_yaml_file(os.path.join(generator.root_dir, "VERSION.yaml"))

        if args.action == "list_tags":
            generator.list_available_tags(all_rules)
        elif args.action == "check_controls":
            generator.check_controls(all_rules)
        elif args.action == "interactive":
            generator.interactive_mode(all_rules, mscp_data, version_data)
        elif args.action == "gui":
            generator.gui_mode(all_rules, mscp_data, version_data)
        elif args.action in ["generate", "tailor", "apply"]:
            if not args.keyword:
                print("Error: --keyword is required for this action.")
                sys.exit(1)
            rules = generator.get_matching_rules(all_rules, args.keyword)
            if not rules:
                print(f"No rules found for keyword '{args.keyword}'.")
                sys.exit(1)
            benchmark = generator._resolve_benchmark(args.keyword)
            if args.action == "generate":
                generator._generate_standard_baseline(
                    rules, benchmark, parse_authors(mscp_data['authors'].get(args.keyword, {})),
                    mscp_data['titles'].get(args.keyword, args.keyword), version_data, args.keyword
                )
            elif args.action == "tailor":
                generator.args.tailor = True
                generator._generate_tailored_baseline(
                    rules, benchmark, parse_authors(mscp_data['authors'].get(args.keyword, {})),
                    mscp_data['titles'].get(args.keyword, args.keyword), version_data, args.keyword
                )
                generator.args.tailor = False
            elif args.action == "apply":
                generator.apply_fixes(rules, args.keyword)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        os.chdir(generator.original_wd)

def maybe_run_preflight(command: str, args: argparse.Namespace, config: dict, json_output: bool = False) -> None:
    """Run preflight automatically before mutating actions."""
    mutating_script_commands = {"privacy", "firewall", "encryption", "app_security"}
    mutating_legacy_actions = {"apply", "generate", "tailor"}
    policy = _preflight_policy(config)

    if command in mutating_script_commands:
        summary = run_preflight(
            require_sudo=True,
            require_rules=False,
            min_macos_version=policy["min_macos_version"],
            enforce_min_version=policy["enforce_min_version"],
        )
    elif command == "legacy" and getattr(args, "action", None) in mutating_legacy_actions:
        summary = run_preflight(
            require_sudo=args.action == "apply",
            require_rules=True,
            min_macos_version=policy["min_macos_version"],
            enforce_min_version=policy["enforce_min_version"],
        )
    else:
        return

    if not json_output:
        print(format_preflight_report(summary))
    if not summary["passed"]:
        if json_output:
            _print_json({
                "command": "preflight_gate",
                "success": False,
                "error": "Aborting because preflight failed required checks.",
                "summary": summary,
            })
        else:
            print("Aborting because preflight failed required checks.", file=sys.stderr)
        sys.exit(1)


def run_doctor(config: dict, policy: dict, scripts: dict[str, str], json_output: bool = False) -> int:
    checks = []

    schema_errors = _validate_config_schema(config)
    checks.append(("config_schema", len(schema_errors) == 0, "; ".join(schema_errors) if schema_errors else "valid"))

    summary = run_preflight(
        require_sudo=False,
        require_rules=True,
        min_macos_version=policy["min_macos_version"],
        enforce_min_version=policy["enforce_min_version"],
    )
    checks.append(("preflight", summary["passed"], f"required_failures={summary['failed_required_count']}, warnings={summary['warning_count']}"))

    for dep in config.get("dependencies", {}).get("required", ["curl", "jq"]):
        present = subprocess.run(["which", dep], capture_output=True, text=True).returncode == 0
        checks.append((f"dependency:{dep}", present, "present" if present else "missing"))

    for name, script in scripts.items():
        exists = os.path.exists(script)
        executable = os.access(script, os.X_OK)
        checks.append((f"script_exists:{name}", exists, script))
        checks.append((f"script_executable:{name}", exists and executable, script))

    current = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True, check=False)
    current_version = (current.stdout or "unknown").strip()
    meets = _version_tuple(current_version) >= _version_tuple(policy["min_macos_version"]) if current.returncode == 0 else False
    checks.append(("min_macos_policy", meets, f"current={current_version}, min={policy['min_macos_version']}"))

    failures = 0
    serialized_checks = []
    for name, passed, detail in checks:
        if not passed:
            failures += 1
        serialized_checks.append({"name": name, "passed": passed, "detail": detail})

    if json_output:
        _print_json({
            "command": "doctor",
            "success": failures == 0,
            "checks": serialized_checks,
            "summary": {"checks": len(checks), "failures": failures},
            "policy": policy,
        })
    else:
        print("Albator Doctor Report")
        print("=====================")
        for check in serialized_checks:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"[{status}] {check['name']}: {check['detail']}")
        print("---------------------")
        print(f"Checks: {len(checks)}  Failures: {failures}")
    return 0 if failures == 0 else 1


def main():
    config = load_config()

    parser = argparse.ArgumentParser(
        description="Albator unified CLI for macOS hardening"
    )
    parser.add_argument("--json-output", action="store_true", help="Emit command output as JSON where supported")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Legacy Python tool commands
    parser_legacy = subparsers.add_parser("legacy", help="Run legacy Python tool commands")
    parser_legacy.add_argument("action", choices=["list_tags", "check_controls", "interactive", "gui", "generate", "tailor", "apply"])
    parser_legacy.add_argument("-k", "--keyword", help="Keyword tag for generate, tailor, apply actions")

    parser_preflight = subparsers.add_parser("preflight", help="Run environment/dependency checks")
    parser_preflight.add_argument("--json", action="store_true", help="Emit preflight output as JSON")
    parser_preflight.add_argument("--require-sudo", action="store_true", help="Treat sudo/root as required")
    parser_preflight.add_argument("--require-rules", action="store_true", help="Require local rule YAML files")
    parser_preflight.add_argument("--min-macos-version", type=str, default=None, help="Minimum macOS version threshold (e.g., 26.3)")
    parser_preflight.add_argument("--enforce-min-version", action="store_true", help="Fail preflight when below minimum macOS version")
    subparsers.add_parser("doctor", help="Run consolidated diagnostics (preflight, config schema, deps, script perms)")

    parser_scan = subparsers.add_parser("scan", help="Audit system against YAML security rules")
    parser_scan.add_argument("--profile", type=str, default=None,
                             help="Compliance profile to filter rules (e.g., cis_level1, cis_level2, stig)")
    parser_scan.add_argument("--severity", type=str, default=None,
                             choices=["low", "medium", "high", "critical"],
                             help="Minimum severity level to include")
    parser_scan.add_argument("--dry-run", action="store_true",
                             help="List rules without running checks")
    parser_scan.add_argument("--timeout", type=int, default=30,
                             help="Per-check timeout in seconds (default: 30)")
    parser_scan.add_argument("--odv-file", type=str, default=None,
                             help="Path to ODV overrides YAML file for customized thresholds")
    parser_scan.add_argument("--exempt-file", type=str, default=None,
                             help="Path to exemptions YAML file for accepted-risk exceptions")

    parser_fix = subparsers.add_parser("fix", help="Remediate non-compliant rules by running fix commands")
    parser_fix.add_argument("--profile", type=str, default=None,
                            help="Compliance profile to filter rules (e.g., cis_level1, cis_level2, stig)")
    parser_fix.add_argument("--severity", type=str, default=None,
                            choices=["low", "medium", "high", "critical"],
                            help="Minimum severity level to include")
    parser_fix.add_argument("--dry-run", action="store_true",
                            help="Identify non-compliant rules without applying fixes")
    parser_fix.add_argument("--check-timeout", type=int, default=30,
                            help="Per-check timeout in seconds (default: 30)")
    parser_fix.add_argument("--fix-timeout", type=int, default=60,
                            help="Per-fix timeout in seconds (default: 60)")
    parser_fix.add_argument("--odv-file", type=str, default=None,
                            help="Path to ODV overrides YAML file for customized thresholds")
    parser_fix.add_argument("--exempt-file", type=str, default=None,
                            help="Path to exemptions YAML file for accepted-risk exceptions")

    parser_rollback = subparsers.add_parser("rollback", help="List or apply rollback metadata to reverse hardening changes")
    parser_rollback.add_argument("--list", action="store_true", dest="list_mode",
                                 help="List available rollback metadata files")
    parser_rollback.add_argument("--latest", action="store_true",
                                 help="Use the most recent rollback metadata file")
    parser_rollback.add_argument("--dry-run", action="store_true",
                                 help="Show rollback operations without executing")
    parser_rollback.add_argument("--timeout", type=int, default=30,
                                 help="Per-command timeout in seconds (default: 30)")
    parser_rollback.add_argument("--state-dir", type=str, default=None,
                                 help="Directory containing rollback metadata (default: $ALBATOR_STATE_DIR or /tmp/albator_state)")
    parser_rollback.add_argument("metadata_file", nargs="?", default=None,
                                 help="Path to a specific rollback metadata JSON file")

    parser_report = subparsers.add_parser("report", help="Generate comprehensive CIS Benchmark compliance report")
    parser_report.add_argument("--profile", type=str, default=None,
                               help="Compliance profile to filter rules (e.g., cis_level1, cis_level2, stig)")
    parser_report.add_argument("--severity", type=str, default=None,
                               choices=["low", "medium", "high", "critical"],
                               help="Minimum severity level to include")
    parser_report.add_argument("--dry-run", action="store_true",
                               help="List controls without running checks")
    parser_report.add_argument("--timeout", type=int, default=30,
                               help="Per-check timeout in seconds (default: 30)")
    parser_report.add_argument("--format", type=str, default="text",
                               choices=["text", "json", "csv"],
                               dest="output_format",
                               help="Output format: text, json, or csv (default: text)")
    parser_report.add_argument("--odv-file", type=str, default=None,
                               help="Path to ODV overrides YAML file for customized thresholds")
    parser_report.add_argument("--exempt-file", type=str, default=None,
                               help="Path to exemptions YAML file for accepted-risk exceptions")

    parser_baseline = subparsers.add_parser("baseline", help="Save, list, or compare compliance scan baselines for drift detection")
    parser_baseline.add_argument("--save", action="store_true",
                                 help="Run a scan and save the result as a baseline")
    parser_baseline.add_argument("--label", type=str, default=None,
                                 help="Human-readable label for the saved baseline (e.g., 'pre-deploy')")
    parser_baseline.add_argument("--list", action="store_true", dest="list_mode",
                                 help="List available saved baselines")
    parser_baseline.add_argument("--compare", nargs=2, metavar=("OLD", "NEW"),
                                 help="Compare two baseline files and show drift")
    parser_baseline.add_argument("--baselines-dir", type=str, default=None,
                                 help="Directory for baseline storage (default: $ALBATOR_BASELINES_DIR or ./baselines)")
    parser_baseline.add_argument("--profile", type=str, default=None,
                                 help="Compliance profile for --save scan")
    parser_baseline.add_argument("--severity", type=str, default=None,
                                 choices=["low", "medium", "high", "critical"],
                                 help="Minimum severity for --save scan")
    parser_baseline.add_argument("--dry-run", action="store_true",
                                 help="Save a dry-run scan as baseline (no checks executed)")
    parser_baseline.add_argument("--timeout", type=int, default=30,
                                 help="Per-check timeout in seconds for --save (default: 30)")
    parser_baseline.add_argument("--odv-file", type=str, default=None,
                                 help="Path to ODV overrides YAML for --save scan")
    parser_baseline.add_argument("--exempt-file", type=str, default=None,
                                 help="Path to exemptions YAML for --save scan")

    # Bash script commands
    bash_scripts = {
        "privacy": "privacy.sh",
        "firewall": "firewall.sh",
        "encryption": "encryption.sh",
        "app_security": "app_security.sh",
        "cve_fetch": "cve_fetch.sh",
        "apple_updates": "apple_updates.sh"
    }
    for name in bash_scripts:
        subparsers.add_parser(name, help=f"Run {name} hardening script")

    args, unknown = parser.parse_known_args()
    policy = _preflight_policy(config)
    schema_errors = _validate_config_schema(config)

    if args.command in {"legacy", "preflight", "doctor"} and unknown:
        parser.error(f"unrecognized arguments: {' '.join(unknown)}")

    if schema_errors:
        print("Configuration schema validation failed:", file=sys.stderr)
        for err in schema_errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(2)

    if args.command == "preflight":
        summary = run_preflight(
            require_sudo=args.require_sudo,
            require_rules=args.require_rules,
            min_macos_version=args.min_macos_version or policy["min_macos_version"],
            enforce_min_version=args.enforce_min_version or policy["enforce_min_version"],
        )
        if args.json or args.json_output:
            print(preflight_to_json(summary))
        else:
            print(format_preflight_report(summary))
        sys.exit(0 if summary["passed"] else 1)

    if args.command == "doctor":
        sys.exit(run_doctor(config, policy, bash_scripts, json_output=args.json_output))

    if args.command == "scan":
        base_dir = os.path.dirname(os.path.abspath(__file__))
        rules_dir = os.path.join(base_dir, "rules")
        profiles_dir = os.path.join(base_dir, "config", "profiles")
        try:
            result = scan(
                rules_dir=rules_dir,
                profiles_dir=profiles_dir,
                profile_name=args.profile,
                min_severity=args.severity,
                dry_run=args.dry_run,
                timeout=args.timeout,
                odv_file=args.odv_file,
                exempt_file=args.exempt_file,
            )
        except FileNotFoundError as e:
            if args.json_output:
                _print_json({"command": "scan", "success": False, "error": str(e)})
            else:
                print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)
        if args.json_output:
            result["command"] = "scan"
            result["success"] = result["failed"] == 0 or result["dry_run"]
            _print_json(result)
        else:
            print(format_scan_report(result))
        sys.exit(0 if (result["failed"] == 0 or result["dry_run"]) else 1)

    if args.command == "fix":
        base_dir = os.path.dirname(os.path.abspath(__file__))
        rules_dir = os.path.join(base_dir, "rules")
        profiles_dir = os.path.join(base_dir, "config", "profiles")
        try:
            result = fix(
                rules_dir=rules_dir,
                profiles_dir=profiles_dir,
                profile_name=args.profile,
                min_severity=args.severity,
                dry_run=args.dry_run,
                check_timeout=args.check_timeout,
                fix_timeout=args.fix_timeout,
                odv_file=args.odv_file,
                exempt_file=args.exempt_file,
            )
        except (FileNotFoundError, ValueError) as e:
            if args.json_output:
                _print_json({"command": "fix", "success": False, "error": str(e)})
            else:
                print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)
        if args.json_output:
            result["command"] = "fix"
            result["success"] = result["fix_failed"] == 0
            _print_json(result)
        else:
            print(format_fix_report(result))
        sys.exit(0 if (result["fix_failed"] == 0 or result["dry_run"]) else 1)

    if args.command == "rollback":
        state_dir = args.state_dir or os.environ.get("ALBATOR_STATE_DIR", "/tmp/albator_state")

        if args.list_mode:
            result = list_rollbacks(state_dir)
            if args.json_output:
                result["command"] = "rollback"
                result["success"] = True
                _print_json(result)
            else:
                print(format_rollback_list(result))
            sys.exit(0)

        # Determine metadata file
        meta_file = args.metadata_file
        if args.latest or meta_file is None:
            files = find_metadata_files(state_dir)
            if not files:
                if args.json_output:
                    _print_json({"command": "rollback", "success": False,
                                 "error": f"No rollback metadata files found in {state_dir}"})
                else:
                    print(f"Error: No rollback metadata files found in {state_dir}", file=sys.stderr)
                sys.exit(2)
            meta_file = files[0]

        try:
            result = apply_rollback(
                metadata_path=meta_file,
                dry_run=args.dry_run,
                timeout=args.timeout,
            )
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
            if args.json_output:
                _print_json({"command": "rollback", "success": False, "error": str(e)})
            else:
                print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)

        if args.json_output:
            result["command"] = "rollback"
            result["success"] = result["failed"] == 0
            _print_json(result)
        else:
            print(format_rollback_report(result))
        sys.exit(0 if result["failed"] == 0 else 1)

    if args.command == "report":
        base_dir = os.path.dirname(os.path.abspath(__file__))
        rules_dir = os.path.join(base_dir, "rules")
        profiles_dir = os.path.join(base_dir, "config", "profiles")
        try:
            result = generate_report(
                rules_dir=rules_dir,
                profiles_dir=profiles_dir,
                profile_name=args.profile,
                min_severity=args.severity,
                dry_run=args.dry_run,
                timeout=args.timeout,
                odv_file=args.odv_file,
                exempt_file=args.exempt_file,
            )
        except (FileNotFoundError, ValueError) as e:
            if args.json_output or args.output_format == "json":
                _print_json({"command": "report", "success": False, "error": str(e)})
            else:
                print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)

        fmt = args.output_format
        if args.json_output:
            fmt = "json"

        if fmt == "json":
            result["command"] = "report"
            result["success"] = result["summary"]["failed"] == 0 or result["metadata"]["dry_run"]
            _print_json(result)
        elif fmt == "csv":
            print(format_csv_report(result))
        else:
            print(format_text_report(result))
        sys.exit(0 if (result["summary"]["failed"] == 0 or result["metadata"]["dry_run"]) else 1)

    if args.command == "baseline":
        base_dir = os.path.dirname(os.path.abspath(__file__))
        baselines_dir = (
            args.baselines_dir
            or os.environ.get("ALBATOR_BASELINES_DIR")
            or os.path.join(base_dir, "baselines")
        )

        if args.list_mode:
            result = list_baselines(baselines_dir)
            if args.json_output:
                result["command"] = "baseline"
                result["success"] = True
                _print_json(result)
            else:
                print(format_baseline_list(result))
            sys.exit(0)

        if args.compare:
            old_path, new_path = args.compare
            try:
                old_bl = load_baseline(old_path)
                new_bl = load_baseline(new_path)
            except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
                if args.json_output:
                    _print_json({"command": "baseline", "success": False, "error": str(e)})
                else:
                    print(f"Error: {e}", file=sys.stderr)
                sys.exit(2)
            diff = compare_baselines(old_bl, new_bl)
            if args.json_output:
                diff["command"] = "baseline"
                diff["success"] = diff["summary"]["regressions"] == 0
                _print_json(diff)
            else:
                print(format_diff_report(diff))
            sys.exit(0 if diff["summary"]["regressions"] == 0 else 1)

        if args.save:
            rules_dir = os.path.join(base_dir, "rules")
            profiles_dir = os.path.join(base_dir, "config", "profiles")
            try:
                scan_result = scan(
                    rules_dir=rules_dir,
                    profiles_dir=profiles_dir,
                    profile_name=args.profile,
                    min_severity=args.severity,
                    dry_run=args.dry_run,
                    timeout=args.timeout,
                    odv_file=args.odv_file,
                    exempt_file=args.exempt_file,
                )
            except (FileNotFoundError, ValueError) as e:
                if args.json_output:
                    _print_json({"command": "baseline", "success": False, "error": str(e)})
                else:
                    print(f"Error: {e}", file=sys.stderr)
                sys.exit(2)
            saved_path = save_baseline(scan_result, baselines_dir, label=args.label)
            if args.json_output:
                _print_json({
                    "command": "baseline",
                    "success": True,
                    "action": "save",
                    "path": saved_path,
                    "label": args.label or "",
                    "scan_summary": scan_result.get("summary", {}),
                })
            else:
                print(f"Baseline saved: {saved_path}")
                s = scan_result.get("summary", {})
                print(f"  Rules: {s.get('total', 0)}  Passed: {s.get('passed', 0)}  "
                      f"Failed: {s.get('failed', 0)}  Compliance: {s.get('compliance_pct', 0)}%")
            sys.exit(0)

        # No action specified
        if args.json_output:
            _print_json({"command": "baseline", "success": False,
                         "error": "Specify --save, --list, or --compare"})
        else:
            print("Error: Specify --save, --list, or --compare", file=sys.stderr)
        sys.exit(2)

    maybe_run_preflight(args.command, args, config, json_output=args.json_output)

    if args.command == "legacy":
        if args.json_output:
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            exit_code = 0
            with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                try:
                    run_legacy_command(args)
                except SystemExit as e:
                    exit_code = int(e.code or 0)
            _print_json({
                "command": "legacy",
                "action": args.action,
                "keyword": args.keyword,
                "success": exit_code == 0,
                "returncode": exit_code,
                "stdout": stdout_capture.getvalue().strip(),
                "stderr": stderr_capture.getvalue().strip(),
                "warnings": [
                    "legacy command path remains supported but may be removed in a future major release"
                ],
            })
            sys.exit(exit_code)
        print("Warning: 'legacy' command path is deprecated and may be removed in a future major release.", file=sys.stderr)
        run_legacy_command(args)
    else:
        script = bash_scripts.get(args.command)
        if script:
            rc = run_bash_script(script, unknown, json_output=args.json_output)
            sys.exit(rc)
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)

if __name__ == "__main__":
    main()
