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
