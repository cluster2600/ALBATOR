import argparse
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

def _preflight_policy(config: dict) -> dict:
    preflight_cfg = config.get("preflight", {}) if isinstance(config, dict) else {}
    return {
        "min_macos_version": preflight_cfg.get("min_macos_version", "26.3"),
        "enforce_min_version": bool(preflight_cfg.get("enforce_min_version", True)),
    }

def run_bash_script(script_name, args=None):
    cmd = ["bash", script_name]
    if args:
        cmd.extend(args)
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running {script_name}: {e.stderr}", file=sys.stderr)
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

def maybe_run_preflight(command: str, args: argparse.Namespace, config: dict) -> None:
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

    print(format_preflight_report(summary))
    if not summary["passed"]:
        print("Aborting because preflight failed required checks.", file=sys.stderr)
        sys.exit(1)


def main():
    config = load_config()

    parser = argparse.ArgumentParser(
        description="Albator unified CLI for macOS hardening"
    )
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

    args = parser.parse_args()
    policy = _preflight_policy(config)

    if args.command == "preflight":
        summary = run_preflight(
            require_sudo=args.require_sudo,
            require_rules=args.require_rules,
            min_macos_version=args.min_macos_version or policy["min_macos_version"],
            enforce_min_version=args.enforce_min_version or policy["enforce_min_version"],
        )
        if args.json:
            print(preflight_to_json(summary))
        else:
            print(format_preflight_report(summary))
        sys.exit(0 if summary["passed"] else 1)

    maybe_run_preflight(args.command, args, config)

    if args.command == "legacy":
        run_legacy_command(args)
    else:
        script = bash_scripts.get(args.command)
        if script:
            run_bash_script(script)
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)

if __name__ == "__main__":
    main()
