import argparse
import subprocess
import sys
import yaml
import os

from arg_parser import create_args
from main import BaselineGenerator
from rule_handler import collect_rules

CONFIG_PATH = "config.yaml"

def load_config(path=CONFIG_PATH):
    if not os.path.exists(path):
        print(f"Configuration file {path} not found. Using defaults.")
        return {}
    with open(path, 'r') as f:
        return yaml.safe_load(f)

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

    if args.command == "legacy":
        generator = BaselineGenerator()
        all_rules = collect_rules()
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
            if args.action == "generate":
                generator._generate_standard_baseline(rules, args.keyword, 
                    parse_authors(mscp_data['authors'].get(args.keyword, {})), 
                    mscp_data['titles'].get(args.keyword, args.keyword), version_data, args.keyword)
            elif args.action == "tailor":
                generator.args.tailor = True
                generator._generate_tailored_baseline(rules, args.keyword, 
                    parse_authors(mscp_data['authors'].get(args.keyword, {})), 
                    mscp_data['titles'].get(args.keyword, args.keyword), version_data, args.keyword)
                generator.args.tailor = False
            elif args.action == "apply":
                generator.apply_fixes(rules, args.keyword)
    else:
        script = bash_scripts.get(args.command)
        if script:
            run_bash_script(script)
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)

if __name__ == "__main__":
    main()
