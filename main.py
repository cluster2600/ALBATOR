import os
import re
import shlex
import yaml
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog
from typing import List, Optional
from arg_parser import create_args
from rule_handler import collect_rules, get_controls, output_baseline, odv_query
from utils import parse_authors, append_authors, available_tags, sanitised_input

class BaselineGenerator:
    """Generates security baselines, applies fixes, and provides interfaces for macOS tuning."""

    def __init__(self, args=None):
        """Initialize with parsed arguments and dynamic directory paths."""
        self.args = args or create_args()
        self.root_dir = os.environ.get('ROOT_DIR') or self.args.root_dir or os.getcwd()
        self.includes_dir = os.path.join(self.root_dir, 'includes')
        self.build_dir = os.path.join(self.root_dir, 'build', 'baselines')
        self.original_wd = os.getcwd()

    @staticmethod
    def _resolve_benchmark(keyword: str) -> str:
        """Map keyword tags to benchmark parent values consistently across all interfaces."""
        established_benchmarks = {'stig', 'cis_lvl1', 'cis_lvl2', 'macos_26_3'}
        return keyword if keyword in established_benchmarks else "recommended"

    @staticmethod
    def _parse_major_version(version_string: str) -> Optional[int]:
        """Extract major version from a version string like 26.3 or 15."""
        if not version_string:
            return None
        match = re.search(r"(\d+)", str(version_string))
        if not match:
            return None
        return int(match.group(1))

    def _get_target_macos_major(self) -> Optional[int]:
        """Determine current/target macOS major version for rule compatibility filtering."""
        env_override = os.environ.get("ALBATOR_MACOS_VERSION")
        if env_override:
            return self._parse_major_version(env_override)
        try:
            result = subprocess.run(
                ["sw_vers", "-productVersion"], capture_output=True, text=True, check=False
            )
            if result.returncode == 0:
                return self._parse_major_version(result.stdout.strip())
        except Exception:
            return None
        return None

    def _is_rule_version_compatible(self, rule, target_major: Optional[int]) -> bool:
        """Check whether a rule applies to the detected macOS major version."""
        if target_major is None:
            return True
        raw = getattr(rule, "rule_macos", "missing")
        if raw in (None, "", "missing"):
            return True

        tokens = raw if isinstance(raw, list) else re.split(r"[,\s]+", str(raw))
        majors = {m for token in tokens for m in [self._parse_major_version(token)] if m is not None}
        if not majors:
            return True
        return target_major in majors

    def setup_directories(self) -> None:
        """Set up working directory and create build directory if needed."""
        try:
            os.chdir(self.root_dir)
            os.makedirs(self.build_dir, exist_ok=True)
        except FileNotFoundError:
            raise RuntimeError(f"Root directory not found: {self.root_dir}")
        except PermissionError:
            raise RuntimeError(f"Permission denied accessing directory: {self.root_dir}")

    def load_yaml_file(self, filepath: str) -> dict:
        """Safely load a YAML file with specific error handling."""
        try:
            with open(filepath, 'r') as file:
                return yaml.load(file, Loader=yaml.SafeLoader)
        except FileNotFoundError:
            raise RuntimeError(f"YAML file not found: {filepath}")
        except yaml.YAMLError as e:
            raise RuntimeError(f"Error parsing YAML file {filepath}: {str(e)}")

    def list_available_tags(self, rules: List) -> None:
        """Display available tags."""
        available_tags(rules)

    def check_controls(self, rules: List) -> None:
        """Check for missing NIST 800-53 controls in rules."""
        baselines = self.load_yaml_file(os.path.join(self.includes_dir, '800-53_baselines.yaml'))
        included_controls = get_controls(rules)
        needed_controls = list(dict.fromkeys(baselines['low']))
        
        missing = [control for control in needed_controls if control not in included_controls]
        if missing:
            print("Missing controls:")
            for control in missing:
                print(f"  - {control}")
        else:
            print("All required controls are covered.")

    def get_matching_rules(self, all_rules: List, keyword: str) -> List:
        """Filter rules based on the provided keyword."""
        matching = [rule for rule in all_rules if keyword in rule.rule_tags or keyword == "all_rules"]
        target_major = self._get_target_macos_major()
        compatible = [rule for rule in matching if self._is_rule_version_compatible(rule, target_major)]
        skipped_count = len(matching) - len(compatible)
        if skipped_count > 0 and target_major is not None:
            print(
                f"Info: skipped {skipped_count} rule(s) not compatible with detected macOS major {target_major}."
            )
        return compatible

    @staticmethod
    def _parse_fix_command(fix_cmd: str) -> List[str]:
        """Parse fix command safely for subprocess execution without a shell."""
        disallowed_tokens = (';', '|', '&', '>', '<', '`', '$', '\n', '\r')
        if any(token in fix_cmd for token in disallowed_tokens):
            raise ValueError("Fix command contains unsupported shell control characters.")

        try:
            cmd = shlex.split(fix_cmd)
        except ValueError as e:
            raise ValueError(f"Invalid fix command syntax: {e}") from e

        if not cmd:
            raise ValueError("Fix command is empty after parsing.")
        return cmd

    @staticmethod
    def _requires_root(raw_cmd: str, parsed_cmd: List[str]) -> bool:
        """Determine whether a command requires root privileges."""
        privileged_bins = ('/usr/bin/pwpolicy', '/usr/sbin/spctl', '/usr/bin/defaults')
        return (
            parsed_cmd[0] == 'sudo'
            or 'sudo' in raw_cmd.lower()
            or any(path in raw_cmd for path in privileged_bins)
        )

    def _run_fix_command(self, fix_cmd: str) -> subprocess.CompletedProcess:
        """Run a validated fix command without shell=True."""
        cmd = self._parse_fix_command(fix_cmd)
        requires_root = self._requires_root(fix_cmd, cmd)

        # Users should run Albator with sudo rather than embedding sudo in rule fixes.
        if cmd[0] == 'sudo':
            cmd = cmd[1:]
        if not cmd:
            raise ValueError("Fix command cannot be only 'sudo'.")

        if requires_root and os.geteuid() != 0:
            raise PermissionError("Fix requires root privileges. Re-run Albator with sudo.")

        return subprocess.run(cmd, check=True, capture_output=True, text=True)

    def apply_fixes(self, rules: List, keyword: str) -> None:
        """Apply fix commands for rules matching the keyword."""
        print(f"Applying fixes for rules with tag '{keyword}'...")
        for rule in rules:
            fix_cmd = rule.rule_fix.strip()
            if not fix_cmd or fix_cmd == "missing":
                print(f"No fix defined for rule '{rule.rule_id}'")
                continue
            
            print(f"\nRule: {rule.rule_id}")
            print(f"Description: {rule.rule_discussion}")
            print(f"Fix Command: {fix_cmd}")
            confirm = sanitised_input(f"Apply this fix? [Y/n]: ", str.lower, range_=('y', 'n'), default_="n")
            if confirm != 'y':
                print(f"Skipping fix for '{rule.rule_id}'")
                continue

            try:
                result = self._run_fix_command(fix_cmd)
                print(f"Successfully applied fix for '{rule.rule_id}': {result.stdout}")
            except ValueError as e:
                print(f"Rejected fix for '{rule.rule_id}': {str(e)}")
            except PermissionError as e:
                print(f"Error: Fix for '{rule.rule_id}' requires root privileges. {str(e)}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to apply fix for '{rule.rule_id}': {e.stderr}")
            except Exception as e:
                print(f"Unexpected error applying fix for '{rule.rule_id}': {str(e)}")

    def enhanced_error_handling(self, func, *args, **kwargs):
        """Wrapper to enhance error handling and logging for critical functions."""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"An error occurred in {func.__name__}: {str(e)}")
            # Additional logging or recovery actions can be added here

    def improved_user_guidance(self):
        """Provide more detailed prompts and guidance in interactive and GUI modes."""
        print("Welcome to Albator interactive mode.")
        print("Use 'help' to list commands and 'exit' to quit.")
        # Additional detailed guidance messages can be added here

    def generate_baseline(self, rules: List, mscp_data: dict, version_data: dict, keyword: str = None) -> None:
        """Generate and write the baseline file."""
        keyword = keyword or self.args.keyword
        benchmark = self._resolve_benchmark(keyword)
        
        authors = (parse_authors(mscp_data['authors'][keyword]) 
                  if keyword in mscp_data['authors'] 
                  else "|===\n  |Name|Organization\n  |===\n")
        
        full_title = (f"{mscp_data['titles'][keyword]}" 
                     if keyword in mscp_data['titles'] and not self.args.tailor 
                     else f"{keyword}")

        if self.args.tailor:
            self._generate_tailored_baseline(rules, benchmark, authors, full_title, version_data, keyword)
        else:
            self._generate_standard_baseline(rules, benchmark, authors, full_title, version_data, keyword)

    def _generate_tailored_baseline(self, rules: List, benchmark: str, authors: str, title: str, version: dict, keyword: str) -> None:
        """Handle tailored baseline generation with user input."""
        tailored_filename = self._get_sanitised_input(
            f'Enter a name for your tailored benchmark or press Enter for default ({keyword}): ',
            default_=keyword
        )
        custom_author_name = self._get_sanitised_input('Enter your name: ')
        custom_author_org = self._get_sanitised_input('Enter your organization: ')
        
        authors = append_authors(authors, custom_author_name, custom_author_org)
        baseline_string = (f"{tailored_filename.upper()} (Tailored from {keyword.upper()})")
        tailored_rules = odv_query(rules, benchmark)
        self._write_baseline(tailored_filename, tailored_rules, version, baseline_string, benchmark, authors, title)

    def _generate_standard_baseline(self, rules: List, benchmark: str, authors: str, title: str, version: dict, keyword: str) -> None:
        """Handle standard baseline generation."""
        self._write_baseline(keyword, rules, version, "", benchmark, authors, title)

    def _write_baseline(self, filename: str, rules: List, version: dict, baseline_string: str, 
                       benchmark: str, authors: str, title: str) -> None:
        """Write the baseline to a YAML file."""
        output_path = os.path.join(self.build_dir, f"{filename}.yaml")
        try:
            with open(output_path, 'w') as output_file:
                output_file.write(output_baseline(rules, version, baseline_string, benchmark, authors, title))
            print(f"Baseline written to {output_path}")
        except IOError as e:
            raise RuntimeError(f"Error writing baseline to {output_path}: {str(e)}")

    def _get_sanitised_input(self, prompt: str, default_: Optional[str] = None) -> str:
        """Get validated user input with an optional default."""
        return sanitised_input(prompt, str, default_=default_)

    def interactive_mode(self, all_rules: List, mscp_data: dict, version_data: dict) -> None:
        """Run an interactive command prompt."""
        print("Entering interactive mode. Type 'help' for commands, 'exit' to quit.")
        while True:
            command = input("mscp> ").strip().lower()
            if command in ['exit', 'quit']:
                print("Exiting interactive mode.")
                break
            elif command == 'help':
                print("Available commands:")
                print("  list                - List all available tags")
                print("  generate <tag>      - Generate a baseline for <tag>")
                print("  check               - Check NIST 800-53 control coverage")
                print("  tailor <tag>        - Tailor a baseline for <tag>")
                print("  apply <tag>         - Apply fixes for rules with <tag>")
                print("  exit/quit           - Exit interactive mode")
            elif command == 'list':
                self.list_available_tags(all_rules)
            elif command == 'check':
                self.check_controls(all_rules)
            elif command.startswith('generate '):
                tag = command.split(' ', 1)[1]
                rules = self.get_matching_rules(all_rules, tag)
                if rules:
                    benchmark = self._resolve_benchmark(tag)
                    self._generate_standard_baseline(rules, benchmark, parse_authors(mscp_data['authors'].get(tag, {})), 
                                                    f"{mscp_data['titles'].get(tag, tag)}", version_data, tag)
                else:
                    print(f"No rules found for tag '{tag}'. Available tags:")
                    self.list_available_tags(all_rules)
            elif command.startswith('tailor '):
                tag = command.split(' ', 1)[1]
                rules = self.get_matching_rules(all_rules, tag)
                if rules:
                    self.args.tailor = True
                    benchmark = self._resolve_benchmark(tag)
                    self._generate_tailored_baseline(rules, benchmark, parse_authors(mscp_data['authors'].get(tag, {})), 
                                                    f"{mscp_data['titles'].get(tag, tag)}", version_data, tag)
                    self.args.tailor = False
                else:
                    print(f"No rules found for tag '{tag}'. Available tags:")
                    self.list_available_tags(all_rules)
            elif command.startswith('apply '):
                tag = command.split(' ', 1)[1]
                rules = self.get_matching_rules(all_rules, tag)
                if rules:
                    self.apply_fixes(rules, tag)
                else:
                    print(f"No rules found for tag '{tag}'. Available tags:")
                    self.list_available_tags(all_rules)
            else:
                print(f"Unknown command: '{command}'. Type 'help' for available commands.")

    def gui_mode(self, all_rules: List, mscp_data: dict, version_data: dict) -> None:
        """Run a graphical user interface with radio buttons."""
        root = tk.Tk()
        root.title("macOS Security Compliance Tool")
        root.geometry("400x400")

        tk.Label(root, text="Select an action:", font=("Arial", 12)).pack(pady=10)
        selected_option = tk.StringVar()

        options = [
            ("List Tags", "list"),
            ("Generate Baseline", "generate"),
            ("Check Controls", "check"),
            ("Tailor Baseline", "tailor"),
            ("Apply Fixes", "apply")
        ]

        for text, value in options:
            tk.Radiobutton(root, text=text, variable=selected_option, value=value, anchor='w', padx=20).pack(fill='x')

        tk.Label(root, text="Note: Applying fixes may require sudo.", font=("Arial", 10, "italic")).pack(pady=10)

        def proceed():
            option = selected_option.get()
            if not option:
                messagebox.showerror("Error", "Please select an option.")
                return

            if option == "list":
                tags = "\n".join(sorted({tag for rule in all_rules for tag in rule.rule_tags} | {"all_rules"}))
                messagebox.showinfo("Available Tags", tags)

            elif option == "generate":
                tag = simpledialog.askstring("Generate Baseline", "Enter tag (e.g., 'stig'):")
                if tag:
                    rules = self.get_matching_rules(all_rules, tag)
                    if rules:
                        benchmark = self._resolve_benchmark(tag)
                        self._generate_standard_baseline(
                            rules, benchmark, parse_authors(mscp_data['authors'].get(tag, {})),
                            mscp_data['titles'].get(tag, tag), version_data, tag
                        )
                        filepath = os.path.join(self.build_dir, f"{tag}.yaml")
                        messagebox.showinfo("Success", f"Baseline written to {filepath}")
                    else:
                        messagebox.showerror("Error", f"No rules found for tag '{tag}'")

            elif option == "check":
                baselines = self.load_yaml_file(os.path.join(self.includes_dir, '800-53_baselines.yaml'))
                included = get_controls(all_rules)
                needed = list(dict.fromkeys(baselines['low']))
                missing = [ctrl for ctrl in needed if ctrl not in included]
                if missing:
                    messagebox.showwarning("Missing Controls", "\n".join(missing))
                else:
                    messagebox.showinfo("Controls", "All required controls covered.")

            elif option == "tailor":
                tag = simpledialog.askstring("Tailor Baseline", "Enter tag (e.g., 'stig'):")
                if tag:
                    rules = self.get_matching_rules(all_rules, tag)
                    if rules:
                        filename = simpledialog.askstring("Tailor Baseline", "Enter tailored benchmark name:", initialvalue=tag) or tag
                        name = simpledialog.askstring("Tailor Baseline", "Enter your name:")
                        org = simpledialog.askstring("Tailor Baseline", "Enter your organization:")
                        authors = append_authors(parse_authors(mscp_data['authors'].get(tag, {})), name, org)
                        tailored_rules = []
                        for rule in rules:
                            if messagebox.askyesno("Include Rule", f"Include '{rule.rule_id}'?\n{rule.rule_discussion}"):
                                tailored_rules.append(rule)
                        filepath = os.path.join(self.build_dir, f"{filename}.yaml")
                        benchmark = self._resolve_benchmark(tag)
                        with open(filepath, 'w') as f:
                            f.write(output_baseline(
                                tailored_rules, version_data, f"{filename.upper()} (from {tag.upper()})",
                                benchmark, authors, mscp_data['titles'].get(tag, tag)
                            ))
                        messagebox.showinfo("Success", f"Tailored baseline written to {filepath}")
                    else:
                        messagebox.showerror("Error", f"No rules found for tag '{tag}'")

            elif option == "apply":
                tag = simpledialog.askstring("Apply Fixes", "Enter tag (e.g., 'stig'):")
                if tag:
                    rules = self.get_matching_rules(all_rules, tag)
                    if rules:
                        for rule in rules:
                            fix = rule.rule_fix.strip()
                            if fix and fix != "missing":
                                if messagebox.askyesno("Apply Fix", f"Run fix for '{rule.rule_id}'?\n{fix}"):
                                    try:
                                        result = self._run_fix_command(fix)
                                        messagebox.showinfo("Success", f"Applied fix: {result.stdout}")
                                    except ValueError as e:
                                        messagebox.showerror("Rejected", f"Fix rejected: {str(e)}")
                                    except PermissionError as e:
                                        messagebox.showerror("Permission Error", str(e))
                                    except subprocess.CalledProcessError as e:
                                        messagebox.showerror("Error", f"Fix failed: {e.stderr}")
                    else:
                        messagebox.showerror("Error", f"No rules found for tag '{tag}'")

        tk.Button(root, text="Proceed", command=proceed, width=10).pack(pady=10)
        tk.Button(root, text="Quit", command=root.quit, width=10).pack(pady=10)
        root.mainloop()

    def run(self) -> None:
        """Execute the main logic based on arguments."""
        try:
            self.setup_directories()
            all_rules = collect_rules(self.root_dir)

            if self.args.list_tags:
                self.list_available_tags(all_rules)
                return
            if self.args.controls:
                self.check_controls(all_rules)
                return
            if self.args.interactive:
                mscp_data = self.load_yaml_file(os.path.join(self.includes_dir, 'mscp-data.yaml'))
                version_data = self.load_yaml_file(os.path.join(self.root_dir, "VERSION.yaml"))
                self.interactive_mode(all_rules, mscp_data, version_data)
                return
            if self.args.gui:
                mscp_data = self.load_yaml_file(os.path.join(self.includes_dir, 'mscp-data.yaml'))
                version_data = self.load_yaml_file(os.path.join(self.root_dir, "VERSION.yaml"))
                self.gui_mode(all_rules, mscp_data, version_data)
                return

            found_rules = self.get_matching_rules(all_rules, self.args.keyword)
            if not found_rules:
                print("No rules found for the keyword provided. Available tags:")
                self.list_available_tags(all_rules)
                return

            mscp_data = self.load_yaml_file(os.path.join(self.includes_dir, 'mscp-data.yaml'))
            version_data = self.load_yaml_file(os.path.join(self.root_dir, "VERSION.yaml"))
            self.generate_baseline(found_rules, mscp_data, version_data)

        except RuntimeError as e:
            print(f"Error: {str(e)}")
        finally:
            os.chdir(self.original_wd)

def main():
    """Entry point for the script."""
    generator = BaselineGenerator()
    generator.run()

if __name__ == "__main__":
    main()
