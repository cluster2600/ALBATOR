import os
import yaml
from typing import List, Optional
from arg_parser import create_args
from rule_handler import collect_rules, get_controls, output_baseline, odv_query
from utils import parse_authors, append_authors, available_tags

class BaselineGenerator:
    def __init__(self):
        self.args = create_args()
        self.root_dir = '/Users/maxime/macoshardening/MACOS_HARDENING/'  # Update to the correct path
        self.includes_dir = os.path.join(self.root_dir, 'includes')
        self.build_dir = os.path.join(self.root_dir, 'build', 'baselines')
        self.original_wd = os.getcwd()

    def setup_directories(self) -> None:
        """Set up working directory and create build directory if needed."""
        os.chdir(self.root_dir)
        if not os.path.isdir(self.build_dir):
            os.makedirs(self.build_dir, exist_ok=True)

    def load_yaml_file(self, filepath: str) -> dict:
        """Safely load a YAML file."""
        try:
            with open(filepath, 'r') as file:
                return yaml.load(file, Loader=yaml.SafeLoader)
        except (IOError, yaml.YAMLError) as e:
            raise RuntimeError(f"Error loading YAML file {filepath}: {str(e)}")

    def list_available_tags(self, rules: List) -> None:
        """Display available tags and exit."""
        available_tags(rules)
        raise SystemExit(0)

    def check_controls(self, rules: List) -> None:
        """Check for missing controls in rules."""
        baselines = self.load_yaml_file(os.path.join(self.includes_dir, '800-53_baselines.yaml'))
        included_controls = get_controls(rules)
        needed_controls = list(dict.fromkeys(baselines['low']))  # Remove duplicates while preserving order
        
        for control in needed_controls:
            if control not in included_controls:
                print(f'{control} missing from any rule, needs a rule, or included in supplemental')
        raise SystemExit(0)

    def get_matching_rules(self, all_rules: List) -> List:
        """Filter rules based on keyword."""
        return [rule for rule in all_rules if self.args.keyword in rule.rule_tags or self.args.keyword == "all_rules"]

    def generate_baseline(self, rules: List, mscp_data: dict, version_data: dict) -> None:
        """Generate and write the baseline file."""
        established_benchmarks = ['stig', 'cis_lvl1', 'cis_lvl2']
        benchmark = self.args.keyword if any(bm in self.args.keyword for bm in established_benchmarks) else "recommended"
        
        authors = (parse_authors(mscp_data['authors'][self.args.keyword]) 
                  if self.args.keyword in mscp_data['authors'] 
                  else "|===\n  |Name|Organization\n  |===\n")
        
        full_title = (f" {mscp_data['titles'][self.args.keyword]}" 
                     if self.args.keyword in mscp_data['titles'] and not self.args.tailor 
                     else f" {self.args.keyword}")

        if self.args.tailor:
            self._generate_tailored_baseline(rules, benchmark, authors, full_title, version_data)
        else:
            self._generate_standard_baseline(rules, benchmark, authors, full_title, version_data)

    def _generate_tailored_baseline(self, rules: List, benchmark: str, authors: str, title: str, version: dict) -> None:
        """Handle tailored baseline generation."""
        tailored_filename = self._get_sanitised_input(
            f'Enter a name for your tailored benchmark or press Enter for the default value ({self.args.keyword}): ',
            default_=self.args.keyword
        )
        custom_author_name = self._get_sanitised_input('Enter your name: ')
        custom_author_org = self._get_sanitised_input('Enter your organization: ')
        
        authors = append_authors(authors, custom_author_name, custom_author_org)
        baseline_string = (f"{self.args.keyword.upper()} (Tailored)" 
                         if tailored_filename == self.args.keyword 
                         else f"{tailored_filename.upper()} (Tailored from {self.args.keyword.upper()})")
        
        self._write_baseline(tailored_filename, odv_query(rules, benchmark), 
                           version, baseline_string, benchmark, authors, title)

    def _generate_standard_baseline(self, rules: List, benchmark: str, authors: str, title: str, version: dict) -> None:
        """Handle standard baseline generation."""
        self._write_baseline(self.args.keyword, rules, version, "", benchmark, authors, title)

    def _write_baseline(self, filename: str, rules: List, version: dict, baseline_string: str, 
                       benchmark: str, authors: str, title: str) -> None:
        """Write baseline to file."""
        output_path = os.path.join(self.build_dir, f"{filename}.yaml")
        with open(output_path, 'w') as output_file:
            output_file.write(output_baseline(rules, version, baseline_string, benchmark, authors, title))

    def _get_sanitised_input(self, prompt: str, default_: Optional[str] = None) -> str:
        """Get sanitised user input with optional default."""
        # Assuming sanitised_input is defined elsewhere, keeping original behavior
        return sanitised_input(prompt, str, default_=default_)

    def run(self) -> None:
        """Main execution logic."""
        try:
            self.setup_directories()
            all_rules = collect_rules()

            if self.args.list_tags:
                self.list_available_tags(all_rules)
            if self.args.controls:
                self.check_controls(all_rules)

            found_rules = self.get_matching_rules(all_rules)
            if not found_rules:
                print("No rules found for the keyword provided, please verify from the following list:")
                self.list_available_tags(all_rules)
                return

            mscp_data = self.load_yaml_file(os.path.join(self.includes_dir, 'mscp-data.yaml'))
            version_data = self.load_yaml_file(os.path.join(self.root_dir, "VERSION.yaml"))
            self.generate_baseline(found_rules, mscp_data, version_data)

        except Exception as e:
            print(f"Error: {str(e)}")
        finally:
            os.chdir(self.original_wd)

def main():
    generator = BaselineGenerator()
    generator.run()

if __name__ == "__main__":
    main()
