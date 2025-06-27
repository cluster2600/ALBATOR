import os
import glob
import yaml
from typing import List, Dict, Any, Optional
from utils import sanitised_input, MacSecurityRule

class RuleHandler:
    """Manages security rule collection, processing, and baseline generation."""

    BASE_PATH = "../"  # Relative to MACOS_HARDENING/
    RULES_DIR = os.path.join(BASE_PATH, "rules")
    CUSTOM_RULES_DIR = os.path.join(BASE_PATH, "custom/rules")

    @staticmethod
    def _load_yaml_file(filepath: str) -> Dict[str, Any]:
        """Load a YAML file with error handling."""
        try:
            with open(filepath, 'r') as file:
                return yaml.load(file, Loader=yaml.SafeLoader) or {}
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            return {}
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file {filepath}: {str(e)}")
            return {}

    @classmethod
    def get_rule_yaml(cls, rule_file: str, custom: bool = False) -> Dict[str, Any]:
        """Merge rule YAML from original and custom sources."""
        resulting_yaml = {}
        file_name = os.path.basename(rule_file)

        custom_pattern = os.path.join(cls.CUSTOM_RULES_DIR, "**", file_name)
        rule_pattern = os.path.join(cls.RULES_DIR, "**", file_name)

        if custom:
            print(f"Custom settings found for rule: {file_name}")
            override_paths = glob.glob(custom_pattern, recursive=True)
            rule_yaml = cls._load_yaml_file(override_paths[0]) if override_paths else {}
        else:
            rule_yaml = cls._load_yaml_file(rule_file)

        og_paths = glob.glob(rule_pattern, recursive=True) or glob.glob(custom_pattern, recursive=True)
        og_rule_yaml = cls._load_yaml_file(og_paths[0]) if og_paths else {}

        for field in og_rule_yaml:
            value = rule_yaml.get(field, og_rule_yaml[field])
            resulting_yaml[field] = value
            if field in rule_yaml and og_rule_yaml[field] != rule_yaml[field]:
                resulting_yaml.setdefault('customized', []).append(f"customized {field}")

        return resulting_yaml

    @classmethod
    def collect_rules(cls) -> List[MacSecurityRule]:
        """Collect and process all security rules from rules directories."""
        all_rules = []
        required_keys = ['mobileconfig', 'macOS', 'severity', 'title', 'check', 'fix', 
                        'odv', 'tags', 'id', 'references', 'result', 'discussion']
        reference_types = ['disa_stig', 'cci', 'cce', '800-53r4', 'srg']

        rule_files = sorted(glob.glob(os.path.join(cls.RULES_DIR, "**/*.yaml"), recursive=True) + 
                          glob.glob(os.path.join(cls.CUSTOM_RULES_DIR, "**/*.yaml"), recursive=True))

        for rule_file in rule_files:
            rule_yaml = cls.get_rule_yaml(rule_file)
            
            for key in required_keys:
                rule_yaml.setdefault(key, "missing")
                if key == "references":
                    rule_yaml[key] = {ref: rule_yaml[key].get(ref, ["None"]) for ref in reference_types}

            all_rules.append(MacSecurityRule(
                rule_yaml['title'].replace('|', '\\|'),
                rule_yaml['id'].replace('|', '\\|'),
                rule_yaml['severity'].replace('|', '\\|'),
                rule_yaml['discussion'].replace('|', '\\|'),
                rule_yaml['check'].replace('|', '\\|'),
                rule_yaml['fix'].replace('|', '\\|'),
                rule_yaml['references']['cci'],
                rule_yaml['references']['cce'],
                rule_yaml['references']['800-53r4'],
                rule_yaml['references']['disa_stig'],
                rule_yaml['references']['srg'],
                rule_yaml['odv'],
                rule_yaml['tags'],
                rule_yaml['result'],
                rule_yaml['mobileconfig'],
                rule_yaml.get('mobileconfig_info', "missing")
            ))

        return all_rules

    @staticmethod
    def get_controls(all_rules: List[MacSecurityRule]) -> List[str]:
        """Extract unique NIST 800-53 controls from rules."""
        controls = set()
        for rule in all_rules:
            controls.update(rule.rule_80053r4)
        return sorted(controls)

    @staticmethod
    def output_baseline(rules: List[MacSecurityRule], version: Dict[str, str], 
                       baseline_tailored_string: str, benchmark: str, 
                       authors: str, full_title: str) -> str:
        """Generate a formatted baseline string."""
        rule_categories = {
            "inherent": [], "permanent": [], "n_a": [], "supplemental": [], "other": []
        }
        sections = set()

        for rule in rules:
            rule_id = rule.rule_id
            if "inherent" in rule.rule_tags:
                rule_categories["inherent"].append(rule_id)
            elif "permanent" in rule.rule_tags:
                rule_categories["permanent"].append(rule_id)
            elif "n_a" in rule.rule_tags:
                rule_categories["n_a"].append(rule_id)
            elif "supplemental" in rule.rule_tags:
                rule_categories["supplemental"].append(rule_id)
            else:
                rule_categories["other"].append(rule_id)
                prefix = "_".join(rule_id.split("_")[:2 if rule_id.startswith("system_settings") else 1])
                sections.add(prefix)

        output = []
        platform_os = f"{version['platform']} {version['os']}"
        title_suffix = f" {baseline_tailored_string}" if baseline_tailored_string else ""
        
        output.append(f'title: "{platform_os}: Security Configuration -{full_title}{title_suffix}"')
        output.append('description: |')
        output.append(f'  This guide describes the actions to take when securing a {platform_os} system against the{full_title}{title_suffix} security baseline.')
        
        if benchmark == "recommended":
            output.append("\n  This is a catalog of settings to assist in security benchmark creation, not a mandatory checklist.")
        
        output.extend([f'authors: |\n  {authors}', f'parent_values: "{benchmark}"', 'profile:'])
        
        for section in sorted(sections):
            output.extend([
                f'  - section: "{section}"',
                '    rules:',
                *[f'      - {rule}' for rule in sorted(rule_categories["other"]) if rule.startswith(section)]
            ])

        for category, title in [("inherent", "Inherent"), ("permanent", "Permanent"), 
                              ("n_a", "not_applicable"), ("supplemental", "Supplemental")]:
            if rule_categories[category]:
                output.extend([
                    f'  - section: "{title}"',
                    '    rules:',
                    *[f'      - {rule}' for rule in sorted(rule_categories[category])]
                ])

        return "\n".join(output)

    @classmethod
    def odv_query(cls, rules: List[MacSecurityRule], benchmark: str) -> List[MacSecurityRule]:
        """Interactively query user for rule inclusion and ODV values."""
        print("Rule inclusion is a risk-based decision (RBD). Each rule maps to an 800-53 control.")
        if benchmark != "recommended":
            print("WARNING: Modifying an established benchmark may affect compliance.")

        included_rules = []
        queried_ids = set()
        include_all = False

        for rule in rules:
            if rule.rule_id in queried_ids:
                continue

            if "inherent" in rule.rule_tags:
                include = "y"
            elif include_all:
                include = "y"
                cls._handle_odv(rule, benchmark, included_rules)
            else:
                include = sanitised_input(
                    f"Include rule \"{rule.rule_id}\" in your benchmark? [Y/n/all/?]: ",
                    str.lower, range_=('y', 'n', 'all', '?'), default_="y"
                )
                if include == "?":
                    print(f'Rule Details: \n{rule.rule_discussion}')
                    include = sanitised_input(
                        f"Include rule \"{rule.rule_id}\" in your benchmark? [Y/n/all]: ",
                        str.lower, range_=('y', 'n', 'all'), default_="y"
                    )
                if include == "all":
                    include_all = True
                    include = "y"
                cls._handle_odv(rule, benchmark, included_rules if include == "y" else None)

            if include == "y":
                included_rules.append(rule)
            queried_ids.add(rule.rule_id)

        return included_rules

    @classmethod
    def _handle_odv(cls, rule: MacSecurityRule, benchmark: str, included_rules: Optional[List] = None) -> None:
        """Process ODV for a rule if included."""
        if rule.rule_odv == "missing" or not included_rules:
            return

        odv_key = "recommended" if benchmark == "recommended" else benchmark
        recommended = rule.rule_odv.get(odv_key)
        if recommended is None:
            return

        print(f'\n{rule.rule_odv.get("hint", "No hint available")}')
        odv_type = type(recommended)
        odv = sanitised_input(
            f'Enter ODV for "{rule.rule_id}" (default: {recommended}): ',
            odv_type, default_=recommended
        )
        
        if odv != recommended:
            cls._write_odv_custom_rule(rule, odv)
        else:
            cls._remove_odv_custom_rule(rule)

    @classmethod
    def _write_odv_custom_rule(cls, rule: MacSecurityRule, odv: Any) -> None:
        """Write custom ODV to a file."""
        os.makedirs(cls.CUSTOM_RULES_DIR, exist_ok=True)
        filepath = os.path.join(cls.CUSTOM_RULES_DIR, f"{rule.rule_id}.yaml")
        
        rule_yaml = cls._load_yaml_file(filepath)
        rule_yaml['odv'] = {"custom": odv}
        
        try:
            with open(filepath, 'w') as f:
                yaml.dump(rule_yaml, f, explicit_start=True)
            print(f"Created custom rule {rule.rule_id} with value {odv}")
        except IOError as e:
            print(f"Error writing custom rule {filepath}: {str(e)}")

    @classmethod
    def _remove_odv_custom_rule(cls, rule: MacSecurityRule) -> None:
        """Remove custom ODV file if it exists and is empty."""
        filepath = os.path.join(cls.CUSTOM_RULES_DIR, f"{rule.rule_id}.yaml")
        if not os.path.exists(filepath):
            return

        rule_yaml = cls._load_yaml_file(filepath)
        rule_yaml.pop('odv', None)
        
        if rule_yaml:
            with open(filepath, 'w') as f:
                yaml.dump(rule_yaml, f, explicit_start=True)
        else:
            os.remove(filepath)

# Legacy function compatibility
def collect_rules() -> List[MacSecurityRule]:
    return RuleHandler.collect_rules()

def get_controls(all_rules: List[MacSecurityRule]) -> List[str]:
    return RuleHandler.get_controls(all_rules)

def output_baseline(rules: List[MacSecurityRule], version: Dict[str, str], 
                   baseline_tailored_string: str, benchmark: str, 
                   authors: str, full_title: str) -> str:
    return RuleHandler.output_baseline(rules, version, baseline_tailored_string, benchmark, authors, full_title)

def odv_query(rules: List[MacSecurityRule], benchmark: str) -> List[MacSecurityRule]:
    return RuleHandler.odv_query(rules, benchmark)
