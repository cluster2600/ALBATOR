from typing import List, Dict, Any, Optional, Type, Iterable
from string import Template

class MacSecurityRule:
    """Represents a macOS security rule with associated attributes."""
    
    def __init__(self, title: str, rule_id: str, severity: str, discussion: str, 
                 check: str, fix: str, cci: List[str], cce: List[str], 
                 nist_controls: List[str], disa_stig: List[str], srg: List[str], 
                 odv: Any, tags: List[str], result_value: Any, 
                 mobileconfig: Any, mobileconfig_info: Any) -> None:
        """Initialize a security rule."""
        self.rule_title = title
        self.rule_id = rule_id
        self.rule_severity = severity
        self.rule_discussion = discussion
        self.rule_check = check
        self.rule_fix = fix
        self.rule_cci = cci
        self.rule_cce = cce
        self.rule_80053r4 = nist_controls
        self.rule_disa_stig = disa_stig
        self.rule_srg = srg
        self.rule_odv = odv
        self.rule_tags = tags
        self.rule_result_value = result_value
        self.rule_mobileconfig = mobileconfig
        self.rule_mobileconfig_info = mobileconfig_info

    def create_asciidoc(self, adoc_rule_template: Template) -> str:
        """Generate AsciiDoc representation of the rule."""
        return adoc_rule_template.substitute(
            rule_title=self.rule_title,
            rule_id=self.rule_id,
            rule_severity=self.rule_severity,
            rule_discussion=self.rule_discussion,
            rule_check=self.rule_check,
            rule_fix=self.rule_fix,
            rule_cci=self._format_list(self.rule_cci),
            rule_80053r4=self._format_list(self.rule_80053r4),
            rule_disa_stig=self._format_list(self.rule_disa_stig),
            rule_srg=self._format_list(self.rule_srg),
            rule_result=str(self.rule_result_value)
        )

    @staticmethod
    def _format_list(items: List[Any]) -> str:
        """Format a list into a comma-separated string."""
        return ", ".join(str(item) for item in items) if items else "None"

def sanitised_input(prompt: str, type_: Optional[Type] = None, 
                   range_: Optional[Iterable] = None, 
                   default_: Optional[Any] = None) -> Any:
    """Get validated user input with type and range checking."""
    while True:
        try:
            user_input = input(prompt).strip()
            if not user_input and default_ is not None:
                return default_
            if not user_input:
                raise ValueError("Input required when no default is provided")

            if type_ is not None:
                user_input = type_(user_input)

            if range_ is not None and user_input not in range_:
                expected = " or ".join((", ".join(str(x) for x in list(range_)[:-1]), 
                                      str(list(range_)[-1]))) if not isinstance(range_, range) else f"{range_.start}-{range_.stop-1}"
                raise ValueError(f"Input must be one of: {expected}")

            return user_input
        except ValueError as e:
            print(f"Invalid input: {str(e)}. Please try again.")

def parse_authors(authors_from_yaml: Dict[str, Any]) -> str:
    """Format author information into a table string."""
    author_block = ["*macOS Security Compliance Project*\n"]
    
    if "preamble" in authors_from_yaml:
        author_block.append(f"  {authors_from_yaml['preamble']}\n")
    
    author_block.append("  |===\n")
    for name in authors_from_yaml.get('names', []):
        author_block.append(f"  |{name}\n")
    author_block.append("  |===\n")
    
    return "".join(author_block)

def append_authors(authors: str, name: str, org: str) -> str:
    """Append a custom author to the existing author block."""
    return (
        "*Security configuration tailored by:*\n"
        "  |===\n"
        f"  |{name}|{org}\n"
        "  |===\n"
        f"  {authors}"
    )

def available_tags(all_rules: List[MacSecurityRule]) -> None:
    """Print all unique tags from the rules."""
    unique_tags = sorted({tag for rule in all_rules for tag in rule.rule_tags} | {"all_rules"})
    print("\n".join(unique_tags))
