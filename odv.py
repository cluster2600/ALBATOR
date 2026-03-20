"""Albator ODV Module — Organization-Defined Values for CIS Benchmark compliance.

Loads, validates, and provides ODV (Organization-Defined Values) that allow
organizations to customize threshold parameters in security rules. Boolean
rules (enable/disable) have odv="none"; tunable rules have structured ODV
metadata with variable name, default value, and type.
"""

import os
import yaml


# Canonical list of ODV variables with their expected types
ODV_SCHEMA = {
    "password_min_length": int,
    "password_max_age_days": int,
    "password_history_count": int,
    "password_lockout_attempts": int,
    "screensaver_timeout_seconds": int,
    "audit_retention_period": str,
    "audit_flags": str,
    "install_log_retention_days": int,
    "ntp_server": str,
    "login_banner_text": str,
    "home_folder_permissions": str,
}

DEFAULT_ODV_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config", "odv_defaults.yaml"
)


def load_odv_defaults(path=None):
    """Load ODV defaults from a YAML file.

    Args:
        path: Path to the ODV YAML file. Defaults to config/odv_defaults.yaml.

    Returns:
        dict mapping ODV variable names to their values.

    Raises:
        FileNotFoundError: If the ODV file does not exist.
        ValueError: If the file is not valid YAML or missing the 'odv' key.
    """
    path = path or DEFAULT_ODV_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(f"ODV defaults file not found: {path}")
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "odv" not in data:
        raise ValueError(f"ODV file must contain a top-level 'odv' mapping: {path}")
    return data["odv"]


def validate_odv_values(odv_values):
    """Validate ODV values against the schema.

    Args:
        odv_values: dict of ODV variable names to values.

    Returns:
        list of error strings (empty if valid).
    """
    errors = []
    for var_name, expected_type in ODV_SCHEMA.items():
        if var_name not in odv_values:
            errors.append(f"missing ODV variable: {var_name}")
            continue
        val = odv_values[var_name]
        if not isinstance(val, expected_type):
            errors.append(
                f"ODV '{var_name}' must be {expected_type.__name__}, got {type(val).__name__}"
            )
        if expected_type is int and isinstance(val, int) and val <= 0:
            errors.append(f"ODV '{var_name}' must be a positive integer, got {val}")
    for var_name in odv_values:
        if var_name not in ODV_SCHEMA:
            errors.append(f"unknown ODV variable: {var_name}")
    return errors


def extract_rule_odv(rule):
    """Extract ODV metadata from a rule.

    Args:
        rule: dict loaded from a YAML rule file.

    Returns:
        None if rule has no ODV (boolean toggle), or a dict with:
        - variable: ODV variable name
        - default: default value
        - description: human-readable description
        - cis_recommendation: CIS recommended value
        - type: "integer" or "string"
    """
    odv = rule.get("odv")
    if odv is None or odv == "none" or odv == "missing":
        return None
    if isinstance(odv, dict) and "variable" in odv:
        return odv
    return None


def get_odv_value(rule, odv_values=None):
    """Get the effective ODV value for a rule.

    Looks up the rule's ODV variable in the provided values dict,
    falling back to the rule's built-in default.

    Args:
        rule: dict loaded from a YAML rule file.
        odv_values: dict of organization-customized ODV values (optional).

    Returns:
        The ODV value, or None if the rule has no ODV.
    """
    odv_meta = extract_rule_odv(rule)
    if odv_meta is None:
        return None
    var_name = odv_meta["variable"]
    if odv_values and var_name in odv_values:
        return odv_values[var_name]
    return odv_meta.get("default")


def list_odv_rules(rules):
    """List all rules that have tunable ODV parameters.

    Args:
        rules: list of rule dicts.

    Returns:
        list of dicts with keys: rule_id, variable, default, description.
    """
    result = []
    for rule in rules:
        odv_meta = extract_rule_odv(rule)
        if odv_meta:
            result.append({
                "rule_id": rule.get("id", "unknown"),
                "variable": odv_meta["variable"],
                "default": odv_meta["default"],
                "description": odv_meta.get("description", ""),
                "type": odv_meta.get("type", "string"),
            })
    return result


def validate_rules_odv_consistency(rules):
    """Validate that all rules have proper ODV fields and no conflicts.

    Args:
        rules: list of rule dicts.

    Returns:
        list of error strings (empty if all consistent).
    """
    errors = []
    seen_variables = {}

    for rule in rules:
        rule_id = rule.get("id", "unknown")
        odv = rule.get("odv")

        if odv is None:
            errors.append(f"rule '{rule_id}' is missing the 'odv' field entirely")
            continue

        if odv == "missing":
            errors.append(f"rule '{rule_id}' has odv='missing' (should be 'none' or structured)")
            continue

        if odv == "none":
            continue

        if not isinstance(odv, dict):
            errors.append(f"rule '{rule_id}' has invalid odv type: {type(odv).__name__}")
            continue

        required_keys = {"variable", "default", "description", "type"}
        missing_keys = required_keys - set(odv.keys())
        if missing_keys:
            errors.append(f"rule '{rule_id}' ODV missing keys: {', '.join(sorted(missing_keys))}")
            continue

        var_name = odv["variable"]
        if var_name not in ODV_SCHEMA:
            errors.append(f"rule '{rule_id}' references unknown ODV variable: {var_name}")

        odv_type = odv.get("type")
        if odv_type not in ("integer", "string"):
            errors.append(f"rule '{rule_id}' has invalid ODV type: {odv_type}")

        if var_name in seen_variables and seen_variables[var_name] != rule_id:
            errors.append(
                f"ODV variable '{var_name}' used by both "
                f"'{seen_variables[var_name]}' and '{rule_id}'"
            )
        seen_variables[var_name] = rule_id

    return errors
