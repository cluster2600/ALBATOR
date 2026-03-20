"""Albator Exemptions Module — Manage accepted-risk rule exceptions.

Organizations running CIS benchmarks often have controls they cannot or
choose not to implement.  This module loads exemption files that document
which rules are exempt, why, and who approved the exception.

Exempted rules are excluded from scan/fix/report failure counts and shown
separately so auditors can distinguish intentional exceptions from gaps.
"""

import os
from datetime import datetime, timezone

import yaml


def load_exemptions(path):
    """Load an exemptions YAML file and return a validated list of exemptions.

    Expected format::

        exemptions:
          - rule_id: os_bluetooth_disable
            reason: "Required for wireless peripherals in conference rooms"
            approved_by: "Jane Smith, CISO"
            expires: "2026-12-31"       # optional
          - rule_id: os_siri_disable
            reason: "Accessibility requirement"
            approved_by: "ADA compliance team"

    Returns:
        list[dict] — each dict has keys: rule_id, reason, approved_by,
        expires (str or None), expired (bool).

    Raises:
        FileNotFoundError: if path does not exist.
        ValueError: if the file is malformed.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Exemptions file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "exemptions" not in data:
        raise ValueError(
            f"Exemptions file must contain a top-level 'exemptions' key: {path}"
        )

    raw = data["exemptions"]
    if not isinstance(raw, list):
        raise ValueError("'exemptions' must be a list of exemption entries")

    exemptions = []
    seen_ids = set()
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"Exemption entry {i} must be a mapping")

        rule_id = entry.get("rule_id")
        reason = entry.get("reason")
        approved_by = entry.get("approved_by")

        if not rule_id or not isinstance(rule_id, str):
            raise ValueError(f"Exemption entry {i}: 'rule_id' is required and must be a string")
        if not reason or not isinstance(reason, str):
            raise ValueError(f"Exemption entry {i}: 'reason' is required and must be a string")
        if not approved_by or not isinstance(approved_by, str):
            raise ValueError(f"Exemption entry {i}: 'approved_by' is required and must be a string")
        if rule_id in seen_ids:
            raise ValueError(f"Duplicate exemption for rule_id '{rule_id}'")
        seen_ids.add(rule_id)

        expires = entry.get("expires")
        expired = False
        if expires is not None:
            expires = str(expires)
            try:
                exp_date = datetime.strptime(expires, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                if datetime.now(timezone.utc) > exp_date:
                    expired = True
            except ValueError:
                raise ValueError(
                    f"Exemption entry {i}: 'expires' must be YYYY-MM-DD format, got '{expires}'"
                )

        exemptions.append({
            "rule_id": rule_id,
            "reason": reason,
            "approved_by": approved_by,
            "expires": expires,
            "expired": expired,
        })

    return exemptions


def get_exempt_ids(exemptions, include_expired=False):
    """Return the set of rule IDs that are currently exempt.

    By default, expired exemptions are NOT included (the rule reverts to
    normal enforcement).  Pass include_expired=True to include them.
    """
    ids = set()
    for ex in exemptions:
        if ex["expired"] and not include_expired:
            continue
        ids.add(ex["rule_id"])
    return ids


def filter_rules_with_exemptions(rules, exempt_ids):
    """Split rules into (active_rules, exempted_rules) based on exempt IDs.

    Returns:
        tuple(list, list) — (rules to evaluate, rules that are exempt)
    """
    active = []
    exempted = []
    for rule in rules:
        if rule["id"] in exempt_ids:
            exempted.append(rule)
        else:
            active.append(rule)
    return active, exempted


def format_exemption_summary(exemptions):
    """Return a human-readable summary of loaded exemptions."""
    if not exemptions:
        return "No exemptions loaded."
    lines = [f"Exemptions: {len(exemptions)} rule(s) exempt"]
    active = [e for e in exemptions if not e["expired"]]
    expired = [e for e in exemptions if e["expired"]]
    for ex in active:
        exp_str = f" (expires {ex['expires']})" if ex["expires"] else ""
        lines.append(f"  [EXEMPT] {ex['rule_id']}: {ex['reason']}{exp_str}")
        lines.append(f"           Approved by: {ex['approved_by']}")
    for ex in expired:
        lines.append(f"  [EXPIRED] {ex['rule_id']}: {ex['reason']} (expired {ex['expires']})")
        lines.append(f"            Approved by: {ex['approved_by']}")
    return "\n".join(lines)
