"""Albator Dependencies Module — Rule dependency graph and topological sort.

Defines ordering constraints between rules so that fix operations apply
prerequisites before dependents. For example, firewall must be enabled
before stealth mode can be configured, and auditd must be running before
audit flags can be set.

The dependency graph is loaded from config/rule_dependencies.yaml and
used by the fix module to sort rules in safe application order.
"""

import os
import yaml
from collections import defaultdict, deque


def load_dependency_graph(dep_file=None):
    """Load rule dependency edges from a YAML file.

    Args:
        dep_file: Path to rule_dependencies.yaml. If None, uses the
                  default at config/rule_dependencies.yaml relative to
                  this module's directory.

    Returns:
        dict mapping rule_id -> list of rule_ids it depends on.
        Example: {"os_firewall_stealth_mode": ["os_firewall_enable"]}
    """
    if dep_file is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dep_file = os.path.join(base_dir, "config", "rule_dependencies.yaml")

    if not os.path.exists(dep_file):
        return {}

    with open(dep_file) as f:
        data = yaml.safe_load(f)

    if not data or "dependencies" not in data:
        return {}

    graph = {}
    for entry in data["dependencies"]:
        rule_id = entry.get("rule_id")
        depends_on = entry.get("depends_on", [])
        if rule_id and isinstance(depends_on, list):
            graph[rule_id] = depends_on
    return graph


def topological_sort(rules, dep_graph):
    """Sort rules respecting dependency ordering (Kahn's algorithm).

    Rules with dependencies are placed after their prerequisites.
    Rules not in the dependency graph retain their original relative order.
    If a cycle is detected, falls back to the original order with a warning.

    Args:
        rules: List of rule dicts (each must have an "id" key).
        dep_graph: dict mapping rule_id -> list of prerequisite rule_ids.

    Returns:
        (sorted_rules, warnings) where sorted_rules is the reordered list
        and warnings is a list of warning strings (empty if no issues).
    """
    if not dep_graph or not rules:
        return list(rules), []

    warnings = []
    rule_ids = {r["id"] for r in rules}
    rule_by_id = {r["id"]: r for r in rules}

    # Build adjacency list and in-degree count for rules in the current set
    # Edge: prerequisite -> dependent (prerequisite must come first)
    adj = defaultdict(list)
    in_degree = defaultdict(int)

    # Initialize all rules with 0 in-degree
    for rid in rule_ids:
        in_degree[rid] = in_degree.get(rid, 0)

    for rule_id, deps in dep_graph.items():
        if rule_id not in rule_ids:
            continue
        for dep in deps:
            if dep not in rule_ids:
                warnings.append(
                    f"dependency {dep} for {rule_id} not in current rule set (skipped)"
                )
                continue
            adj[dep].append(rule_id)
            in_degree[rule_id] = in_degree.get(rule_id, 0) + 1

    # Kahn's algorithm — use original order as tiebreaker
    original_order = {r["id"]: i for i, r in enumerate(rules)}
    queue = deque(
        sorted(
            [rid for rid in rule_ids if in_degree.get(rid, 0) == 0],
            key=lambda x: original_order.get(x, 0),
        )
    )

    sorted_ids = []
    while queue:
        node = queue.popleft()
        sorted_ids.append(node)
        for neighbor in sorted(adj[node], key=lambda x: original_order.get(x, 0)):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    if len(sorted_ids) != len(rule_ids):
        # Cycle detected — fall back to original order
        cycle_nodes = rule_ids - set(sorted_ids)
        warnings.append(
            f"dependency cycle detected involving {sorted(cycle_nodes)}; "
            f"using original order for those rules"
        )
        # Add remaining rules in original order
        for r in rules:
            if r["id"] not in set(sorted_ids):
                sorted_ids.append(r["id"])

    sorted_rules = [rule_by_id[rid] for rid in sorted_ids if rid in rule_by_id]
    return sorted_rules, warnings


def validate_dependency_graph(dep_graph, available_rule_ids):
    """Validate that all referenced rules exist and there are no cycles.

    Args:
        dep_graph: dict mapping rule_id -> list of prerequisite rule_ids.
        available_rule_ids: set of all known rule IDs.

    Returns:
        list of error strings (empty if valid).
    """
    errors = []

    for rule_id, deps in dep_graph.items():
        if rule_id not in available_rule_ids:
            errors.append(f"dependency source '{rule_id}' is not a known rule")
        for dep in deps:
            if dep not in available_rule_ids:
                errors.append(
                    f"dependency target '{dep}' (required by '{rule_id}') is not a known rule"
                )
            if dep == rule_id:
                errors.append(f"rule '{rule_id}' depends on itself")

    # Check for cycles using DFS
    visited = set()
    in_stack = set()

    def dfs(node):
        if node in in_stack:
            return True  # cycle
        if node in visited:
            return False
        visited.add(node)
        in_stack.add(node)
        for dep_target in dep_graph.get(node, []):
            # Follow reverse: who depends on this node?
            pass
        # Actually need forward edges: node depends on deps, so check deps
        for dep in dep_graph.get(node, []):
            if dfs(dep):
                return True
        in_stack.discard(node)
        return False

    for rule_id in dep_graph:
        if rule_id not in visited:
            if dfs(rule_id):
                errors.append(f"dependency cycle detected involving '{rule_id}'")

    return errors


def get_dependency_order_summary(rules, dep_graph):
    """Return a human-readable summary of dependency ordering.

    Args:
        rules: List of rule dicts.
        dep_graph: Dependency graph dict.

    Returns:
        List of strings describing the ordering.
    """
    sorted_rules, warnings = topological_sort(rules, dep_graph)
    lines = []
    for i, rule in enumerate(sorted_rules, 1):
        deps = dep_graph.get(rule["id"], [])
        dep_str = f" (after: {', '.join(deps)})" if deps else ""
        lines.append(f"{i:3d}. {rule['id']}{dep_str}")
    for w in warnings:
        lines.append(f"WARNING: {w}")
    return lines
