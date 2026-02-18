#!/usr/bin/env python3
"""Apply Albator rollback metadata files in reverse order."""

import argparse
import json
import os
import shlex
import subprocess
import sys
from typing import Any, Dict, List


def load_meta(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def derive_fallback_rollback(change: Dict[str, Any]) -> str:
    component = str(change.get("component", ""))
    if "/" in component:
        domain, key = component.split("/", 1)
        if domain and key:
            return f"defaults delete {shlex.quote(domain)} {shlex.quote(key)}"
    return ""


def apply_rollback(meta: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
    changes: List[Dict[str, Any]] = list(meta.get("changes", []))
    applied = []
    failed = []

    for change in reversed(changes):
        cmd = str(change.get("rollback_command") or "").strip()
        if not cmd:
            cmd = derive_fallback_rollback(change)
        if not cmd:
            failed.append({"change": change, "reason": "missing rollback command"})
            continue

        if dry_run:
            applied.append({"change": change, "command": cmd, "dry_run": True})
            continue

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
        entry = {
            "change": change,
            "command": cmd,
            "returncode": result.returncode,
            "stdout": (result.stdout or "").strip(),
            "stderr": (result.stderr or "").strip(),
        }
        if result.returncode == 0:
            applied.append(entry)
        else:
            failed.append(entry)

    return {
        "script": meta.get("script", "unknown"),
        "status": "ok" if not failed else "failed",
        "applied_count": len(applied),
        "failed_count": len(failed),
        "applied": applied,
        "failed": failed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply Albator rollback metadata")
    parser.add_argument("metadata", help="Path to rollback metadata JSON file")
    parser.add_argument("--dry-run", action="store_true", help="Show rollback operations without executing")
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    args = parser.parse_args()

    if not os.path.exists(args.metadata):
        print(f"Metadata file not found: {args.metadata}", file=sys.stderr)
        return 2

    meta = load_meta(args.metadata)
    result = apply_rollback(meta, dry_run=args.dry_run)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Albator Rollback Apply")
        print("=====================")
        print(f"Script: {result['script']}")
        print(f"Applied: {result['applied_count']}")
        print(f"Failed: {result['failed_count']}")

    return 0 if result["failed_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
