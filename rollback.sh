#!/bin/bash

# Albator Rollback Script
# Reads rollback metadata JSON files and reverses changes in LIFO order.
# Usage: rollback.sh [--dry-run] [--json] <metadata_file | state_dir>

set -euo pipefail

source "$(dirname "$0")"/utils.sh

SCRIPT_NAME="rollback.sh"
DRY_RUN=${DRY_RUN:-false}
JSON_OUTPUT=false
STATE_DIR="${ALBATOR_STATE_DIR:-/tmp/albator_state}"

usage() {
    echo "Usage: $0 [--dry-run] [--json] [--latest] [<metadata_file>]"
    echo ""
    echo "Options:"
    echo "  --dry-run    Show rollback operations without executing"
    echo "  --json       Emit JSON result"
    echo "  --latest     Find and use the most recent rollback metadata file"
    echo "  --list       List available rollback metadata files"
    echo "  --help       Show this help message"
    echo ""
    echo "If <metadata_file> is a directory, the most recent metadata file"
    echo "in that directory is used."
}

find_latest_metadata() {
    local search_dir="${1:-$STATE_DIR}"
    if [[ ! -d "$search_dir" ]]; then
        echo ""
        return 1
    fi
    # Find the newest rollback JSON (not plan files)
    local latest
    latest=$(find "$search_dir" -maxdepth 1 -name '*_rollback_*.json' -type f 2>/dev/null | sort -r | head -n1)
    echo "$latest"
}

list_metadata_files() {
    local search_dir="${1:-$STATE_DIR}"
    if [[ ! -d "$search_dir" ]]; then
        echo "No state directory found: $search_dir"
        return 1
    fi
    local count=0
    while IFS= read -r f; do
        if [[ -n "$f" ]]; then
            local script_name status
            if command -v jq >/dev/null 2>&1; then
                script_name=$(jq -r '.script // "unknown"' "$f" 2>/dev/null || echo "unknown")
                status=$(jq -r '.status // "unknown"' "$f" 2>/dev/null || echo "unknown")
                local num_changes
                num_changes=$(jq '.changes | length' "$f" 2>/dev/null || echo "0")
                echo "  $f  (script=$script_name, status=$status, changes=$num_changes)"
            else
                echo "  $f"
            fi
            count=$((count + 1))
        fi
    done < <(find "$search_dir" -maxdepth 1 -name '*_rollback_*.json' -type f 2>/dev/null | sort -r)
    if [[ $count -eq 0 ]]; then
        echo "No rollback metadata files found in $search_dir"
        return 1
    fi
    echo ""
    echo "Found $count rollback file(s)"
}

apply_rollback_from_file() {
    local meta_file="$1"
    local applied=0
    local failed=0
    local skipped=0

    if ! command -v jq >/dev/null 2>&1; then
        show_error "jq is required for rollback operations"
        return 1
    fi

    local script_name
    script_name=$(jq -r '.script // "unknown"' "$meta_file")
    local num_changes
    num_changes=$(jq '.changes | length' "$meta_file")

    if [[ "$num_changes" -eq 0 ]]; then
        show_warning "No changes recorded in $meta_file — nothing to roll back"
        return 0
    fi

    show_progress "Rolling back $num_changes change(s) from $script_name..."

    # Process changes in reverse order (LIFO)
    local i
    for ((i = num_changes - 1; i >= 0; i--)); do
        local component detail rollback_cmd
        component=$(jq -r ".changes[$i].component // \"\"" "$meta_file")
        detail=$(jq -r ".changes[$i].detail // \"\"" "$meta_file")
        rollback_cmd=$(jq -r ".changes[$i].rollback_command // \"\"" "$meta_file")

        # Try fallback: if component looks like domain/key, use defaults delete
        if [[ -z "$rollback_cmd" ]] && [[ "$component" == */* ]]; then
            local domain key
            domain="${component%%/*}"
            key="${component#*/}"
            rollback_cmd="defaults delete $domain $key"
        fi

        if [[ -z "$rollback_cmd" ]]; then
            show_warning "SKIP: No rollback command for: $detail ($component)"
            skipped=$((skipped + 1))
            continue
        fi

        if [[ "$DRY_RUN" == "true" ]]; then
            show_progress "DRY RUN: Would execute: $rollback_cmd"
            applied=$((applied + 1))
            continue
        fi

        show_progress "Executing: $rollback_cmd"
        if eval "$rollback_cmd" 2>>"${LOG_FILE:-/tmp/albator_rollback.log}"; then
            show_success "Rolled back: $detail"
            applied=$((applied + 1))
        else
            show_error "Failed to roll back: $detail (command: $rollback_cmd)"
            failed=$((failed + 1))
        fi
    done

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        cat <<EOF
{
  "script": "$script_name",
  "metadata_file": "$meta_file",
  "dry_run": $DRY_RUN,
  "total_changes": $num_changes,
  "applied": $applied,
  "failed": $failed,
  "skipped": $skipped,
  "status": "$(if [[ $failed -eq 0 ]]; then echo "ok"; else echo "failed"; fi)"
}
EOF
    else
        echo ""
        echo "===================================="
        echo "Rollback Summary"
        echo "  Script:  $script_name"
        echo "  Applied: $applied"
        echo "  Failed:  $failed"
        echo "  Skipped: $skipped"
        echo "===================================="
    fi

    if [[ $failed -gt 0 ]]; then
        return 1
    fi
    return 0
}

main() {
    local meta_file=""
    local use_latest=false
    local list_mode=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --latest)
                use_latest=true
                shift
                ;;
            --list)
                list_mode=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            -*)
                show_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                meta_file="$1"
                shift
                ;;
        esac
    done

    if [[ "$list_mode" == "true" ]]; then
        list_metadata_files "$STATE_DIR"
        exit $?
    fi

    if [[ "$use_latest" == "true" ]] || [[ -z "$meta_file" ]]; then
        meta_file=$(find_latest_metadata "$STATE_DIR")
        if [[ -z "$meta_file" ]]; then
            show_error "No rollback metadata files found in $STATE_DIR"
            exit 2
        fi
        show_progress "Using latest metadata: $meta_file"
    elif [[ -d "$meta_file" ]]; then
        # If a directory was passed, find the latest metadata in it
        local dir_meta
        dir_meta=$(find_latest_metadata "$meta_file")
        if [[ -z "$dir_meta" ]]; then
            show_error "No rollback metadata files found in $meta_file"
            exit 2
        fi
        meta_file="$dir_meta"
        show_progress "Using latest metadata from directory: $meta_file"
    fi

    if [[ ! -f "$meta_file" ]]; then
        show_error "Metadata file not found: $meta_file"
        exit 2
    fi

    apply_rollback_from_file "$meta_file"
}

main "$@"
