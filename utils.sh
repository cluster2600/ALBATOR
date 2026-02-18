#!/bin/bash

# Albator Utility Functions
# Common functions for logging, status messages, and other utilities

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
_json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local logfile="${LOG_FILE:-/tmp/albator.log}"
    local format="${ALBATOR_LOG_FORMAT:-text}"

    if [[ "$format" == "json" ]]; then
        local payload
        payload="{\"timestamp\":\"$timestamp\",\"level\":\"$(_json_escape "$level")\",\"script\":\"$(_json_escape "${SCRIPT_NAME:-unknown}")\",\"message\":\"$(_json_escape "$message")\"}"
        echo "$payload" | tee -a "$logfile"
    else
        echo "[$timestamp] [$level] $message" | tee -a "$logfile"
    fi
}

init_script_state() {
    ALBATOR_CHANGES=0
    ALBATOR_NOOP_HINTS=0
    local state_dir="${ALBATOR_STATE_DIR:-/tmp/albator_state}"
    mkdir -p "$state_dir"
    ROLLBACK_META_FILE="$state_dir/${SCRIPT_NAME:-script}_rollback_$(date +%Y%m%d_%H%M%S).json"
    DRYRUN_PLAN_FILE="$state_dir/${SCRIPT_NAME:-script}_plan_$(date +%Y%m%d_%H%M%S).json"
    cat > "$ROLLBACK_META_FILE" <<EOF
{"script":"${SCRIPT_NAME:-unknown}","started_at":"$(date -u +"%Y-%m-%dT%H:%M:%SZ")","changes":[]}
EOF
    cat > "$DRYRUN_PLAN_FILE" <<EOF
{"script":"${SCRIPT_NAME:-unknown}","started_at":"$(date -u +"%Y-%m-%dT%H:%M:%SZ")","planned_actions":[]}
EOF
}

record_rollback_change() {
    local component="$1"
    local detail="$2"
    local rollback_command="${3:-}"
    ALBATOR_CHANGES=$((ALBATOR_CHANGES + 1))
    if command -v jq >/dev/null 2>&1; then
        local tmp_file="${ROLLBACK_META_FILE}.tmp"
        jq --arg component "$component" --arg detail "$detail" --arg rollback "$rollback_command" --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
           '.changes += [{"component":$component,"detail":$detail,"rollback_command":$rollback,"timestamp":$ts}]' \
           "$ROLLBACK_META_FILE" > "$tmp_file" && mv "$tmp_file" "$ROLLBACK_META_FILE"
    fi
}

record_plan_action() {
    local component="$1"
    local action="$2"
    local command_text="${3:-}"
    if command -v jq >/dev/null 2>&1; then
        local tmp_file="${DRYRUN_PLAN_FILE}.tmp"
        jq --arg component "$component" --arg action "$action" --arg command "$command_text" --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
           '.planned_actions += [{"component":$component,"action":$action,"command":$command,"timestamp":$ts}]' \
           "$DRYRUN_PLAN_FILE" > "$tmp_file" && mv "$tmp_file" "$DRYRUN_PLAN_FILE"
    fi
}

record_noop() {
    local detail="$1"
    ALBATOR_NOOP_HINTS=$((ALBATOR_NOOP_HINTS + 1))
    log "INFO" "No-op: $detail"
}

finalize_script_state() {
    local script_status="$1"
    if command -v jq >/dev/null 2>&1; then
        local tmp_file="${ROLLBACK_META_FILE}.tmp"
        jq --arg status "$script_status" --arg finished "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
           '.status = $status | .finished_at = $finished' \
           "$ROLLBACK_META_FILE" > "$tmp_file" && mv "$tmp_file" "$ROLLBACK_META_FILE"

        local plan_tmp_file="${DRYRUN_PLAN_FILE}.tmp"
        jq --arg status "$script_status" --arg finished "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
           '.status = $status | .finished_at = $finished' \
           "$DRYRUN_PLAN_FILE" > "$plan_tmp_file" && mv "$plan_tmp_file" "$DRYRUN_PLAN_FILE"
    fi
}

exit_with_status() {
    local errors="$1"
    if [[ "$errors" -ne 0 ]]; then
        finalize_script_state "failed"
        exit 1
    fi
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        finalize_script_state "dry_run"
        exit 0
    fi
    if [[ "${ALBATOR_CHANGES:-0}" -eq 0 ]]; then
        finalize_script_state "already_compliant"
        exit 10
    fi
    finalize_script_state "applied_changes"
    exit 0
}

# Progress indicator
show_progress() {
    local message=$1
    echo -e "${BLUE}[INFO]${NC} $message"
    log "INFO" "$message"
}

# Success indicator
show_success() {
    local message=$1
    echo -e "${GREEN}[SUCCESS]${NC} $message"
    log "SUCCESS" "$message"
}

# Error indicator
show_error() {
    local message=$1
    echo -e "${RED}[ERROR]${NC} $message" >&2
    log "ERROR" "$message"
}

# Warning indicator
show_warning() {
    local message=$1
    echo -e "${YELLOW}[WARNING]${NC} $message"
    log "WARNING" "$message"
}

# Function to check for sudo access without password prompt
check_sudo_access() {
    if sudo -n true 2>/dev/null; then
        return 0 # Sudo access without password
    else
        return 1 # Sudo access requires password or is not available
    fi
}

get_min_macos_version() {
    local config_file="${1:-config/albator.yaml}"
    local default_version="${2:-26.3}"
    if [[ -f "$config_file" ]]; then
        local from_cfg
        from_cfg=$(sed -n 's/^[[:space:]]*min_macos_version:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$config_file" | head -n1)
        if [[ -n "$from_cfg" ]]; then
            echo "$from_cfg"
            return 0
        fi
    fi
    echo "$default_version"
}
