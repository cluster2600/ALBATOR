#!/bin/bash

# Albator Firewall Configuration Script
# Enhanced with error handling, logging, and verification

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Source common utilities
source "$(dirname "$0")"/utils.sh

# Configuration
SCRIPT_NAME="firewall.sh"
LOG_FILE="/tmp/albator_firewall.log"
BACKUP_DIR="/tmp/albator_backup/firewall"
DRY_RUN=${DRY_RUN:-false}
ALBATOR_TEST_ALLOW_DRYRUN_NO_SUDO=${ALBATOR_TEST_ALLOW_DRYRUN_NO_SUDO:-false}
FIREWALL_CMD="${FIREWALL_CMD:-/usr/libexec/ApplicationFirewall/socketfilterfw}"

# Function to backup current firewall settings
backup_firewall_settings() {
    show_progress "Backing up current firewall settings..."
    
    mkdir -p "$BACKUP_DIR"
    
    local backup_file="$BACKUP_DIR/firewall_settings_$(date +%Y%m%d_%H%M%S).backup"
    
    {
        echo "# Firewall backup created on $(date)"
        echo "GLOBAL_STATE=$(sudo $FIREWALL_CMD --getglobalstate 2>/dev/null || echo 'unknown')"
        echo "BLOCK_ALL=$(sudo $FIREWALL_CMD --getblockall 2>/dev/null || echo 'unknown')"
        echo "STEALTH_MODE=$(sudo $FIREWALL_CMD --getstealthmode 2>/dev/null || echo 'unknown')"
        echo "LOGGING_MODE=$(sudo $FIREWALL_CMD --getloggingmode 2>/dev/null || echo 'unknown')"
        echo "ALLOW_SIGNED=$(sudo $FIREWALL_CMD --getallowsigned 2>/dev/null || echo 'unknown')"
        echo "ALLOW_SIGNED_APP=$(sudo $FIREWALL_CMD --getallowsignedapp 2>/dev/null || echo 'unknown')"
    } > "$backup_file"
    
    log "INFO" "Firewall settings backed up to $backup_file"
}

# Function to apply firewall setting with verification
apply_firewall_setting() {
    local setting_flag=$1
    local setting_value=$2
    local description=$3
    local verification_flag=$4
    local expected_output=$5
    
    show_progress "Configuring: $description"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "DRY RUN: Would run: sudo $FIREWALL_CMD $setting_flag $setting_value"
        record_plan_action "firewall" "$description" "sudo $FIREWALL_CMD $setting_flag $setting_value"
        return 0
    fi
    local pre_value
    pre_value=$(sudo "$FIREWALL_CMD" "$verification_flag" 2>/dev/null || echo "UNKNOWN")
    if [[ "$pre_value" == *"$expected_output"* ]]; then
        show_success "$description already compliant"
        record_noop "$description already compliant"
        return 0
    fi
    
    # Apply the setting
    if sudo "$FIREWALL_CMD" "$setting_flag" "$setting_value" 2>>"$LOG_FILE"; then
        # Verify the setting was applied
        local current_value
        current_value=$(sudo "$FIREWALL_CMD" "$verification_flag" 2>/dev/null || echo "FAILED")
        
        if [[ "$current_value" == *"$expected_output"* ]]; then
            show_success "$description"
            record_rollback_change "$setting_flag" "$description"
            return 0
        else
            show_error "Failed to verify $description (expected: $expected_output, got: $current_value)"
            return 1
        fi
    else
        show_error "Failed to apply $description"
        return 1
    fi
}

# Function to check current firewall status
check_firewall_status() {
    show_progress "Checking current firewall status..."
    
    local global_state
    global_state=$(sudo "$FIREWALL_CMD" --getglobalstate 2>/dev/null || echo "unknown")
    
    if [[ "$global_state" == *"enabled"* ]]; then
        show_success "Firewall is currently enabled"
        record_noop "Firewall already enabled"
        return 0
    elif [[ "$global_state" == *"disabled"* ]]; then
        show_warning "Firewall is currently disabled"
        return 1
    else
        show_error "Unable to determine firewall status: $global_state"
        return 2
    fi
}

# Main firewall configuration function
configure_firewall() {
    local errors=0
    
    show_progress "Starting firewall configuration..."
    
    # Check if firewall command exists
    if [[ "$FIREWALL_CMD" == /* ]]; then
        if [[ ! -x "$FIREWALL_CMD" ]]; then
            show_error "Firewall command not found: $FIREWALL_CMD"
            return 1
        fi
    elif ! command -v "$FIREWALL_CMD" >/dev/null 2>&1; then
        show_error "Firewall command not found in PATH: $FIREWALL_CMD"
        return 1
    fi
    
    # Backup current settings
    backup_firewall_settings
    
    # Check current status
    check_firewall_status || true  # Don't fail if disabled
    
    # Enable the firewall
    apply_firewall_setting "--setglobalstate" "on" "Application Layer Firewall" "--getglobalstate" "enabled" || ((errors++))
    
    # Configure firewall settings
    apply_firewall_setting "--setallowsigned" "off" "Allow signed applications" "--getallowsigned" "disabled" || ((errors++))
    apply_firewall_setting "--setallowsignedapp" "off" "Allow signed applications (app-specific)" "--getallowsignedapp" "disabled" || ((errors++))
    apply_firewall_setting "--setblockall" "on" "Block all incoming connections" "--getblockall" "enabled" || ((errors++))
    apply_firewall_setting "--setstealthmode" "on" "Stealth mode" "--getstealthmode" "enabled" || ((errors++))
    apply_firewall_setting "--setloggingmode" "on" "Firewall logging" "--getloggingmode" "enabled" || ((errors++))
    
    return $errors
}

# Function to verify all firewall settings
verify_firewall_settings() {
    local errors=0
    
    show_progress "Verifying firewall configuration..."
    
    # Verification tests
    local tests=(
        "--getglobalstate:enabled:Firewall enabled"
        "--getblockall:enabled:Block all incoming enabled"
        "--getstealthmode:enabled:Stealth mode enabled"
        "--getloggingmode:enabled:Logging enabled"
        "--getallowsigned:disabled:Allow signed disabled"
        "--getallowsignedapp:disabled:Allow signed apps disabled"
    )
    
    for test in "${tests[@]}"; do
        IFS=':' read -r flag expected description <<< "$test"
        
        local actual
        actual=$(sudo "$FIREWALL_CMD" "$flag" 2>/dev/null || echo "FAILED")
        
        if [[ "$actual" == *"$expected"* ]]; then
            show_success "✓ $description"
        else
            show_error "✗ $description (expected: $expected, got: $actual)"
            ((errors++))
        fi
    done
    
    return $errors
}

# Function to display firewall status summary
display_firewall_summary() {
    show_progress "Firewall Configuration Summary:"
    echo "================================"
    
    local settings=(
        "--getglobalstate:Global State"
        "--getblockall:Block All Incoming"
        "--getstealthmode:Stealth Mode"
        "--getloggingmode:Logging Mode"
        "--getallowsigned:Allow Signed"
        "--getallowsignedapp:Allow Signed Apps"
    )
    
    for setting in "${settings[@]}"; do
        IFS=':' read -r flag description <<< "$setting"
        local value
        value=$(sudo "$FIREWALL_CMD" "$flag" 2>/dev/null || echo "ERROR")
        printf "%-20s: %s\n" "$description" "$value"
    done
    
    echo "================================"
}

# Function to test firewall functionality
test_firewall() {
    show_progress "Testing firewall functionality..."
    
    # Test if firewall is blocking connections (basic test)
    if command -v nc >/dev/null 2>&1; then
        show_progress "Testing with netcat (if available)..."
        # This is a basic test - in a real scenario you'd want more comprehensive testing
        show_warning "Firewall functionality testing requires manual verification"
    else
        show_warning "netcat not available for firewall testing"
    fi
    
    # Check firewall log
    local log_path="/var/log/appfirewall.log"
    if [[ -f "$log_path" ]]; then
        show_success "Firewall log file exists: $log_path"
        local recent_entries
        recent_entries=$(tail -5 "$log_path" 2>/dev/null | wc -l)
        show_progress "Recent log entries: $recent_entries"
    else
        show_warning "Firewall log file not found: $log_path"
    fi
}

# Main execution
main() {
    echo "Albator Firewall Configuration Script"
    echo "====================================="
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                show_warning "Running in dry-run mode"
                shift
                ;;
            --test)
                TEST_MODE=true
                shift
                ;;
            --help)
                echo "Usage: $0 [--dry-run] [--test] [--help]"
                echo "  --dry-run   Show what would be done without making changes"
                echo "  --test      Include firewall functionality tests"
                echo "  --help      Show this help message"
                exit 0
                ;;
            *)
                show_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    log "INFO" "Starting firewall configuration script"
    init_script_state
    
    # Check against configured baseline version
    local macos_version
    macos_version=$(sw_vers -productVersion)
    local min_macos
    min_macos=$(get_min_macos_version)
    if [[ "$macos_version" != "$min_macos"* ]]; then
        show_warning "Configured baseline is macOS >= $min_macos, detected: $macos_version"
    fi
    
    # Check for sudo privileges
    if ! sudo -n true 2>/dev/null; then
        if [[ "$DRY_RUN" == "true" && "$ALBATOR_TEST_ALLOW_DRYRUN_NO_SUDO" == "true" ]]; then
            show_warning "Proceeding in dry-run test mode without sudo"
        else
            show_error "This script requires sudo privileges"
            exit 1
        fi
    fi
    
    # Run configuration
    local config_errors=0
    configure_firewall || config_errors=$?
    
    # Run verification
    local verify_errors=0
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "Skipping verification in dry-run mode"
    else
        verify_firewall_settings || verify_errors=$?
    fi
    
    # Display summary
    display_firewall_summary
    
    # Run tests if requested
    if [[ "${TEST_MODE:-false}" == "true" ]]; then
        test_firewall
    fi
    
    # Summary
    local total_errors=$((config_errors + verify_errors))
    
    echo ""
    echo "====================================="
    if [[ $total_errors -eq 0 ]]; then
        show_success "Firewall configuration completed successfully!"
        log "INFO" "Firewall configuration completed successfully"
        exit_with_status 0
    else
        show_error "Firewall configuration completed with $total_errors errors"
        show_error "Check log file: $LOG_FILE"
        log "ERROR" "Firewall configuration completed with $total_errors errors"
        exit_with_status "$total_errors"
    fi
}

# Run main function with all arguments
main "$@"
